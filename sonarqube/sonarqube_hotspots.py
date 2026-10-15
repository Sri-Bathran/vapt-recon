#!/usr/bin/env python3
"""
SonarQube Security Hotspots Fetcher v2
Fetches ALL fields including category, rule name, review priority, what/where/fix details.
Always fetches per-hotspot detail automatically (no flag needed).

Usage:
    python sonarqube_hotspots.py --url http://localhost:9000 --token YOUR_TOKEN --project YOUR_PROJECT_KEY
    python sonarqube_hotspots.py --url http://localhost:9000 --token YOUR_TOKEN --project YOUR_PROJECT_KEY --output-dir C:\Reports\Pentest
"""

import argparse, json, os, sys, requests
from datetime import datetime
from urllib.parse import urljoin

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable, PageBreak, KeepTogether
from reportlab.lib.enums import TA_LEFT, TA_CENTER

# ══════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════

SEVERITY_HEX = {"HIGH": "E67E22", "MEDIUM": "E8A838", "LOW": "27AE60", "CRITICAL": "C0392B", "INFO": "2980B9"}
STATUS_HEX   = {"TO_REVIEW": "E74C3C", "REVIEWED": "27AE60", "ACKNOWLEDGED": "F39C12", "FIXED": "2ECC71", "SAFE": "3498DB"}
HEADER_BG    = "1A2B4A"
SUBHDR_BG    = "2C3E6B"
STRIPE_BG    = "EBF0FA"
PAGE_SIZE    = landscape(A4)

# Human-readable category names (SonarQube internal key → display name)
CATEGORY_NAMES = {
    "buffer-overflow": "Buffer Overflow",
    "sql-injection": "SQL Injection",
    "rce": "Remote Code Execution",
    "object-injection": "Object Injection",
    "command-injection": "Command Injection",
    "path-traversal-injection": "Path Traversal",
    "ldap-injection": "LDAP Injection",
    "xpath-injection": "XPath Injection",
    "expression-lang-injection": "Expression Language Injection",
    "log-injection": "Log Injection",
    "xxe": "XML External Entity (XXE)",
    "open-redirect": "Open Redirect",
    "ssrf": "Server-Side Request Forgery",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "xss": "Cross-Site Scripting (XSS)",
    "dos": "Denial of Service (DoS)",
    "weak-cryptography": "Weak Cryptography",
    "auth": "Authentication",
    "insecure-conf": "Insecure Configuration",
    "file-manipulation": "File Manipulation",
    "others": "Others",
    "http-response-splitting": "HTTP Response Splitting",
    "header-injection": "Header Injection",
    "encrypt-data": "Encryption of Sensitive Data",
    "traceability": "Traceability",
    "permission": "Permission",
}

# ══════════════════════════════════════════════════════════
# SONARQUBE CLIENT
# ══════════════════════════════════════════════════════════

class SonarQubeClient:
    def __init__(self, base_url, token):
        self.base_url = base_url.rstrip("/")
        s = requests.Session()
        s.auth = (token, "")
        s.headers.update({"Accept": "application/json"})
        self.s = s

    def _get(self, path, params=None):
        url = self.base_url + "/" + path.lstrip("/")
        r = self.s.get(url, params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def get_project_info(self, key):
        try:
            return self._get("/api/components/show", {"component": key}).get("component", {})
        except Exception:
            return {"key": key, "name": key}

    def get_hotspots(self, project_key, status=None):
        hotspots, page = [], 1
        while True:
            params = {"projectKey": project_key, "p": page, "ps": 500}
            if status:
                params["status"] = status
            try:
                data = self._get("/api/hotspots/search", params)
            except requests.HTTPError as e:
                print(f"[ERROR] API call failed: {e}")
                sys.exit(1)
            batch = data.get("hotspots", [])
            hotspots.extend(batch)
            total = data.get("paging", {}).get("total", 0)
            print(f"  Page {page}: {len(batch)} hotspots  (total: {total})")
            if page * 500 >= total or not batch:
                break
            page += 1
        return hotspots

    def get_hotspot_detail(self, key):
        try:
            return self._get("/api/hotspots/show", {"hotspot": key})
        except Exception as e:
            print(f"  [WARN] Could not fetch detail for {key}: {e}")
            return {}

# ══════════════════════════════════════════════════════════
# DATA ENRICHMENT  — always fetches per-hotspot detail
# ══════════════════════════════════════════════════════════

def enrich(client, raw_list):
    result = []
    total = len(raw_list)
    for i, hs in enumerate(raw_list, 1):
        key = hs.get("key", "")
        print(f"  [{i}/{total}] Detail: {key}")
        detail = client.get_hotspot_detail(key)

        # ── component / file path ──────────────────────────────
        comp = detail.get("component", hs.get("component", {}))
        if isinstance(comp, dict):
            file_path = comp.get("longName") or comp.get("key", "")
        else:
            file_path = str(comp)
        # Strip duplicate project prefix e.g. "myproject:myproject/src/..."
        if ":" in file_path:
            file_path = file_path.split(":", 1)[1]

        # ── line number ───────────────────────────────────────
        tr = detail.get("textRange", hs.get("textRange", {}))
        line = tr.get("startLine") or hs.get("line", "")

        # ── rule fields (detail API has full rule object) ─────
        rule = detail.get("rule", hs.get("rule", {}))
        if isinstance(rule, str):
            rule_key, rule_name, category, vuln_prob, risk_desc, fix_desc = rule, "", "", "", "", ""
        else:
            rule_key   = rule.get("key", "")
            rule_name  = rule.get("name", "")
            category   = rule.get("securityCategory", "") or hs.get("securityCategory", "")
            vuln_prob  = rule.get("vulnerabilityProbability", "") or hs.get("vulnerabilityProbability", "")
            risk_desc  = _strip_html(rule.get("riskDescription", ""))
            fix_desc   = _strip_html(rule.get("fixRecommendations", ""))

        severity = (vuln_prob or "").upper()
        cat_display = CATEGORY_NAMES.get(category, category.replace("-", " ").title() if category else "—")

        # ── status / resolution ───────────────────────────────
        status     = detail.get("status", hs.get("status", ""))
        resolution = detail.get("resolution", hs.get("resolution", ""))

        # ── author / assignee ─────────────────────────────────
        author   = detail.get("author", hs.get("author", ""))
        assignee = ""
        ass_obj  = detail.get("assignee", {})
        if isinstance(ass_obj, dict):
            assignee = ass_obj.get("name") or ass_obj.get("login", "")
        elif isinstance(ass_obj, str):
            assignee = ass_obj

        # ── dates ─────────────────────────────────────────────
        created = (detail.get("creationDate") or hs.get("creationDate", ""))[:10]
        updated = (detail.get("updateDate")   or hs.get("updateDate",   ""))[:10]

        # ── message ───────────────────────────────────────────
        message = detail.get("message", hs.get("message", ""))

        # ── comment ───────────────────────────────────────────
        comments = detail.get("comment", []) or []
        comment_text = comments[0].get("markdown", "") if comments else ""

        result.append({
            "key":          key,
            "message":      message,
            "file":         file_path,
            "line":         str(line) if line else "—",
            "status":       status,
            "resolution":   resolution,
            "severity":     severity,
            "category":     category,
            "category_display": cat_display,
            "rule_key":     rule_key,
            "rule_name":    rule_name,
            "risk_desc":    risk_desc[:400] if risk_desc else "",
            "fix_desc":     fix_desc[:400] if fix_desc else "",
            "author":       author,
            "assignee":     assignee,
            "created":      created,
            "updated":      updated,
            "comment":      comment_text[:300],
        })
    return result


def _strip_html(text):
    """Remove basic HTML tags for plain text output."""
    if not text:
        return ""
    import re
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def build_summary(hotspots):
    s = {"total": len(hotspots), "by_status": {}, "by_severity": {}, "by_category": {}}
    for h in hotspots:
        for k, field in [("by_status","status"),("by_severity","severity"),("by_category","category_display")]:
            v = h[field] or "Unknown"
            s[k][v] = s[k].get(v, 0) + 1
    return s

# ══════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════

def _fill(hex_c):  return PatternFill("solid", start_color=hex_c, end_color=hex_c)
def _border():
    t = Side(style="thin", color="CCCCCC")
    return Border(left=t, right=t, top=t, bottom=t)
def _font(bold=False, color="000000", size=10):
    return Font(name="Arial", bold=bold, color=color, size=size)

# ══════════════════════════════════════════════════════════
# EXCEL
# ══════════════════════════════════════════════════════════

def export_excel(hotspots, summary, project_info, path):
    wb = Workbook()
    wb.remove(wb.active)
    _xl_summary(wb, summary, project_info)
    _xl_hotspots(wb, hotspots)
    _xl_by_category(wb, hotspots)
    wb.save(path)
    print(f"[✓] Excel → {path}")


def _xl_header_row(ws, row, values, widths=None):
    for col, val in enumerate(values, 1):
        c = ws.cell(row=row, column=col, value=val)
        c.font      = _font(bold=True, color="FFFFFF")
        c.fill      = _fill(HEADER_BG)
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border    = _border()
        if widths:
            ws.column_dimensions[get_column_letter(col)].width = widths[col-1]
    ws.row_dimensions[row].height = 26


def _xl_summary(wb, summary, project_info):
    ws = wb.create_sheet("Summary")
    ws.sheet_view.showGridLines = False

    ws.merge_cells("A1:G1")
    ws["A1"] = "SonarQube Security Hotspots — VAPT Report"
    ws["A1"].font = _font(bold=True, size=15, color="FFFFFF")
    ws["A1"].fill = _fill(HEADER_BG)
    ws["A1"].alignment = Alignment(horizontal="center", vertical="center")
    ws.row_dimensions[1].height = 34

    ws.merge_cells("A2:G2")
    ws["A2"] = f"Project: {project_info.get('name', project_info.get('key',''))}   |   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    ws["A2"].font = _font(size=9, color="FFFFFF")
    ws["A2"].fill = _fill(SUBHDR_BG)
    ws["A2"].alignment = Alignment(horizontal="center")
    ws.row_dimensions[2].height = 20

    row = 4
    ws[f"A{row}"] = "Total Hotspots"
    ws[f"B{row}"] = summary["total"]
    ws[f"A{row}"].font = _font(bold=True, size=12)
    ws[f"B{row}"].font = _font(bold=True, size=14, color=HEADER_BG)
    row += 2

    for section, data, color_map in [
        ("BY STATUS",   summary["by_status"],   STATUS_HEX),
        ("BY SEVERITY", summary["by_severity"],  SEVERITY_HEX),
        ("BY CATEGORY", summary["by_category"],  {}),
    ]:
        ws.merge_cells(f"A{row}:C{row}")
        ws[f"A{row}"] = section
        ws[f"A{row}"].font = _font(bold=True, color="FFFFFF")
        ws[f"A{row}"].fill = _fill(SUBHDR_BG)
        row += 1
        _xl_header_row(ws, row, ["Name", "Count", "% of Total"])
        row += 1
        for name, count in sorted(data.items(), key=lambda x: -x[1]):
            pct = f"{round(count/summary['total']*100,1)}%" if summary["total"] else "0%"
            hex_c = color_map.get(name)
            c1 = ws.cell(row=row, column=1, value=name)
            c2 = ws.cell(row=row, column=2, value=count)
            c3 = ws.cell(row=row, column=3, value=pct)
            if hex_c:
                c1.fill = _fill(hex_c); c1.font = _font(bold=True, color="FFFFFF")
            c2.alignment = Alignment(horizontal="center")
            c3.alignment = Alignment(horizontal="center")
            for c in [c1,c2,c3]: c.border = _border()
            row += 1
        row += 1

    for col, w in zip("ABCD", [28, 10, 14, 14]):
        ws.column_dimensions[col].width = w


def _xl_hotspots(wb, hotspots):
    ws = wb.create_sheet("All Hotspots")
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = "A2"

    cols    = ["#","Severity","Status","Category","Rule Name","Message","File","Line","Author","Assignee","Created","Resolution","What's the Risk?","How to Fix?"]
    widths  = [4,  12,        14,      26,         28,         46,       44,    6,     16,      16,        12,       14,          42,                 42]

    _xl_header_row(ws, 1, cols, widths)
    ws.auto_filter.ref = f"A1:{get_column_letter(len(cols))}1"

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4,"":5}
    sorted_hs = sorted(hotspots, key=lambda x: (sev_order.get(x["severity"],5), x["status"]))

    for ri, hs in enumerate(sorted_hs, 2):
        stripe = STRIPE_BG if ri % 2 == 0 else "FFFFFF"
        vals = [
            ri-1,
            hs["severity"],
            hs["status"],
            hs["category_display"],
            hs["rule_name"] or hs["rule_key"],
            hs["message"],
            hs["file"],
            hs["line"],
            hs["author"],
            hs["assignee"],
            hs["created"],
            hs["resolution"] or "—",
            hs["risk_desc"] or "—",
            hs["fix_desc"]  or "—",
        ]
        for ci, val in enumerate(vals, 1):
            cell = ws.cell(row=ri, column=ci, value=val)
            cell.border    = _border()
            cell.alignment = Alignment(vertical="top", wrap_text=True)
            if ci == 2 and hs["severity"] in SEVERITY_HEX:
                cell.fill = _fill(SEVERITY_HEX[hs["severity"]])
                cell.font = _font(bold=True, color="FFFFFF")
            elif ci == 3 and hs["status"] in STATUS_HEX:
                cell.fill = _fill(STATUS_HEX[hs["status"]])
                cell.font = _font(bold=True, color="FFFFFF")
            else:
                cell.fill = _fill(stripe)
                cell.font = _font()
        ws.row_dimensions[ri].height = 48


def _xl_by_category(wb, hotspots):
    ws = wb.create_sheet("By Category")
    ws.sheet_view.showGridLines = False

    cats = {}
    for h in hotspots:
        cats.setdefault(h["category_display"], []).append(h)

    row = 1
    col_names  = ["Severity","Status","Message","File","Line","Rule Name","Author","Created","Risk Summary"]
    col_widths = [12,        14,      46,       42,    6,     28,        16,      12,       44]

    for cat, items in sorted(cats.items()):
        ws.merge_cells(f"A{row}:{get_column_letter(len(col_names))}{row}")
        ws[f"A{row}"] = f"  {cat.upper()}  ({len(items)} findings)"
        ws[f"A{row}"].font = _font(bold=True, color="FFFFFF", size=11)
        ws[f"A{row}"].fill = _fill(SUBHDR_BG)
        ws[f"A{row}"].alignment = Alignment(horizontal="left", indent=1)
        ws.row_dimensions[row].height = 22
        row += 1

        _xl_header_row(ws, row, col_names, col_widths)
        row += 1

        for idx, hs in enumerate(items):
            stripe = STRIPE_BG if idx % 2 == 0 else "FFFFFF"
            vals = [hs["severity"], hs["status"], hs["message"], hs["file"],
                    hs["line"], hs["rule_name"] or hs["rule_key"],
                    hs["author"], hs["created"], hs["risk_desc"] or "—"]
            for ci, val in enumerate(vals, 1):
                cell = ws.cell(row=row, column=ci, value=val)
                cell.border = _border()
                cell.alignment = Alignment(vertical="top", wrap_text=True)
                if ci == 1 and hs["severity"] in SEVERITY_HEX:
                    cell.fill = _fill(SEVERITY_HEX[hs["severity"]]); cell.font = _font(bold=True, color="FFFFFF")
                elif ci == 2 and hs["status"] in STATUS_HEX:
                    cell.fill = _fill(STATUS_HEX[hs["status"]]); cell.font = _font(bold=True, color="FFFFFF")
                else:
                    cell.fill = _fill(stripe); cell.font = _font()
            ws.row_dimensions[row].height = 44
            row += 1
        row += 1

# ══════════════════════════════════════════════════════════
# PDF
# ══════════════════════════════════════════════════════════

def export_pdf(hotspots, summary, project_info, path):
    doc = SimpleDocTemplate(path, pagesize=PAGE_SIZE,
        leftMargin=1.2*cm, rightMargin=1.2*cm,
        topMargin=1.2*cm, bottomMargin=1.5*cm)

    styles = getSampleStyleSheet()
    ST = lambda name, **kw: ParagraphStyle(name, parent=styles["Normal"], **kw)

    title_s  = ST("T", fontSize=17, textColor=colors.white,
                  backColor=colors.HexColor(f"#{HEADER_BG}"), alignment=TA_CENTER, spaceAfter=3)
    sub_s    = ST("S", fontSize=9, textColor=colors.white,
                  backColor=colors.HexColor(f"#{SUBHDR_BG}"), alignment=TA_CENTER, spaceAfter=8)
    h1_s     = ST("H1", fontSize=12, textColor=colors.white,
                  backColor=colors.HexColor(f"#{SUBHDR_BG}"), spaceBefore=10, spaceAfter=5)
    h2_s     = ST("H2", fontSize=10, textColor=colors.HexColor(f"#{HEADER_BG}"),
                  spaceBefore=8, spaceAfter=4, fontName="Helvetica-Bold")
    cell_s   = ST("C", fontSize=7, leading=9)
    normal_s = ST("N", fontSize=8.5, spaceAfter=2)
    meta_s   = ST("M", fontSize=8, textColor=colors.HexColor("#777777"), alignment=TA_CENTER, spaceAfter=6)

    story = []

    # ── Title ──────────────────────────────────────────────
    story.append(Paragraph("SonarQube Security Hotspots — VAPT Report", title_s))
    pname = project_info.get("name", project_info.get("key",""))
    story.append(Paragraph(
        f"Project: <b>{pname}</b>  |  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  CONFIDENTIAL", sub_s))
    story.append(HRFlowable(width="100%", color=colors.HexColor(f"#{HEADER_BG}"), thickness=1))
    story.append(Spacer(1, 8))

    # ── Executive Summary ──────────────────────────────────
    story.append(Paragraph("Executive Summary", h1_s))
    story.append(Paragraph(f"Total Security Hotspots Found: <b>{summary['total']}</b>", normal_s))
    story.append(Spacer(1, 6))

    for section_title, data, color_map in [
        ("Breakdown by Status",   summary["by_status"],   STATUS_HEX),
        ("Breakdown by Severity", summary["by_severity"],  SEVERITY_HEX),
        ("Breakdown by Category", summary["by_category"],  {}),
    ]:
        story.append(Paragraph(section_title, h2_s))
        rows = [["Name", "Count", "% of Total"]]
        for name, count in sorted(data.items(), key=lambda x: -x[1]):
            pct = f"{round(count/summary['total']*100,1)}%" if summary["total"] else "0%"
            rows.append([name, str(count), pct])
        tbl = Table(rows, colWidths=[7*cm, 2.5*cm, 3*cm])
        cmds = [
            ("BACKGROUND", (0,0),(-1,0), colors.HexColor(f"#{HEADER_BG}")),
            ("TEXTCOLOR",  (0,0),(-1,0), colors.white),
            ("FONTNAME",   (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0),(-1,-1), 8),
            ("ALIGN",      (1,1),(-1,-1), "CENTER"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, colors.HexColor(f"#{STRIPE_BG}")]),
            ("GRID",       (0,0),(-1,-1), 0.4, colors.HexColor("#CCCCCC")),
            ("TOPPADDING", (0,0),(-1,-1), 4), ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ]
        for i, row_data in enumerate(rows[1:], 1):
            hex_c = color_map.get(row_data[0])
            if hex_c:
                cmds += [("BACKGROUND",(0,i),(0,i),colors.HexColor(f"#{hex_c}")),
                         ("TEXTCOLOR", (0,i),(0,i),colors.white),
                         ("FONTNAME",  (0,i),(0,i),"Helvetica-Bold")]
        tbl.setStyle(TableStyle(cmds))
        story.append(tbl)
        story.append(Spacer(1, 8))

    story.append(PageBreak())

    # ── Per-Category Detailed Findings ────────────────────
    story.append(Paragraph("Detailed Findings by Category", h1_s))
    story.append(Spacer(1, 6))

    cats = {}
    for h in hotspots:
        cats.setdefault(h["category_display"], []).append(h)

    sev_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4,"":5}

    for cat, items in sorted(cats.items()):
        items_sorted = sorted(items, key=lambda x: sev_order.get(x["severity"], 5))
        story.append(Paragraph(f"  {cat}  ({len(items)} findings)", h1_s))
        story.append(Spacer(1, 4))

        for idx, hs in enumerate(items_sorted, 1):
            sev_hex = SEVERITY_HEX.get(hs["severity"], "999999")
            stat_hex = STATUS_HEX.get(hs["status"], "999999")

            # Header row for each finding
            hdr_data = [[
                Paragraph(f"<b>#{idx}</b>", cell_s),
                Paragraph(f"<b>Severity:</b> {hs['severity'] or '—'}", cell_s),
                Paragraph(f"<b>Status:</b> {hs['status'] or '—'}", cell_s),
                Paragraph(f"<b>Rule:</b> {hs['rule_name'] or hs['rule_key'] or '—'}", cell_s),
                Paragraph(f"<b>Author:</b> {hs['author'] or '—'}", cell_s),
                Paragraph(f"<b>Date:</b> {hs['created'] or '—'}", cell_s),
            ]]
            hdr_tbl = Table(hdr_data, colWidths=[1*cm, 3*cm, 3.5*cm, 7.5*cm, 4*cm, 3*cm])
            hdr_style = [
                ("BACKGROUND",(0,0),(-1,-1), colors.HexColor(f"#{STRIPE_BG}")),
                ("GRID",(0,0),(-1,-1), 0.3, colors.HexColor("#BBBBBB")),
                ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
                ("BACKGROUND",(1,0),(1,0), colors.HexColor(f"#{sev_hex}")),
                ("TEXTCOLOR", (1,0),(1,0), colors.white),
                ("BACKGROUND",(2,0),(2,0), colors.HexColor(f"#{stat_hex}")),
                ("TEXTCOLOR", (2,0),(2,0), colors.white),
            ]
            hdr_tbl.setStyle(TableStyle(hdr_style))

            # Detail row
            det_data = [[
                Paragraph(f"<b>Message:</b> {hs['message']}", cell_s),
                Paragraph(f"<b>File:</b> {hs['file']}  <b>Line:</b> {hs['line']}", cell_s),
            ]]
            det_tbl = Table(det_data, colWidths=[13*cm, 9*cm])
            det_tbl.setStyle(TableStyle([
                ("GRID",(0,0),(-1,-1), 0.3, colors.HexColor("#CCCCCC")),
                ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
            ]))

            # Risk + Fix row (only if present)
            extra_rows = []
            if hs["risk_desc"] or hs["fix_desc"]:
                rf_data = [[
                    Paragraph(f"<b>What's the Risk?</b><br/>{hs['risk_desc'] or '—'}", cell_s),
                    Paragraph(f"<b>How to Fix?</b><br/>{hs['fix_desc'] or '—'}", cell_s),
                ]]
                rf_tbl = Table(rf_data, colWidths=[11*cm, 11*cm])
                rf_tbl.setStyle(TableStyle([
                    ("BACKGROUND",(0,0),(0,0), colors.HexColor("#FEF9E7")),
                    ("BACKGROUND",(1,0),(1,0), colors.HexColor("#EAFAF1")),
                    ("GRID",(0,0),(-1,-1), 0.3, colors.HexColor("#CCCCCC")),
                    ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),
                ]))
                extra_rows.append(rf_tbl)

            story.append(KeepTogether([hdr_tbl, det_tbl] + extra_rows + [Spacer(1, 6)]))

        story.append(Spacer(1, 10))

    # ── Plain summary table (all hotspots) ────────────────
    story.append(PageBreak())
    story.append(Paragraph("All Hotspots — Quick Reference", h1_s))
    story.append(Spacer(1, 6))

    col_headers = ["#","Sev","Status","Category","Message","File : Line","Rule","Author","Date"]
    col_ws      = [0.7*cm, 1.8*cm, 2.4*cm, 3.2*cm, 6.5*cm, 7*cm, 3.2*cm, 2.8*cm, 1.8*cm]

    tbl_data = [col_headers]
    sev_map = {}
    stat_map = {}

    all_sorted = sorted(hotspots, key=lambda x: (sev_order.get(x["severity"],5), x["status"]))
    for idx, hs in enumerate(all_sorted, 1):
        msg  = hs["message"][:100] + ("…" if len(hs["message"])>100 else "")
        fl   = f"{hs['file']}" + (f" :{hs['line']}" if hs["line"] != "—" else "")
        tbl_data.append([
            str(idx),
            hs["severity"] or "—",
            hs["status"] or "—",
            hs["category_display"] or "—",
            Paragraph(msg, cell_s),
            Paragraph(fl, cell_s),
            Paragraph(hs["rule_name"] or hs["rule_key"] or "—", cell_s),
            hs["author"] or "—",
            hs["created"] or "—",
        ])
        sev_map[len(tbl_data)-1]  = hs["severity"]
        stat_map[len(tbl_data)-1] = hs["status"]

    ref_tbl = Table(tbl_data, colWidths=col_ws, repeatRows=1)
    ref_cmds = [
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor(f"#{HEADER_BG}")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,0),7.5),
        ("FONTSIZE",(0,1),(-1,-1),7),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor(f"#{STRIPE_BG}")]),
        ("GRID",(0,0),(-1,-1),0.3,colors.HexColor("#CCCCCC")),
        ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),
    ]
    for ri, sev in sev_map.items():
        hex_c = SEVERITY_HEX.get(sev)
        if hex_c:
            ref_cmds += [("BACKGROUND",(1,ri),(1,ri),colors.HexColor(f"#{hex_c}")),
                         ("TEXTCOLOR",(1,ri),(1,ri),colors.white),("FONTNAME",(1,ri),(1,ri),"Helvetica-Bold")]
    for ri, stat in stat_map.items():
        hex_c = STATUS_HEX.get(stat)
        if hex_c:
            ref_cmds += [("BACKGROUND",(2,ri),(2,ri),colors.HexColor(f"#{hex_c}")),
                         ("TEXTCOLOR",(2,ri),(2,ri),colors.white),("FONTNAME",(2,ri),(2,ri),"Helvetica-Bold")]

    ref_tbl.setStyle(TableStyle(ref_cmds))
    story.append(ref_tbl)

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    print(f"[✓] PDF  → {path}")


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#888888"))
    w, h = PAGE_SIZE
    canvas.drawString(1.2*cm, 0.7*cm,
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}  |  CONFIDENTIAL — Internal Use Only")
    canvas.drawRightString(w-1.2*cm, 0.7*cm, f"Page {doc.page}")
    canvas.restoreState()

# ══════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════

def parse_args():
    p = argparse.ArgumentParser(
        description="SonarQube Security Hotspots → PDF + Excel (v2 — full detail)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sonarqube_hotspots.py --url http://localhost:9000 --token squ_abc --project myapp
  python sonarqube_hotspots.py --url http://localhost:9000 --token squ_abc --project myapp --status TO_REVIEW --output-dir C:\\Reports
""")
    p.add_argument("--url",        required=True)
    p.add_argument("--token",      required=True)
    p.add_argument("--project",    required=True)
    p.add_argument("--status",     default=None, help="TO_REVIEW | REVIEWED | ACKNOWLEDGED | FIXED | SAFE")
    p.add_argument("--output-dir", default=".")
    p.add_argument("--prefix",     default=None)
    p.add_argument("--no-pdf",     action="store_true")
    p.add_argument("--no-excel",   action="store_true")
    p.add_argument("--json",       action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    prefix    = (args.prefix or args.project).replace("/","_").replace(":","_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base      = os.path.join(args.output_dir, f"{prefix}_{timestamp}")

    print(f"\n{'='*60}")
    print(f"  SonarQube Hotspot Fetcher v2")
    print(f"  URL     : {args.url}")
    print(f"  Project : {args.project}")
    print(f"  Status  : {args.status or 'ALL'}")
    print(f"{'='*60}\n")

    client       = SonarQubeClient(args.url, args.token)
    project_info = client.get_project_info(args.project)

    print("[*] Fetching hotspot list …")
    raw = client.get_hotspots(args.project, status=args.status)
    print(f"    → {len(raw)} hotspots\n")

    if not raw:
        print("[!] No hotspots found.")
        sys.exit(0)

    print("[*] Fetching per-hotspot detail (category, rule, risk, fix) …")
    hotspots = enrich(client, raw)
    summary  = build_summary(hotspots)

    print(f"\n[*] Summary:")
    for s, c in sorted(summary["by_status"].items(), key=lambda x: -x[1]):
        print(f"    {s:<22} {c}")
    print(f"    {'Total':<22} {summary['total']}\n")

    if args.json:
        jpath = base + ".json"
        with open(jpath, "w") as f: json.dump(hotspots, f, indent=2)
        print(f"[✓] JSON → {jpath}")

    if not args.no_excel:
        export_excel(hotspots, summary, project_info, base + ".xlsx")

    if not args.no_pdf:
        export_pdf(hotspots, summary, project_info, base + ".pdf")

    print(f"\n[✓] Done → {os.path.abspath(args.output_dir)}\n")


if __name__ == "__main__":
    main()