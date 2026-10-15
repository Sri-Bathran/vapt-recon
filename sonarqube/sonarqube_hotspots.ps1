<#
.SYNOPSIS
    SonarQube Security Hotspots fetcher (PowerShell port of sonarqube_hotspots.py).
    No Python, no pip, no admin rights needed. Works in Windows PowerShell 5.1,
    including locked-down machines running Constrained Language Mode (cmdlets only).

.DESCRIPTION
    Pulls ALL security hotspots for a project, fetches per-hotspot detail
    (category, rule, risk, fix, author, dates, comment) and writes:
      <name>.xlsx  native Excel workbook (Summary + All Hotspots + By Category) - Excel not required to create it
      <name>.html  print-ready report (open in a browser -> Ctrl+P -> Save as PDF)
      <name>.csv   flat table
      <name>.json  enriched data (only with -Json)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\sonarqube_hotspots.ps1 -Url http://localhost:9000 -Token squ_xxx -Project myapp -OutputDir C:\Reports

.EXAMPLE
    .\sonarqube_hotspots.ps1 -Url http://localhost:9000 -Token squ_xxx -Project myapp -Status TO_REVIEW -Json

.EXAMPLE
    # Hotspots + open security issues (vulnerabilities), with the source lines around each one
    .\sonarqube_hotspots.ps1 -Url http://localhost:9000 -Token squ_xxx -Project myapp -Json -Issues -IncludeCode
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][string]$Token,
    [Parameter(Mandatory = $true)][string]$Project,
    [ValidateSet('TO_REVIEW', 'REVIEWED', 'ACKNOWLEDGED', 'FIXED', 'SAFE')][string]$Status,
    [string]$OutputDir = '.',
    [string]$Prefix,
    [switch]$NoExcel,
    [switch]$NoHtml,
    [switch]$NoCsv,
    [switch]$Json,
    [switch]$Issues,        # also export open security issues (vulnerabilities), with source lines
    [switch]$IncludeCode,   # add the source lines around each hotspot to the .json / .csv
    [int]$CodeContext = 6   # lines of source above and below the flagged line
)

$ErrorActionPreference = 'Stop'

# ======================================================================
# CONSTANTS
# ======================================================================
$HEADER_BG = '1A2B4A'
$SUBHDR_BG = '2C3E6B'
$STRIPE_BG = 'EBF0FA'

$ColorKeyList = @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'TO_REVIEW', 'REVIEWED', 'ACKNOWLEDGED', 'FIXED', 'SAFE')
$ColorHex = @{
    CRITICAL = 'C0392B'; HIGH = 'E67E22'; MEDIUM = 'E8A838'; LOW = '27AE60'; INFO = '2980B9'
    TO_REVIEW = 'E74C3C'; REVIEWED = '27AE60'; ACKNOWLEDGED = 'F39C12'; FIXED = '2ECC71'; SAFE = '3498DB'
}
$SevOrder = @{ CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3; INFO = 4 }

$CategoryNames = @{
    'buffer-overflow' = 'Buffer Overflow'; 'sql-injection' = 'SQL Injection'; 'rce' = 'Remote Code Execution'
    'object-injection' = 'Object Injection'; 'command-injection' = 'Command Injection'
    'path-traversal-injection' = 'Path Traversal'; 'ldap-injection' = 'LDAP Injection'
    'xpath-injection' = 'XPath Injection'; 'expression-lang-injection' = 'Expression Language Injection'
    'log-injection' = 'Log Injection'; 'xxe' = 'XML External Entity (XXE)'; 'open-redirect' = 'Open Redirect'
    'ssrf' = 'Server-Side Request Forgery'; 'csrf' = 'Cross-Site Request Forgery (CSRF)'
    'xss' = 'Cross-Site Scripting (XSS)'; 'dos' = 'Denial of Service (DoS)'
    'weak-cryptography' = 'Weak Cryptography'; 'auth' = 'Authentication'
    'insecure-conf' = 'Insecure Configuration'; 'file-manipulation' = 'File Manipulation'; 'others' = 'Others'
    'http-response-splitting' = 'HTTP Response Splitting'; 'header-injection' = 'Header Injection'
    'encrypt-data' = 'Encryption of Sensitive Data'; 'traceability' = 'Traceability'; 'permission' = 'Permission'
}

# ======================================================================
# SONARQUBE CLIENT
# ======================================================================
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

# Base64 by hand (token is ASCII) - [Convert] is blocked in Constrained Language Mode.
function ConvertTo-Base64Ascii([string]$Text) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    $bytes = @($Text.ToCharArray() | ForEach-Object { [int]$_ })
    $out = ''
    for ($i = 0; $i -lt $bytes.Count; $i += 3) {
        $b0 = $bytes[$i]
        $b1 = 0; $b2 = 0
        $have = 1
        if ($i + 1 -lt $bytes.Count) { $b1 = $bytes[$i + 1]; $have = 2 }
        if ($i + 2 -lt $bytes.Count) { $b2 = $bytes[$i + 2]; $have = 3 }
        $n = ($b0 * 65536) + ($b1 * 256) + $b2
        $out += $alphabet[[int]((($n - ($n % 262144)) / 262144) % 64)]
        $out += $alphabet[[int]((($n - ($n % 4096)) / 4096) % 64)]
        if ($have -ge 2) { $out += $alphabet[[int]((($n - ($n % 64)) / 64) % 64)] } else { $out += '=' }
        if ($have -ge 3) { $out += $alphabet[[int]($n % 64)] } else { $out += '=' }
    }
    return $out
}

$script:BaseUrl = $Url.TrimEnd('/')
$script:Headers = @{ Authorization = ('Basic ' + (ConvertTo-Base64Ascii ($Token + ':'))); Accept = 'application/json' }

function Invoke-Sonar([string]$Path, [hashtable]$Query) {
    $qs = ''
    if ($Query -and $Query.Count -gt 0) {
        $pairs = foreach ($k in $Query.Keys) {
            '{0}={1}' -f [uri]::EscapeDataString([string]$k), [uri]::EscapeDataString([string]$Query[$k])
        }
        $qs = '?' + ($pairs -join '&')
    }
    Invoke-RestMethod -Uri ($script:BaseUrl + $Path + $qs) -Headers $script:Headers -Method Get -TimeoutSec 60
}

function Get-ProjectInfo([string]$Key) {
    try { return (Invoke-Sonar '/api/components/show' @{ component = $Key }).component }
    catch { return @{ key = $Key; name = $Key } }
}

function Get-Hotspots([string]$Key) {
    $all = @()
    $page = 1
    while ($true) {
        $q = @{ projectKey = $Key; p = $page; ps = 500 }
        if ($Status -eq 'TO_REVIEW') { $q.status = 'TO_REVIEW' }
        elseif ($Status -eq 'REVIEWED') { $q.status = 'REVIEWED' }
        elseif ($Status) { $q.status = 'REVIEWED'; $q.resolution = $Status }   # ACKNOWLEDGED / FIXED / SAFE
        try { $data = Invoke-Sonar '/api/hotspots/search' $q }
        catch { throw "API call failed: $($_.Exception.Message)" }
        $batch = @($data.hotspots)
        $all += $batch
        $total = [int]$data.paging.total
        Write-Host ("  Page {0}: {1} hotspots  (total: {2})" -f $page, $batch.Count, $total)
        if (($page * 500) -ge $total -or $batch.Count -eq 0) { break }
        $page++
    }
    return $all
}

function Get-HotspotDetail([string]$Key) {
    try { return Invoke-Sonar '/api/hotspots/show' @{ hotspot = $Key } }
    catch { Write-Host "  [WARN] Could not fetch detail for ${Key}: $($_.Exception.Message)"; return $null }
}

# ======================================================================
# SOURCE SNIPPETS + SECURITY ISSUES (vulnerabilities)
# ======================================================================
# /api/sources/lines returns each line as HTML (syntax-highlight spans, entities).
function ConvertFrom-SonarCodeHtml([string]$Html) {
    if (-not $Html) { return '' }
    $t = [regex]::Replace($Html, '<[^>]+>', '')
    return $t.Replace('&lt;', '<').Replace('&gt;', '>').Replace('&quot;', '"').Replace('&#39;', "'").Replace('&amp;', '&')
}

# A few lines of source around a finding, the flagged line marked with ">>".
function Get-CodeSnippet([string]$ComponentKey, $Line) {
    if (-not $ComponentKey -or -not $Line -or ([string]$Line) -notmatch '^\d+$') { return '' }
    $n = [int]$Line
    $from = $n - $CodeContext; if ($from -lt 1) { $from = 1 }
    $to = $n + $CodeContext
    try { $r = Invoke-Sonar '/api/sources/lines' @{ key = $ComponentKey; from = $from; to = $to } }
    catch { return '' }
    $rows = foreach ($s in @($r.sources)) {
        $mark = '  '; if ([int]$s.line -eq $n) { $mark = '>>' }
        '{0}{1,5}  {2}' -f $mark, $s.line, (ConvertFrom-SonarCodeHtml ([string]$s.code))
    }
    return (@($rows) -join "`n")
}

# Rule description as plain text (newer servers use descriptionSections, older htmlDesc).
function Get-RuleText([string]$RuleKey) {
    try { $r = (Invoke-Sonar '/api/rules/show' @{ key = $RuleKey }).rule } catch { return '' }
    $parts = @()
    foreach ($sec in @($r.descriptionSections)) { if ($sec.content) { $parts += ConvertTo-PlainText ([string]$sec.content) } }
    if ($parts.Count -eq 0 -and $r.htmlDesc) { $parts += ConvertTo-PlainText ([string]$r.htmlDesc) }
    $text = ($parts -join ' ')
    if ($text.Length -gt 2500) { $text = $text.Substring(0, 2500) + ' ...' }
    return $text
}

# Open security issues. Newer SonarQube filters by software quality; if the server
# rejects that, fall back to the legacy VULNERABILITY type filter.
function Get-SecurityIssues([string]$Key) {
    $all = @()
    $ruleNames = @{}
    $legacy = $false
    $page = 1
    while ($true) {
        $q = @{ componentKeys = $Key; p = $page; ps = 500; additionalFields = 'rules' }
        if ($legacy) { $q.types = 'VULNERABILITY'; $q.resolved = 'false' }
        else { $q.impactSoftwareQualities = 'SECURITY'; $q.issueStatuses = 'OPEN,CONFIRMED' }
        try { $data = Invoke-Sonar '/api/issues/search' $q }
        catch {
            if (-not $legacy -and $page -eq 1) {
                Write-Host '  (server rejected the new issue filters, using legacy filters)'
                $legacy = $true
                continue
            }
            throw "Issue search failed: $($_.Exception.Message)"
        }
        foreach ($r in @($data.rules)) { if ($r.key) { $ruleNames[[string]$r.key] = [string]$r.name } }
        $batch = @($data.issues)
        $all += $batch
        $total = [int]$data.paging.total
        Write-Host ("  Page {0}: {1} issues  (total: {2})" -f $page, $batch.Count, $total)
        if (($page * 500) -ge $total -or $batch.Count -eq 0) { break }
        $page++
    }
    return @{ issues = $all; ruleNames = $ruleNames }
}

function Get-EnrichedIssues($found) {
    $ruleText = @{}
    $n = 0
    $total = @($found.issues).Count
    foreach ($i in @($found.issues)) {
        $n++
        Write-Host ("  [{0}/{1}] Issue: {2}" -f $n, $total, $i.key)
        $ruleKey = [string]$i.rule
        if (-not $ruleText.ContainsKey($ruleKey)) { $ruleText[$ruleKey] = Get-RuleText $ruleKey }

        $compKey = [string]$i.component
        $file = $compKey
        if ($file.StartsWith("${Project}:")) { $file = $file.Substring($Project.Length + 1) }
        $line = $i.line
        if (-not $line) { $line = $i.textRange.startLine }

        # Severity: the software-quality impact when present, else the legacy severity.
        $sev = [string]$i.severity
        $quality = ''
        $imp = @($i.impacts)
        if ($imp.Count -gt 0 -and $imp[0]) { $sev = [string]$imp[0].severity; $quality = [string]$imp[0].softwareQuality }

        $ruleName = ''
        if ($found.ruleNames.ContainsKey($ruleKey)) { $ruleName = $found.ruleNames[$ruleKey] }
        $lineText = '-'; if ($line) { $lineText = [string]$line }
        $tags = ''; if ($i.tags) { $tags = (@($i.tags) -join ', ') }

        New-Object PSObject -Property @{
            key         = [string]$i.key
            severity    = $sev.ToUpper()
            quality     = $quality
            type        = [string]$i.type
            status      = [string]$i.status
            rule_key    = $ruleKey
            rule_name   = $ruleName
            message     = [string]$i.message
            file        = $file
            line        = $lineText
            created     = (Format-Day $i.creationDate)
            effort      = [string]$i.effort
            clean_code  = [string]$i.cleanCodeAttribute
            tags        = $tags
            rule_desc   = $ruleText[$ruleKey]
            code        = (Get-CodeSnippet $compKey $line)
        } | Select-Object key, severity, quality, type, status, rule_key, rule_name, message, file, line, created, effort, clean_code, tags, rule_desc, code
    }
}

function Export-IssueReports([string]$Key, [string]$base) {
    Write-Host '[*] Fetching open security issues (vulnerabilities) ...'
    $found = Get-SecurityIssues $Key
    $count = @($found.issues).Count
    Write-Host "    -> $count security issues"
    Write-Host ''
    if ($count -eq 0) { Write-Host '[!] No open security issues found.'; return }

    Write-Host '[*] Fetching rule text and source lines ...'
    $issues = @(Get-EnrichedIssues $found)
    Write-Host ''
    Write-Host '[*] Issues by severity:'
    foreach ($e in ((Get-Counts $issues 'severity').GetEnumerator() | Sort-Object Value -Descending)) { Write-Host ('    {0,-22} {1}' -f $e.Key, $e.Value) }

    $jp = "${base}_issues.json"
    Set-Content -LiteralPath $jp -Value (ConvertTo-Json -InputObject $issues -Depth 5) -Encoding UTF8
    Write-Host "[OK] Issues JSON -> $jp"
    $cp = "${base}_issues.csv"
    $issues | Export-Csv -LiteralPath $cp -NoTypeInformation -Encoding UTF8
    Write-Host "[OK] Issues CSV  -> $cp"
}

# ======================================================================
# DATA ENRICHMENT
# ======================================================================
function Get-HtmlEscaped($s) {
    if ($null -eq $s) { return '' }
    return ([string]$s).Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function ConvertTo-PlainText([string]$Text) {
    if (-not $Text) { return '' }
    $t = [regex]::Replace($Text, '<[^>]+>', ' ')
    $t = $t.Replace('&amp;', '&').Replace('&lt;', '<').Replace('&gt;', '>').Replace('&quot;', '"').Replace('&#39;', "'").Replace('&nbsp;', ' ')
    return ([regex]::Replace($t, '\s+', ' ')).Trim()
}

function Format-Day($v) {
    if (-not $v) { return '' }
    if ($v -is [datetime]) { return $v.ToString('yyyy-MM-dd') }
    $s = [string]$v
    if ($s.Length -ge 10) { return $s.Substring(0, 10) }
    return $s
}

function Get-TitleCase([string]$s) {
    $words = foreach ($w in ($s -split '[-\s]+')) { if ($w.Length -gt 0) { $w.Substring(0, 1).ToUpper() + $w.Substring(1) } }
    return ($words -join ' ')
}

function Get-EnrichedHotspots($rawList) {
    $hsProps = @('key', 'severity', 'status', 'category', 'category_display', 'rule_key', 'rule_name', 'message', 'file', 'line', 'resolution', 'author', 'assignee', 'created', 'updated', 'risk_desc', 'fix_desc', 'comment')
    if ($IncludeCode) { $hsProps += 'code' }
    $total = @($rawList).Count
    $i = 0
    foreach ($hs in $rawList) {
        $i++
        $key = [string]$hs.key
        Write-Host ("  [{0}/{1}] Detail: {2}" -f $i, $total, $key)
        $d = Get-HotspotDetail $key
        if (-not $d) { $d = @{} }

        # component / file path
        $comp = $d.component
        if (-not $comp) { $comp = $hs.component }
        if ($comp -is [string]) { $file = $comp }
        else {
            $file = $comp.path
            if (-not $file) { $file = $comp.longName }
            if (-not $file) { $file = $comp.key }
        }
        $compKey = ''
        if ($comp -is [string]) { $compKey = $comp } else { $compKey = [string]$comp.key }
        if ($file -and $file.StartsWith("${Project}:")) { $file = $file.Substring($Project.Length + 1) }

        # line
        $line = $d.line
        if (-not $line) { $line = $d.textRange.startLine }
        if (-not $line) { $line = $hs.line }
        if (-not $line) { $line = $hs.textRange.startLine }

        # rule
        $rule = $d.rule
        if (-not $rule) { $rule = $hs.rule }
        $ruleKey = ''; $ruleName = ''; $category = ''; $prob = ''; $risk = ''; $fix = ''
        if ($rule -is [string]) { $ruleKey = $rule }
        elseif ($rule) {
            $ruleKey = [string]$rule.key
            $ruleName = [string]$rule.name
            $category = [string]$rule.securityCategory
            $prob = [string]$rule.vulnerabilityProbability
            $risk = ConvertTo-PlainText ([string]$rule.riskDescription)
            $fix = ConvertTo-PlainText ([string]$rule.fixRecommendations)
        }
        if (-not $category) { $category = [string]$hs.securityCategory }
        if (-not $prob) { $prob = [string]$hs.vulnerabilityProbability }
        $severity = $prob.ToUpper()
        if ($category -and $CategoryNames.ContainsKey($category)) { $catDisplay = $CategoryNames[$category] }
        elseif ($category) { $catDisplay = Get-TitleCase $category }
        else { $catDisplay = '-' }

        # status / resolution
        $st = $d.status; if (-not $st) { $st = $hs.status }
        $res = $d.resolution; if (-not $res) { $res = $hs.resolution }

        # author / assignee
        $author = $d.author; if (-not $author) { $author = $hs.author }
        $assignee = ''
        $a = $d.assignee
        if ($a -is [string]) { $assignee = $a }
        elseif ($a) { $assignee = $a.name; if (-not $assignee) { $assignee = $a.login } }

        # dates
        $created = $d.creationDate; if (-not $created) { $created = $hs.creationDate }
        $updated = $d.updateDate; if (-not $updated) { $updated = $hs.updateDate }

        # message / comment
        $msg = $d.message; if (-not $msg) { $msg = $hs.message }
        $comments = @($d.comment)
        $commentText = ''
        if ($comments.Count -gt 0 -and $comments[0]) { $commentText = [string]$comments[0].markdown }

        $lineText = '-'
        if ($line) { $lineText = [string]$line }
        $codeText = ''
        if ($IncludeCode) { $codeText = Get-CodeSnippet $compKey $line }

        New-Object PSObject -Property @{
            key              = $key
            severity         = $severity
            status           = [string]$st
            category         = $category
            category_display = $catDisplay
            rule_key         = $ruleKey
            rule_name        = $ruleName
            message          = [string]$msg
            file             = [string]$file
            line             = $lineText
            resolution       = [string]$res
            author           = [string]$author
            assignee         = [string]$assignee
            created          = (Format-Day $created)
            updated          = (Format-Day $updated)
            risk_desc        = $risk
            fix_desc         = $fix
            comment          = $commentText
            code             = $codeText
        } | Select-Object -Property $hsProps
    }
}

function Get-Counts($items, [string]$field) {
    $h = @{}
    foreach ($it in $items) {
        $k = $it.$field
        if (-not $k) { $k = 'Unknown' }
        if ($h.ContainsKey($k)) { $h[$k]++ } else { $h[$k] = 1 }
    }
    return $h
}

function Get-SortRank($sev) {
    if ($sev -and $SevOrder.ContainsKey($sev)) { return $SevOrder[$sev] }
    return 5
}

function Get-Pct($count, $total) {
    if ($total -gt 0) { return ('{0:0.#}%' -f ($count / $total * 100)) }
    return '0%'
}

# ======================================================================
# XLSX WRITER  (hand-built OOXML, zipped with Compress-Archive - no Excel needed)
# ======================================================================
# xf indexes: 0 body, 1 table header, 2 section header, 3 title, 4 bold, 5+ = ColorKeyList in order
$script:XfOf = @{}
for ($ci = 0; $ci -lt $ColorKeyList.Count; $ci++) { $script:XfOf[$ColorKeyList[$ci]] = 5 + $ci }

function Get-ColLetter([int]$n) {
    $s = ''
    while ($n -gt 0) {
        $m = ($n - 1) % 26
        $s = "$([char](65 + $m))$s"
        $n = [int](($n - 1 - $m) / 26)
    }
    return $s
}

function ConvertTo-XmlText($s) {
    if ($null -eq $s) { return '' }
    $s = [string]$s
    if ($s.Length -gt 32000) { $s = $s.Substring(0, 32000) }
    $s = [regex]::Replace($s, '[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF]', '')
    return $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function Get-StylesXml {
    $p = @()
    $p += '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    $p += '<fonts count="4">'
    $p += '<font><sz val="10"/><name val="Arial"/></font>'
    $p += '<font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Arial"/></font>'
    $p += '<font><b/><sz val="15"/><color rgb="FFFFFFFF"/><name val="Arial"/></font>'
    $p += '<font><b/><sz val="10"/><name val="Arial"/></font>'
    $p += '</fonts>'
    $fills = @($HEADER_BG, $SUBHDR_BG) + @($ColorKeyList | ForEach-Object { $ColorHex[$_] })
    $p += "<fills count=""$($fills.Count + 2)"">"
    $p += '<fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>'
    foreach ($f in $fills) { $p += "<fill><patternFill patternType=""solid""><fgColor rgb=""FF$f""/><bgColor indexed=""64""/></patternFill></fill>" }
    $p += '</fills>'
    $p += '<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border>'
    $p += '<border><left style="thin"><color rgb="FFCCCCCC"/></left><right style="thin"><color rgb="FFCCCCCC"/></right><top style="thin"><color rgb="FFCCCCCC"/></top><bottom style="thin"><color rgb="FFCCCCCC"/></bottom><diagonal/></border></borders>'
    $p += '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    $p += "<cellXfs count=""$(5 + $ColorKeyList.Count)"">"
    $p += '<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>'
    $p += '<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>'
    $p += '<xf numFmtId="0" fontId="1" fillId="3" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="left" vertical="center" indent="1"/></xf>'
    $p += '<xf numFmtId="0" fontId="2" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="center" vertical="center"/></xf>'
    $p += '<xf numFmtId="0" fontId="3" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1"><alignment vertical="top"/></xf>'
    for ($fi = 4; $fi -lt (4 + $ColorKeyList.Count); $fi++) {
        $p += "<xf numFmtId=""0"" fontId=""1"" fillId=""$fi"" borderId=""1"" xfId=""0"" applyFont=""1"" applyFill=""1"" applyBorder=""1"" applyAlignment=""1""><alignment horizontal=""center"" vertical=""top"" wrapText=""1""/></xf>"
    }
    $p += '</cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'
    return ($p -join '')
}

function Get-SheetXml($sheet) {
    $p = @()
    $p += '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    $p += '<sheetViews><sheetView workbookViewId="0" showGridLines="0">'
    if ($sheet.Freeze) { $p += '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>' }
    $p += '</sheetView></sheetViews>'
    if ($sheet.Widths) {
        $p += '<cols>'
        for ($c = 0; $c -lt $sheet.Widths.Count; $c++) {
            $p += "<col min=""$($c + 1)"" max=""$($c + 1)"" width=""$($sheet.Widths[$c])"" customWidth=""1""/>"
        }
        $p += '</cols>'
    }
    $p += '<sheetData>'
    $r = 0
    foreach ($row in $sheet.Rows) {
        $r++
        $ht = ''
        if ($row.H) { $ht = " ht=""$($row.H)"" customHeight=""1""" }
        $cells = for ($c = 0; $c -lt $row.V.Count; $c++) {
            $ref = "$(Get-ColLetter ($c + 1))$r"
            $s = 0
            if ($row.S -and $c -lt $row.S.Count -and $null -ne $row.S[$c]) { $s = $row.S[$c] }
            $v = $row.V[$c]
            if ($v -is [int] -or $v -is [double]) {
                "<c r=""$ref"" s=""$s""><v>$v</v></c>"
            }
            elseif ($null -eq $v -or "$v" -eq '') {
                "<c r=""$ref"" s=""$s""/>"
            }
            else {
                "<c r=""$ref"" s=""$s"" t=""inlineStr""><is><t xml:space=""preserve"">$(ConvertTo-XmlText $v)</t></is></c>"
            }
        }
        $p += "<row r=""$r""$ht>" + ($cells -join '') + '</row>'
    }
    $p += '</sheetData>'
    if ($sheet.Filter) { $p += "<autoFilter ref=""$($sheet.Filter)""/>" }
    if ($sheet.Merges -and @($sheet.Merges).Count -gt 0) {
        $p += "<mergeCells count=""$(@($sheet.Merges).Count)"">"
        foreach ($m in $sheet.Merges) { $p += "<mergeCell ref=""$m""/>" }
        $p += '</mergeCells>'
    }
    $p += '</worksheet>'
    return ($p -join '')
}

function New-Xlsx([string]$Path, $Sheets) {
    $Sheets = @($Sheets)
    $stage = Join-Path (Split-Path -Parent $Path) ('_xlsx_stage_' + (Get-Date -Format 'HHmmssfff'))
    foreach ($d in @('_rels', 'xl', 'xl\_rels', 'xl\worksheets')) {
        New-Item -ItemType Directory -Path (Join-Path $stage $d) -Force | Out-Null
    }
    try {
        $ct = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        for ($i = 1; $i -le $Sheets.Count; $i++) {
            $ct += "<Override PartName=""/xl/worksheets/sheet$i.xml"" ContentType=""application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml""/>"
        }
        $ct += '</Types>'
        Set-Content -LiteralPath (Join-Path $stage '[Content_Types].xml') -Value $ct -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $stage '_rels\.rels') -Encoding UTF8 -Value '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'

        $wb = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
        $rel = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        for ($i = 1; $i -le $Sheets.Count; $i++) {
            $wb += "<sheet name=""$(ConvertTo-XmlText $Sheets[$i-1].Name)"" sheetId=""$i"" r:id=""rId$i""/>"
            $rel += "<Relationship Id=""rId$i"" Type=""http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"" Target=""worksheets/sheet$i.xml""/>"
        }
        $wb += '</sheets></workbook>'
        $rel += "<Relationship Id=""rId$($Sheets.Count + 1)"" Type=""http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"" Target=""styles.xml""/></Relationships>"
        Set-Content -LiteralPath (Join-Path $stage 'xl\workbook.xml') -Value $wb -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $stage 'xl\_rels\workbook.xml.rels') -Value $rel -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $stage 'xl\styles.xml') -Value (Get-StylesXml) -Encoding UTF8
        for ($i = 1; $i -le $Sheets.Count; $i++) {
            Set-Content -LiteralPath (Join-Path $stage "xl\worksheets\sheet$i.xml") -Value (Get-SheetXml $Sheets[$i - 1]) -Encoding UTF8
        }

        $zipPath = $Path -replace '\.xlsx$', '.zip'
        if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
        $top = @(Get-ChildItem -LiteralPath $stage -Force | ForEach-Object { $_.FullName })
        Compress-Archive -LiteralPath $top -DestinationPath $zipPath -Force
        Move-Item -LiteralPath $zipPath -Destination $Path -Force
    }
    finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-ColorXf($key) {
    if ($key -and $script:XfOf.ContainsKey($key)) { return $script:XfOf[$key] }
    return 0
}

function Export-Excel($hotspots, $summary, $projectInfo, [string]$path) {
    $pname = $projectInfo.name; if (-not $pname) { $pname = $projectInfo.key }
    $nowText = Get-Date -Format 'yyyy-MM-dd HH:mm'

    # ---- Summary sheet
    $sumRows = @()
    $sumRows += , @{ V = @('SonarQube Security Hotspots - VAPT Report', '', ''); S = @(3, 3, 3); H = 34 }
    $sumRows += , @{ V = @("Project: $pname   |   Generated: $nowText", '', ''); S = @(2, 2, 2); H = 20 }
    $sumRows += , @{ V = @('', '', '') }
    $sumRows += , @{ V = @('Total Hotspots', [int]$summary.total, ''); S = @(4, 4, 0) }
    $sections = @(
        @{ T = 'BY STATUS'; D = $summary.by_status },
        @{ T = 'BY SEVERITY'; D = $summary.by_severity },
        @{ T = 'BY CATEGORY'; D = $summary.by_category }
    )
    foreach ($sec in $sections) {
        $sumRows += , @{ V = @('', '', '') }
        $sumRows += , @{ V = @($sec.T, '', ''); S = @(2, 2, 2) }
        $sumRows += , @{ V = @('Name', 'Count', '% of Total'); S = @(1, 1, 1); H = 22 }
        foreach ($e in ($sec.D.GetEnumerator() | Sort-Object Value -Descending)) {
            $sumRows += , @{ V = @($e.Key, [int]$e.Value, (Get-Pct $e.Value $summary.total)); S = @((Get-ColorXf $e.Key), 0, 0) }
        }
    }
    $sumSheet = @{ Name = 'Summary'; Widths = @(34, 10, 14); Rows = $sumRows; Merges = @('A1:C1', 'A2:C2') }

    # ---- All Hotspots sheet
    $cols = @('#', 'Severity', 'Status', 'Category', 'Rule Name', 'Message', 'File', 'Line', 'Author', 'Assignee', 'Created', 'Resolution', "What's the Risk?", 'How to Fix?')
    $widths = @(5, 12, 14, 26, 28, 46, 44, 6, 16, 16, 12, 14, 42, 42)
    $head = @{ V = $cols; S = @(1) * $cols.Count; H = 26 }
    $sorted = @($hotspots | Sort-Object @{Expression = { Get-SortRank $_.severity } }, status)
    $n = 0
    $dataRows = foreach ($h in $sorted) {
        $n++
        $rn = $h.rule_name; if (-not $rn) { $rn = $h.rule_key }
        $res = $h.resolution; if (-not $res) { $res = '-' }
        $rk = $h.risk_desc; if (-not $rk) { $rk = '-' }
        $fx = $h.fix_desc; if (-not $fx) { $fx = '-' }
        @{
            V = @($n, $h.severity, $h.status, $h.category_display, $rn, $h.message, $h.file, $h.line, $h.author, $h.assignee, $h.created, $res, $rk, $fx)
            S = @(0, (Get-ColorXf $h.severity), (Get-ColorXf $h.status), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            H = 60
        }
    }
    $allSheet = @{ Name = 'All Hotspots'; Widths = $widths; Rows = (@($head) + @($dataRows)); Freeze = $true; Filter = "A1:$(Get-ColLetter $cols.Count)1" }

    # ---- By Category sheet
    $bcCols = @('Severity', 'Status', 'Message', 'File', 'Line', 'Rule Name', 'Author', 'Created', 'Risk Summary')
    $bcWidths = @(12, 14, 46, 42, 6, 28, 16, 12, 44)
    $bc = @()
    $groups = @($hotspots | Group-Object category_display | Sort-Object Name)
    foreach ($g in $groups) {
        $title = @("  $($g.Name.ToUpper())  ($($g.Count) findings)") + (@('') * ($bcCols.Count - 1))
        $bc += , @{ V = $title; S = @(2) * $bcCols.Count; H = 22 }
        $bc += , @{ V = $bcCols; S = @(1) * $bcCols.Count; H = 26 }
        foreach ($h in ($g.Group | Sort-Object @{Expression = { Get-SortRank $_.severity } })) {
            $rn = $h.rule_name; if (-not $rn) { $rn = $h.rule_key }
            $rk = $h.risk_desc; if (-not $rk) { $rk = '-' }
            $bc += , @{
                V = @($h.severity, $h.status, $h.message, $h.file, $h.line, $rn, $h.author, $h.created, $rk)
                S = @((Get-ColorXf $h.severity), (Get-ColorXf $h.status), 0, 0, 0, 0, 0, 0, 0)
                H = 48
            }
        }
        $bc += , @{ V = @('') * $bcCols.Count }
    }
    $bcSheet = @{ Name = 'By Category'; Widths = $bcWidths; Rows = $bc }

    New-Xlsx $path @($sumSheet, $allSheet, $bcSheet)
    Write-Host "[OK] Excel -> $path"
}

# ======================================================================
# HTML (open in browser, Ctrl+P -> Save as PDF)
# ======================================================================
function Get-Badge([string]$value) {
    $hex = '999999'
    if ($value -and $ColorHex.ContainsKey($value)) { $hex = $ColorHex[$value] }
    $label = $value; if (-not $label) { $label = '-' }
    return "<span class=""badge"" style=""background:#$hex"">$(Get-HtmlEscaped $label)</span>"
}

function Export-Html($hotspots, $summary, $projectInfo, [string]$path) {
    $pname = $projectInfo.name; if (-not $pname) { $pname = $projectInfo.key }
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm'
    $p = @()
    $p += @"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>SonarQube Security Hotspots - $(Get-HtmlEscaped $pname)</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;font-size:12px;color:#222;margin:24px}
h1{background:#$HEADER_BG;color:#fff;text-align:center;padding:14px;margin:0;font-size:22px}
.sub{background:#$SUBHDR_BG;color:#fff;text-align:center;padding:6px;margin:0 0 14px 0}
h2{background:#$SUBHDR_BG;color:#fff;padding:6px 10px;font-size:15px;margin:22px 0 8px}
h3{color:#$HEADER_BG;margin:14px 0 4px}
table{border-collapse:collapse;width:100%;margin-bottom:10px}
th{background:#$HEADER_BG;color:#fff;padding:5px 7px;text-align:left}
td{border:1px solid #ccc;padding:4px 7px;vertical-align:top;word-break:break-word}
tr:nth-child(even) td{background:#$STRIPE_BG}
.sum{width:auto;min-width:380px}
.badge{color:#fff;font-weight:bold;padding:2px 7px;border-radius:3px;display:inline-block;font-size:11px}
.finding{page-break-inside:avoid;margin-bottom:10px}
.rf td.risk{background:#FEF9E7}.rf td.fix{background:#EAFAF1}
.foot{color:#888;font-size:10px;margin-top:20px}
@media print{body{margin:8px}.noprint{display:none}}
</style></head><body>
<h1>SonarQube Security Hotspots - VAPT Report</h1>
<p class="sub">Project: <b>$(Get-HtmlEscaped $pname)</b> | Generated: $now | CONFIDENTIAL</p>
<p class="noprint">Tip: press Ctrl+P and choose "Save as PDF" to produce a PDF.</p>
<h2>Executive Summary</h2>
<p>Total Security Hotspots Found: <b>$($summary.total)</b></p>
"@
    $sections = @(
        @{ T = 'Breakdown by Status'; D = $summary.by_status },
        @{ T = 'Breakdown by Severity'; D = $summary.by_severity },
        @{ T = 'Breakdown by Category'; D = $summary.by_category }
    )
    foreach ($sec in $sections) {
        $p += "<h3>$($sec.T)</h3><table class=""sum""><tr><th>Name</th><th>Count</th><th>% of Total</th></tr>"
        foreach ($e in ($sec.D.GetEnumerator() | Sort-Object Value -Descending)) {
            if ($ColorHex.ContainsKey($e.Key)) { $name = Get-Badge $e.Key } else { $name = Get-HtmlEscaped $e.Key }
            $p += "<tr><td>$name</td><td>$($e.Value)</td><td>$(Get-Pct $e.Value $summary.total)</td></tr>"
        }
        $p += '</table>'
    }

    $p += '<h2>Detailed Findings by Category</h2>'
    $groups = @($hotspots | Group-Object category_display | Sort-Object Name)
    foreach ($g in $groups) {
        $p += "<h3>$(Get-HtmlEscaped $g.Name) ($($g.Count) findings)</h3>"
        $idx = 0
        foreach ($h in ($g.Group | Sort-Object @{Expression = { Get-SortRank $_.severity } })) {
            $idx++
            $rn = $h.rule_name; if (-not $rn) { $rn = $h.rule_key }
            $p += "<div class=""finding""><table><tr><th>#$idx</th><td>Severity: $(Get-Badge $h.severity)</td><td>Status: $(Get-Badge $h.status)</td><td><b>Rule:</b> $(Get-HtmlEscaped $rn)</td><td><b>Author:</b> $(Get-HtmlEscaped $h.author)</td><td><b>Date:</b> $(Get-HtmlEscaped $h.created)</td></tr>"
            $p += "<tr><td colspan=""3""><b>Message:</b> $(Get-HtmlEscaped $h.message)</td><td colspan=""3""><b>File:</b> $(Get-HtmlEscaped $h.file) <b>Line:</b> $(Get-HtmlEscaped $h.line)</td></tr>"
            if ($h.risk_desc -or $h.fix_desc) {
                $rk = $h.risk_desc; if (-not $rk) { $rk = '-' }
                $fx = $h.fix_desc; if (-not $fx) { $fx = '-' }
                $p += "<tr class=""rf""><td colspan=""3"" class=""risk""><b>What's the Risk?</b><br>$(Get-HtmlEscaped $rk)</td><td colspan=""3"" class=""fix""><b>How to Fix?</b><br>$(Get-HtmlEscaped $fx)</td></tr>"
            }
            $p += '</table></div>'
        }
    }

    $p += '<h2>All Hotspots - Quick Reference</h2><table><tr><th>#</th><th>Sev</th><th>Status</th><th>Category</th><th>Message</th><th>File : Line</th><th>Rule</th><th>Author</th><th>Date</th></tr>'
    $n = 0
    $rowsHtml = foreach ($h in ($hotspots | Sort-Object @{Expression = { Get-SortRank $_.severity } }, status)) {
        $n++
        $rn = $h.rule_name; if (-not $rn) { $rn = $h.rule_key }
        $fl = $h.file; if ($h.line -ne '-') { $fl = "$($h.file) :$($h.line)" }
        "<tr><td>$n</td><td>$(Get-Badge $h.severity)</td><td>$(Get-Badge $h.status)</td><td>$(Get-HtmlEscaped $h.category_display)</td><td>$(Get-HtmlEscaped $h.message)</td><td>$(Get-HtmlEscaped $fl)</td><td>$(Get-HtmlEscaped $rn)</td><td>$(Get-HtmlEscaped $h.author)</td><td>$(Get-HtmlEscaped $h.created)</td></tr>"
    }
    $p += @($rowsHtml)
    $p += "</table><p class=""foot"">Generated: $now | CONFIDENTIAL - Internal Use Only</p></body></html>"
    Set-Content -LiteralPath $path -Value ($p -join "`r`n") -Encoding UTF8
    Write-Host "[OK] HTML  -> $path"
}

function Export-HotspotReports($raw, $projectInfo, [string]$base) {
    Write-Host '[*] Fetching per-hotspot detail (category, rule, risk, fix) ...'
    $hotspots = @(Get-EnrichedHotspots $raw)

    $summary = @{
        total       = $hotspots.Count
        by_status   = (Get-Counts $hotspots 'status')
        by_severity = (Get-Counts $hotspots 'severity')
        by_category = (Get-Counts $hotspots 'category_display')
    }
    Write-Host ''
    Write-Host '[*] Summary:'
    foreach ($e in ($summary.by_status.GetEnumerator() | Sort-Object Value -Descending)) { Write-Host ('    {0,-22} {1}' -f $e.Key, $e.Value) }
    Write-Host ('    {0,-22} {1}' -f 'Total', $summary.total)
    Write-Host ''

    if ($Json) {
        $jp = "$base.json"
        Set-Content -LiteralPath $jp -Value (ConvertTo-Json -InputObject $hotspots -Depth 5) -Encoding UTF8
        Write-Host "[OK] JSON  -> $jp"
    }
    if (-not $NoCsv) {
        $cp = "$base.csv"
        $hotspots | Export-Csv -LiteralPath $cp -NoTypeInformation -Encoding UTF8
        Write-Host "[OK] CSV   -> $cp"
    }
    if (-not $NoExcel) { Export-Excel $hotspots $summary $projectInfo "$base.xlsx" }
    if (-not $NoHtml) { Export-Html $hotspots $summary $projectInfo "$base.html" }
}

# ======================================================================
# MAIN
# ======================================================================
try {
    if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    $OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
    $pfx = $Prefix; if (-not $pfx) { $pfx = $Project }
    $pfx = ($pfx -replace '[\\/:*?"<>|]', '_')
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $base = Join-Path $OutputDir "${pfx}_$stamp"

    $statusLabel = $Status; if (-not $statusLabel) { $statusLabel = 'ALL' }
    Write-Host ''
    Write-Host ('=' * 60)
    Write-Host '  SonarQube Hotspot Fetcher (PowerShell)'
    Write-Host "  URL     : $Url"
    Write-Host "  Project : $Project"
    Write-Host "  Status  : $statusLabel"
    Write-Host ('=' * 60)
    Write-Host ''

    $projectInfo = Get-ProjectInfo $Project

    Write-Host '[*] Fetching hotspot list ...'
    $raw = @(Get-Hotspots $Project)
    Write-Host "    -> $($raw.Count) hotspots"
    Write-Host ''
    if ($raw.Count -eq 0) { Write-Host '[!] No hotspots found.' }
    else { Export-HotspotReports $raw $projectInfo $base }

    if ($Issues) { Export-IssueReports $Project $base }

    Write-Host ''
    Write-Host "[OK] Done -> $OutputDir"
    Write-Host ''
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
