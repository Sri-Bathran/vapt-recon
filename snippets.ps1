# snippets.ps1 - prints short, masked excerpts around regex matches, so a reviewer can verify a finding
# without being sent whole files. Appends to <Root>\recon-output\snippets.txt. CLM-safe, no admin.
#
# One query:
#   powershell -ExecutionPolicy Bypass -File snippets.ps1 -Pattern 'polyfill\.io' -PathLike '\.js$' -Context 0
# Many queries from a file (one per line:  label :: regex :: path regex :: context lines :: max hits ; '#' = comment):
#   powershell -ExecutionPolicy Bypass -File snippets.ps1 -QueryFile queries.txt
#
# Masking: cloud keys, JWTs, URL credentials, values after password/secret/token/key names, and any 32+ character
# token-like string are cut to their first characters. Long (minified) lines are cut to a window around the match.
param(
    [string]$Root = (Get-Location).Path,
    [string]$Pattern = '',
    [string]$Label = '',
    [string]$PathLike = '',
    [int]$Context = 0,
    [int]$Max = 20,
    [int]$Width = 170,
    [string]$QueryFile = '',
    [string]$OutFile = ''
)
$Root = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
$rootLen = $Root.Length + 1
$outDir = Join-Path $Root 'recon-output'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
if (-not $OutFile) { $OutFile = Join-Path $outDir 'snippets.txt' }
$skipRx = '(?i)\\(node_modules|\.git|\.dart_tool|\.gradle|build|pods|\.pub-cache|recon-output|review-files|\.fvm|intermediates)(\\|$)'
$include = @('*.js', '*.dart', '*.kt', '*.java', '*.swift', '*.m', '*.h', '*.xml', '*.json', '*.gradle', '*.kts', '*.plist', '*.yml', '*.yaml', '*.properties', '*.md', '*.pro', '*.html')

function Hide-Text([string]$s) {
    $t = [regex]::Replace($s, '(AKIA[0-9A-Z]{2}|AIza[0-9A-Za-z_\-]{4}|eyJ[A-Za-z0-9_\-]{4})[A-Za-z0-9_\-\.]+', '$1***')
    $t = [regex]::Replace($t, '://[^/\s:@]+:[^/\s@]+@', '://***:***@')
    $t = [regex]::Replace($t, '(?i)((password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[a-z_]*|private[_-]?key)["'']?(\s*[:=]\s*["'']?|\s+["'']))([^"''\s,;]{0,3})[^"''\s,;]*', '$1$4***')
    # long token-like strings are masked only when they contain a digit (random keys do; identifiers such as kSecAttrAccessible... do not)
    $t = [regex]::Replace($t, '([A-Za-z0-9+/=_\-]{4})(?=[A-Za-z0-9+/=_\-]*[0-9])[A-Za-z0-9+/=_\-]{28,}', '$1***')
    # Indian personal identifiers: PAN, Aadhaar (12 digits), mobile numbers (10 digits)
    $t = [regex]::Replace($t, '\b([A-Z]{2})[A-Z]{3}[0-9]{4}[A-Z]\b', '$1***')
    $t = [regex]::Replace($t, '\b([0-9]{2})[0-9]{8,10}\b', '$1***')
    return $t
}

function Run-Query([string]$label, [string]$rx, [string]$pathRx, [int]$ctx, [int]$max) {
    $hdr = "## $label   [pattern: $rx]" + $(if ($pathRx) { "   [paths: $pathRx]" } else { '' })
    Write-Host "[*] $label"
    $lines = @($hdr)
    $files = Get-ChildItem -LiteralPath $Root -Recurse -File -Force -Include $include -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch $skipRx -and $_.Length -lt 12MB }
    if ($pathRx) { $files = @($files | Where-Object { $_.FullName.Substring($rootLen) -match $pathRx }) }
    $hits = 0
    foreach ($f in $files) {
        if ($hits -ge $max) { break }
        $rel = $f.FullName.Substring($rootLen)
        $ms = @(Select-String -LiteralPath $f.FullName -Pattern $rx -Context $ctx, $ctx -ErrorAction SilentlyContinue)
        foreach ($m in $ms) {
            if ($hits -ge $max) { break }
            $hits++
            $ln = $m.Line
            if ($ln.Length -gt $Width) {
                $mi = [regex]::Match($ln, $rx).Index - [int]($Width / 3)
                if ($mi -lt 0) { $mi = 0 }
                $take = $ln.Length - $mi
                if ($take -gt $Width) { $take = $Width }
                $ln = $ln.Substring($mi, $take)
                # never start or end inside a token (it could be the tail or head of a key)
                $ln = '...' + [regex]::Replace([regex]::Replace($ln, '^[A-Za-z0-9_\-\.]+', ''), '[A-Za-z0-9_\-\.]+$', '') + '...'
            }
            $lines += ('{0}:{1}' -f $rel, $m.LineNumber)
            if ($ctx -gt 0 -and $m.Context) {
                foreach ($c in @($m.Context.PreContext)) { if ($null -ne $c) { $lines += ('      | ' + (Hide-Text $c.Trim())) } }
            }
            $lines += ('   >> ' + (Hide-Text $ln.Trim()))
            if ($ctx -gt 0 -and $m.Context) {
                foreach ($c in @($m.Context.PostContext)) { if ($null -ne $c) { $lines += ('      | ' + (Hide-Text $c.Trim())) } }
            }
        }
    }
    if ($hits -eq 0) { $lines += '   (no match)' }
    $lines += ''
    Add-Content -LiteralPath $OutFile -Value $lines -Encoding UTF8
}

if ($QueryFile) {
    if (-not (Test-Path -LiteralPath $QueryFile)) { Write-Host "Query file not found: $QueryFile"; exit 1 }
    foreach ($q in @(Get-Content -LiteralPath $QueryFile)) {
        $t = $q.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $p = [regex]::Split($t, '\s*::\s*')
        $ctx = 0; $mx = 20
        if ($p.Count -gt 3) { $ctx = [int]$p[3].Trim() }
        if ($p.Count -gt 4) { $mx = [int]$p[4].Trim() }
        $pl = ''; if ($p.Count -gt 2) { $pl = $p[2].Trim() }
        Run-Query $p[0].Trim() $p[1].Trim() $pl $ctx $mx
    }
}
elseif ($Pattern) {
    $lab = $Label; if (-not $lab) { $lab = $Pattern }
    Run-Query $lab $Pattern $PathLike $Context $Max
}
else { Write-Host 'Give -Pattern or -QueryFile (see the header of this script).'; exit 1 }
Write-Host "[OK] excerpts appended to $OutFile"
