# collect_review_files.ps1 - writes masked facts about a project into <Root>\recon-output:
#   secret-files-masked.txt  secret-type files (gradle/local/key properties, .env) with every value masked,
#                            plus keystore / certificate files listed by name and size only
#   manifest-lines.txt       permission, export, backup, cleartext, debuggable and scheme lines of every AndroidManifest.xml
#   signing-refs.txt         keystore / signing lines of every build.gradle(.kts), passwords masked
#   ios-config-lines.txt     App Transport Security and URL-scheme lines of every Info.plist
# No source file is copied unless you pass -CopyFiles -ListFile <text file with one relative path per line>;
# that copy goes to review-files\ and is client material: keep it on the machine, never publish it.
# CLM-safe, no admin:  powershell -ExecutionPolicy Bypass -File collect_review_files.ps1
param(
    [string]$Root = (Get-Location).Path,
    [string]$OutDir = '',
    [switch]$CopyFiles,
    [string]$ListFile = ''
)
$Root = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
if (-not $OutDir) { $OutDir = Join-Path $Root 'recon-output' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$rootLen = $Root.Length + 1
$skipRx = '(?i)\\(node_modules|\.git|\.dart_tool|\.gradle|build|pods|\.pub-cache|recon-output|review-files|\.fvm|intermediates)(\\|$)'

Write-Host '[*] Searching for secret, manifest, signing and plist files ...'
$names = @('gradle.properties', 'local.properties', 'key.properties', '.env', '.env.*', '*.env', 'androidmanifest.xml', 'build.gradle', 'build.gradle.kts', 'info.plist', '*.jks', '*.keystore', '*.p12', '*.pfx', '*.gpg', 'secrets.*')
$found = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -Include $names -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch $skipRx })
Write-Host "    -> $($found.Count) files"

function Rel($f) { return $f.FullName.Substring($rootLen) }
function Hide-Value([string]$v) {
    $v = $v.Trim().Trim('"').Trim("'")
    if ($v.Length -eq 0) { return '(empty)' }
    if ($v.Length -lt 3) { return '*** (' + $v.Length + ' chars)' }
    return $v.Substring(0, 2) + '*** (' + $v.Length + ' chars)'
}

# 1. secret-type files: key names and masked values
$m = @()
$secretNames = '^(gradle\.properties|local\.properties|key\.properties|\.env(\..+)?|.+\.env|secrets\..+)$'
foreach ($f in ($found | Where-Object { $_.Name -match $secretNames } | Sort-Object FullName)) {
    $m += "== $(Rel $f)"
    foreach ($ln in @(Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)) {
        $t = $ln.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $mm = [regex]::Match($t, '^(?:export\s+)?([^=:\s]+)\s*[=:]\s*(.*)$')
        if ($mm.Success) { $m += ('   {0} = {1}' -f $mm.Groups[1].Value, (Hide-Value $mm.Groups[2].Value)) }
        else { $m += '   (line is not key=value, ' + $t.Length + ' chars)' }
    }
}
$m += ''
$m += '== keystores / certificates / encrypted files (name and size only, never read)'
foreach ($f in ($found | Where-Object { $_.Name -match '\.(jks|keystore|p12|pfx|gpg)$' } | Sort-Object FullName)) {
    $m += ('   {0}  ({1} bytes)' -f (Rel $f), $f.Length)
}
Set-Content -LiteralPath (Join-Path $OutDir 'secret-files-masked.txt') -Value $m -Encoding UTF8

# 2. manifests
$o = @()
foreach ($f in ($found | Where-Object { $_.Name -ieq 'AndroidManifest.xml' } | Sort-Object FullName)) {
    $o += "== $(Rel $f)"
    $ml = @(Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)
    for ($i = 0; $i -lt $ml.Count; $i++) {
        if ($ml[$i] -match 'uses-permission|uses-feature|tools:node|android:exported|allowBackup|usesCleartextTraffic|debuggable|networkSecurityConfig|android:scheme|autoVerify|requestLegacyExternalStorage|android:permission') {
            $o += ('{0}: {1}' -f ($i + 1), $ml[$i].Trim())
        }
    }
}
Set-Content -LiteralPath (Join-Path $OutDir 'manifest-lines.txt') -Value $o -Encoding UTF8

# 3. signing references in gradle files (passwords masked)
$s = @()
foreach ($f in ($found | Where-Object { $_.Name -match '^build\.gradle(\.kts)?$' } | Sort-Object FullName)) {
    $gl = @(Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)
    $hits = @()
    for ($i = 0; $i -lt $gl.Count; $i++) {
        if ($gl[$i] -match '(?i)keystore|storeFile|storePassword|keyPassword|keyAlias|signingConfig|\.jks') {
            $line = [regex]::Replace($gl[$i].Trim(), '(?i)((password)\s*[=:]?\s*["''])([^"'']{0,2})[^"'']*', '$1$3***')
            $hits += ('   {0}: {1}' -f ($i + 1), $line)
        }
    }
    if ($hits.Count -gt 0) { $s += "== $(Rel $f)"; $s += $hits }
}
Set-Content -LiteralPath (Join-Path $OutDir 'signing-refs.txt') -Value $s -Encoding UTF8

# 4. iOS Info.plist: ATS and URL schemes
$p = @()
foreach ($f in ($found | Where-Object { $_.Name -ieq 'Info.plist' } | Sort-Object FullName)) {
    $pl = @(Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue)
    $hits = @()
    for ($i = 0; $i -lt $pl.Count; $i++) {
        if ($pl[$i] -match 'NSAppTransportSecurity|NSAllowsArbitraryLoads|NSExceptionDomains|NSExceptionAllowsInsecureHTTPLoads|NSAllowsLocalNetworking|CFBundleURLSchemes|LSApplicationQueriesSchemes') {
            $hits += ('   {0}: {1}' -f ($i + 1), $pl[$i].Trim())
            for ($k = 1; $k -le 6; $k++) { if ($i + $k -lt $pl.Count) { $hits += ('   {0}: {1}' -f ($i + $k + 1), $pl[$i + $k].Trim()) } }
        }
    }
    if ($hits.Count -gt 0) { $p += "== $(Rel $f)"; $p += $hits }
}
Set-Content -LiteralPath (Join-Path $OutDir 'ios-config-lines.txt') -Value $p -Encoding UTF8

# 5. optional copy of chosen source files (stays on this machine)
$copied = 0; $missing = @()
if ($CopyFiles) {
    if (-not $ListFile -or -not (Test-Path -LiteralPath $ListFile)) { Write-Host '-CopyFiles needs -ListFile <file with one relative path per line>'; exit 1 }
    $copyDir = Join-Path $Root 'review-files'
    foreach ($ln in @(Get-Content -LiteralPath $ListFile)) {
        $f = $ln.Trim()
        if ($f -eq '' -or $f.StartsWith('#')) { continue }
        $src = Join-Path $Root $f
        if (Test-Path -LiteralPath $src) {
            $dst = Join-Path $copyDir $f
            New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
            Copy-Item -LiteralPath $src -Destination $dst -Force
            $copied++
        }
        else { $missing += $f }
    }
}

Write-Host ''
Write-Host "[OK] masked facts written to $OutDir"
Write-Host '     secret-files-masked.txt, manifest-lines.txt, signing-refs.txt, ios-config-lines.txt'
if ($CopyFiles) { Write-Host "     $copied source files copied to review-files ($($missing.Count) not found) - client source, do NOT publish" }
