# publish_results.ps1 - gathers ONLY the masked recon output into one folder, ready to hand to the reviewer.
# Run it in the project root after project_recon.ps1 and collect_review_files.ps1. CLM-safe, no admin.
#   powershell -ExecutionPolicy Bypass -File publish_results.ps1 -Name myproject
# The folder is NOT uploaded anywhere: copy it to your own machine (RDP drive / clipboard) and share it
# through a channel you control. Never put it in a public repository.
param(
    [string]$Root = (Get-Location).Path,
    [string]$Name = 'project'
)
$Root = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
$src = Join-Path $Root 'recon-output'
if (-not (Test-Path -LiteralPath $src)) { Write-Host "No recon-output folder in $Root - run project_recon.ps1 first."; exit 1 }

# whitelist: masked text outputs only (never source, never review-files, never the full inventory)
$allow = @('PASTE-ME.txt', 'README-ARCHITECTURE.md', 'review-targets.csv', 'bundle-hosts.txt', 'secret-files-masked.txt', 'manifest-lines.txt', 'signing-refs.txt', 'ios-config-lines.txt', 'snippets.txt')
$stamp = Get-Date -Format 'yyyyMMdd-HHmm'
$pub = Join-Path $src ("SHARE-" + $Name + "-" + $stamp)
New-Item -ItemType Directory -Force -Path $pub | Out-Null
$n = 0
foreach ($a in $allow) {
    $f = Join-Path $src $a
    if (Test-Path -LiteralPath $f) { Copy-Item -LiteralPath $f -Destination (Join-Path $pub $a) -Force; $n++ }
}
Write-Host "[OK] $n masked files gathered in $pub"
Write-Host 'Copy this folder to your own machine to hand it over. It is not uploaded anywhere.'
Start-Process explorer.exe -ArgumentList $pub
