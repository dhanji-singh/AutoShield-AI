param([Parameter(Mandatory=$true)][string]$ProjectPath)
$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path -Parent $PSScriptRoot
$destinationRoot = (Resolve-Path -LiteralPath $ProjectPath).Path
if (-not (Test-Path -LiteralPath (Join-Path $destinationRoot 'compose.yaml'))) {
    throw 'Select the existing project directory containing compose.yaml and .env.'
}
if ($destinationRoot -eq $sourceRoot) {
    throw 'Extract the update separately, then point ProjectPath at your existing project.'
}
$manifest = Get-Content -LiteralPath (Join-Path $sourceRoot 'docs/manifests/SCANNER_GATEWAY_UPDATE.json') -Raw | ConvertFrom-Json
$backup = Join-Path $destinationRoot ('scanner-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
foreach ($relative in $manifest.files) {
    if ($relative -match '(^|[\\/])\.\.([\\/]|$)' -or [IO.Path]::IsPathRooted($relative) -or [IO.Path]::GetFileName($relative) -eq '.env') {
        throw 'Invalid update manifest path.'
    }
    $source = Join-Path $sourceRoot $relative
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Missing update file: $relative" }
}
foreach ($move in $manifest.relocations) {
    if ($move.from -match '(^|[\\/])\.\.([\\/]|$)' -or [IO.Path]::IsPathRooted($move.from) -or [IO.Path]::GetFileName($move.from) -eq '.env') {
        throw 'Invalid relocation path.'
    }
    # The destination must be one of the validated source files above.
    if ($manifest.files -notcontains $move.to -and $move.to -ne 'docs/manifests/SCANNER_GATEWAY_UPDATE.json') {
        throw 'Relocation destination is missing from the update.'
    }
}
# Back up existing versions before replacing any file. Never read or copy .env.
foreach ($relative in $manifest.files) {
    $destination = Join-Path $destinationRoot $relative
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        $saved = Join-Path $backup $relative
        New-Item -ItemType Directory -Force -Path (Split-Path $saved -Parent) | Out-Null
        Copy-Item -LiteralPath $destination -Destination $saved
    }
}
foreach ($move in $manifest.relocations) {
    $old = Join-Path $destinationRoot $move.from
    if (Test-Path -LiteralPath $old -PathType Leaf) {
        $saved = Join-Path $backup $move.from
        New-Item -ItemType Directory -Force -Path (Split-Path $saved -Parent) | Out-Null
        Copy-Item -LiteralPath $old -Destination $saved
    }
}
foreach ($relative in $manifest.files) {
    $destination = Join-Path $destinationRoot $relative
    New-Item -ItemType Directory -Force -Path (Split-Path $destination -Parent) | Out-Null
    Copy-Item -LiteralPath (Join-Path $sourceRoot $relative) -Destination $destination -Force
}
Copy-Item -LiteralPath (Join-Path $sourceRoot 'docs/manifests/SCANNER_GATEWAY_UPDATE.json') -Destination (Join-Path $destinationRoot 'docs/manifests/SCANNER_GATEWAY_UPDATE.json') -Force
# Remove old locations only after every new file has been copied and backed up.
foreach ($move in $manifest.relocations) {
    $old = Join-Path $destinationRoot $move.from
    if (Test-Path -LiteralPath $old -PathType Leaf) { Remove-Item -LiteralPath $old }
}
Write-Host "Updated $($manifest.files.Count) files. Existing .env and compose settings preserved."
Write-Host "Backup: $backup"
Write-Host 'Read docs/PUBLIC_SCANNER_MCP.md, configure the matching ArmorIQ scanner policy, then rebuild Docker services.'
