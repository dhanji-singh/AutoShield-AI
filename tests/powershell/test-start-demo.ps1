# Self-contained launcher tests: Docker and HTTP calls are mocked, never live.
param([string]$Scenario = 'all')
$ErrorActionPreference = 'Stop'
if ($Scenario -eq 'all') {
    $shellPath = Join-Path $PSHOME 'pwsh'
    if (-not (Test-Path -LiteralPath $shellPath)) {
        $shellPath = Join-Path $PSHOME 'pwsh.exe'
    }
    if (-not (Test-Path -LiteralPath $shellPath)) {
        $shellPath = Join-Path $PSHOME 'powershell.exe'
    }
    foreach ($case in @('start', 'check', 'stop', 'missing-key', 'wrong-engine', 'up-fails', 'config-fails')) {
        & $shellPath -NoProfile -File $PSCommandPath -Scenario $case
        if ($LASTEXITCODE -ne 0) { throw "Launcher test failed: $case" }
    }
    Write-Host '7 launcher tests passed (mocked Docker/HTTP).'
    exit 0
}

$source = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'start-demo.ps1'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('autoshield test ' + [guid]::NewGuid().ToString('N'))
$global:DemoCalls = New-Object System.Collections.ArrayList
$global:DemoScenario = $Scenario
New-Item -ItemType Directory -Path $temporary | Out-Null
Copy-Item -LiteralPath $source -Destination $temporary
foreach ($file in @('compose.yaml', 'compose.fixture.yaml', 'compose.motion.yaml', 'compose.mcp.yaml')) {
    Set-Content -LiteralPath (Join-Path $temporary $file) -Value 'services: {}'
}
Set-Content -LiteralPath (Join-Path $temporary '.env.example') -Value 'ARMORIQ_API_KEY='
if ($Scenario -ne 'check') { Set-Content -LiteralPath (Join-Path $temporary '.env') -Value '# preserved test configuration' }

function global:docker {
    [void]$global:DemoCalls.Add(($args -join '|'))
    $global:LASTEXITCODE = 0
    if ($args[0] -eq 'info') {
        if ($global:DemoScenario -eq 'wrong-engine') { return 'windows' }
        return 'linux'
    }
    if ($args -contains 'version') { return 'Docker Compose test double' }
    if ($args -contains '--help') { return '--wait --wait-timeout' }
    if ($args -contains 'config') {
        if ($global:DemoScenario -eq 'config-fails') { $global:LASTEXITCODE = 1; return }
        $key = 'fake-unit-test-key'
        if ($global:DemoScenario -eq 'missing-key') { $key = '' }
        return (@{services = @{
            backend = @{environment = @{ARMORIQ_API_KEY = $key}}
            'mcp-gateway' = @{environment = @{MCP_ARMORIQ_MODE = 'required'; ARMORIQ_API_KEY = $key}}
        }} | ConvertTo-Json -Depth 6 -Compress)
    }
    if (($args -contains 'up') -and $global:DemoScenario -eq 'up-fails') { $global:LASTEXITCODE = 1 }
}
function global:Invoke-RestMethod {
    param($Uri, $TimeoutSec)
    if ($Uri -like '*/scans/readiness') { return @{prerequisites_ready = $true} }
    if ($Uri -like '*/api/mcp/status') { return @{armoriq_mode = 'required'; armoriq_key_present = $true} }
    return @{status = 'ok'}
}
function global:Invoke-WebRequest {
    param($Uri, $TimeoutSec, [switch]$UseBasicParsing)
    return @{StatusCode = 200}
}

try {
    $global:LASTEXITCODE = 0
    $launcherArgs = @{NonInteractive = $true; NoBrowser = $true; WaitTimeoutSeconds = 30}
    if ($Scenario -eq 'check') { $launcherArgs.CheckOnly = $true }
    if ($Scenario -eq 'stop') { $launcherArgs.Stop = $true }
    & (Join-Path $temporary 'start-demo.ps1') @launcherArgs 2>$null
    $failed = $LASTEXITCODE -ne 0
    $expectedFailure = $Scenario -in @('missing-key', 'wrong-engine', 'up-fails', 'config-fails')
    if ($failed -ne $expectedFailure) { throw "Unexpected exit status: $Scenario" }
    $calls = $global:DemoCalls -join "`n"
    if ($Scenario -eq 'start' -and $calls -notmatch 'up\|-d\|--wait\|--wait-timeout\|30\|--build') { throw 'Startup did not wait for health.' }
    if ($Scenario -in @('check', 'missing-key', 'wrong-engine', 'config-fails') -and $calls -match '\|up\|-d') { throw 'Unexpected container startup.' }
    if ($Scenario -eq 'check' -and (Test-Path -LiteralPath (Join-Path $temporary '.env'))) { throw 'Temporary .env was not removed.' }
    if ($Scenario -eq 'stop' -and ($calls -notmatch '\|down\|--remove-orphans' -or $calls -match '\|(-v|--volumes)')) { throw 'Stop must retain evidence volumes.' }
    if ($calls -match '\|up\|-d' -and $calls -notmatch 'compose.fixture.yaml.*compose.motion.yaml.*compose.mcp.yaml') { throw 'Missing Compose overlays.' }
    Write-Host "PASS: $Scenario"
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
