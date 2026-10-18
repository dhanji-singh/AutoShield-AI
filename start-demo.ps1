#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$CheckOnly,
    [switch]$Stop,
    [switch]$NoBuild,
    [switch]$NoBrowser,
    [switch]$NonInteractive,
    [ValidateRange(30, 3600)][int]$WaitTimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = $PSScriptRoot
$EnvFile = Join-Path $ProjectRoot '.env'
$ComposeArgs = @('compose', '--project-directory', $ProjectRoot, '--env-file', $EnvFile)
foreach ($name in @('compose.yaml', 'compose.fixture.yaml', 'compose.motion.yaml', 'compose.mcp.yaml')) {
    $file = Join-Path $ProjectRoot $name
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing Compose file: $name" }
    $ComposeArgs += @('-f', $file)
}

function Invoke-Compose {
    param([string[]]$Arguments, [switch]$Capture)
    if ($Capture) {
        # Effective config can contain keys. Keep it in memory and off the terminal.
        $result = & docker @ComposeArgs @Arguments 2>$null
        if ($LASTEXITCODE -ne 0) { throw 'Compose configuration failed. Check your local .env syntax and Compose files.' }
        return ($result -join "`n")
    }
    & docker @ComposeArgs @Arguments
    if ($LASTEXITCODE -ne 0) { throw 'Docker Compose failed. Inspect service status and logs using the commands in docs/SETUP.md.' }
}

function Get-DemoConfig {
    $raw = Invoke-Compose -Arguments @('config', '--format', 'json') -Capture
    return ($raw | ConvertFrom-Json)
}

function Test-ConfiguredKey {
    param($Value)
    $text = [string]$Value
    return (-not [string]::IsNullOrWhiteSpace($text) -and $text -notmatch '^(your[-_]|replace[-_]|<)')
}

Push-Location -LiteralPath $ProjectRoot
try {
    if ($CheckOnly -and $Stop) { throw 'Choose either -CheckOnly or -Stop.' }
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Install Docker Desktop with Docker Compose, then start Docker Desktop.' }
    & docker compose version
    if ($LASTEXITCODE -ne 0) { throw 'Docker Compose is unavailable. Install/update Docker Desktop.' }

    if (-not (Test-Path -LiteralPath $EnvFile)) {
        if ($CheckOnly) {
            # Validate with placeholders without creating .env or prompting for secrets.
            # The base service env_file path needs .env to exist, so create a temporary
            # copy for this check and remove it in finally.
            Copy-Item -LiteralPath (Join-Path $ProjectRoot '.env.example') -Destination $EnvFile
            $RemoveTemporaryEnv = $true
        } elseif ($Stop) {
            throw 'No .env exists for this deployment.'
        } else {
            Copy-Item -LiteralPath (Join-Path $ProjectRoot '.env.example') -Destination $EnvFile
            Write-Host 'Created .env from the blank template. Existing configuration is never overwritten.'
        }
    }

    $config = Get-DemoConfig
    if ($Stop) {
        Invoke-Compose -Arguments @('down', '--remove-orphans')
        Write-Host 'Demo stopped. Evidence volumes were retained.'
        return
    }

    if ($CheckOnly) {
        Write-Host 'All four Compose files merged and validated successfully.'
        if (-not (Test-ConfiguredKey $config.services.backend.environment.ARMORIQ_API_KEY)) {
            Write-Warning 'ArmorIQ key is missing. Real scanning will block until configured.'
        }
        Write-Host 'Configuration check only: no containers, cloud decisions or target requests were started.'
        return
    }

    $engine = (& docker info --format '{{.OSType}}' 2>$null) -join ''
    if ($LASTEXITCODE -ne 0) { throw 'Docker Engine is unavailable. Start Docker Desktop and retry.' }
    if ($engine.Trim() -ne 'linux') { throw 'Switch Docker Desktop to Linux containers and retry.' }

    if (-not (Test-ConfiguredKey $config.services.backend.environment.ARMORIQ_API_KEY)) {
        if ($NonInteractive) { throw 'Set ARMORIQ_API_KEY in .env before using -NonInteractive.' }
        $secure = Read-Host 'ArmorIQ API key (hidden; saved only to your local .env)' -AsSecureString
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try {
            $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
            if (-not (Test-ConfiguredKey $plain) -or $plain -match "[\r\n'\x00]") { throw 'API key is empty or contains unsupported characters.' }
            [IO.File]::AppendAllText($EnvFile, "`nARMORIQ_API_KEY='$plain'`n", (New-Object Text.UTF8Encoding($false)))
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
            $plain = $null
            $secure = $null
        }
        $config = Get-DemoConfig
    }
    if ($config.services.'mcp-gateway'.environment.MCP_ARMORIQ_MODE -ne 'required') {
        throw 'The enforced demo requires MCP_ARMORIQ_MODE=required. Update .env (and any overriding shell variable).'
    }
    if (-not (Test-ConfiguredKey $config.services.'mcp-gateway'.environment.ARMORIQ_API_KEY)) {
        throw 'The MCP gateway ArmorIQ key is missing; check .env and shell overrides.'
    }

    $upHelp = (& docker compose up --help) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $upHelp -notmatch '--wait-timeout') { throw 'Update Docker Compose: this launcher needs up --wait and --wait-timeout.' }
    $up = @('up', '-d', '--wait', '--wait-timeout', [string]$WaitTimeoutSeconds)
    if (-not $NoBuild) { $up += '--build' }
    Invoke-Compose -Arguments $up
    Invoke-Compose -Arguments @('ps')

    $null = Invoke-RestMethod -Uri 'http://127.0.0.1:8010/health' -TimeoutSec 10
    $null = Invoke-WebRequest -Uri 'http://127.0.0.1:8502/' -UseBasicParsing -TimeoutSec 10
    $null = Invoke-WebRequest -Uri 'http://127.0.0.1:8090/health' -UseBasicParsing -TimeoutSec 10
    $ready = Invoke-RestMethod -Uri 'http://127.0.0.1:8010/scans/readiness' -TimeoutSec 10
    if (-not $ready.prerequisites_ready) { throw 'Containers started but scanner prerequisites are not ready. Inspect Session readiness.' }
    $gateway = Invoke-RestMethod -Uri 'http://127.0.0.1:8502/api/mcp/status' -TimeoutSec 10
    if ($gateway.armoriq_mode -ne 'required' -or -not $gateway.armoriq_key_present) { throw 'DevOps MCP lab is not configured for required ArmorIQ enforcement.' }
    Write-Host 'Ready: React http://localhost:8502 | Streamlit scanner http://127.0.0.1:8501'
    Write-Host 'Scanner target inside Docker: http://fixture-lab:8090/'
    Write-Host 'Cloud ALLOW/BLOCK has not been tested by startup. Each target request still needs an actual policy decision.'
    if (-not $NoBrowser) { Start-Process 'http://localhost:8502' }
} catch {
    Write-Error ("AutoShield setup failed: " + $_.Exception.Message) -ErrorAction Continue
    exit 1
} finally {
    if ($RemoveTemporaryEnv) { Remove-Item -LiteralPath $EnvFile -Force }
    Pop-Location
}
