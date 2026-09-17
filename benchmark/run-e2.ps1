[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [Nullable[int]]$Iterations
)

$ErrorActionPreference = "Stop"

if (-not $PSBoundParameters.ContainsKey("Iterations")) {
    if ($env:ORION_PERF_ITERATIONS) {
        $ParsedIterations = 0
        if (-not [int]::TryParse($env:ORION_PERF_ITERATIONS, [ref]$ParsedIterations)) {
            throw "ORION_PERF_ITERATIONS must be a positive integer"
        }
        $Iterations = $ParsedIterations
    }
    else {
        $Iterations = 10
    }
}
if ($Iterations -lt 1) {
    throw "Usage: .\benchmark\run-e2.ps1 [positive iterations]"
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$ArgumentList
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($ArgumentList -join ' ')"
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "===== $Title ====="
}

function Test-IdpAvailable {
    $IdpUrl = if ($env:ORION_IDP_URL) { $env:ORION_IDP_URL.TrimEnd('/') } else { "http://localhost:3000" }
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 `
            -Uri "$IdpUrl/ssso/pubkeys" | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-PythonSummary {
    if (Get-Command python3 -ErrorAction SilentlyContinue) {
        Invoke-NativeCommand -FilePath python3 -ArgumentList @(
            "./benchmark/e2/summarize.py"
        )
        return
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        Invoke-NativeCommand -FilePath python -ArgumentList @(
            "./benchmark/e2/summarize.py"
        )
        return
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        Invoke-NativeCommand -FilePath py -ArgumentList @(
            "-3", "./benchmark/e2/summarize.py"
        )
        return
    }
    throw "Python 3 is required to render the consolidated E2 table"
}

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $ProjectRoot
try {
    if (-not (Test-IdpAvailable)) {
        throw "The live stack is unavailable; all E2 rows require the browser/container path."
    }

    Write-Section "E2 - live browser/container paths ($Iterations iterations)"
    $env:ORION_PERF_ITERATIONS = [string]$Iterations
    Push-Location ./benchmark/e2/browser
    try {
        Invoke-NativeCommand -FilePath npm -ArgumentList @("run", "perf")
    }
    finally {
        Pop-Location
    }

    Write-Section "Table IV"
    Invoke-PythonSummary
    Write-Host ""
    Write-Host "reports: benchmark/results/"
}
finally {
    Pop-Location
}
