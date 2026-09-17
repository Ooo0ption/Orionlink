[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [Nullable[int]]$Iterations
)

$ErrorActionPreference = "Stop"

if (-not $PSBoundParameters.ContainsKey("Iterations")) {
    if ($env:ORION_ITERATIONS) {
        $ParsedIterations = 0
        if (-not [int]::TryParse($env:ORION_ITERATIONS, [ref]$ParsedIterations)) {
            throw "ORION_ITERATIONS must be a positive integer"
        }
        $Iterations = $ParsedIterations
    }
    else {
        $Iterations = 100
    }
}
if ($Iterations -lt 1) {
    throw "Usage: .\benchmark\run-e1.ps1 [positive iterations]"
}

function Convert-DurationToMilliseconds {
    param([Parameter(Mandatory = $true)][string]$Duration)

    $MicrosecondsSuffix = ([char]0x00B5) + "s"
    if ($Duration.EndsWith("ms")) {
        return [double]$Duration.Substring(0, $Duration.Length - 2)
    }
    if ($Duration.EndsWith($MicrosecondsSuffix) -or $Duration.EndsWith("us")) {
        return [double]$Duration.Substring(0, $Duration.Length - 2) / 1000
    }
    if ($Duration.EndsWith("ns")) {
        return [double]$Duration.Substring(0, $Duration.Length - 2) / 1000000
    }
    if ($Duration.EndsWith("s")) {
        return [double]$Duration.Substring(0, $Duration.Length - 1) * 1000
    }
    return [double]$Duration
}

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LogPath = if ($env:ORION_E1_LOG) {
    $env:ORION_E1_LOG
}
else {
    Join-Path ([System.IO.Path]::GetTempPath()) "orionlink-e1.log"
}

Push-Location $ProjectRoot
try {
    $env:ORION_ITERATIONS = [string]$Iterations
    Write-Host "log: $LogPath"
    Write-Host "iterations: $Iterations"
    Write-Host ""

    $TestOutput = @(
        & go test -run TestAllPartsLocal -timeout 60m -v ./benchmark/e1/ 2>&1 |
            Tee-Object -FilePath $LogPath |
            ForEach-Object {
                Write-Host $_
                $_
            }
    )
    $TestExitCode = $LASTEXITCODE

    if ($TestExitCode -ne 0) {
        throw "E1 failed with exit code $TestExitCode; see $LogPath"
    }

    $Rows = @()
    $CurrentOperation = $null
    $CurrentStage = $null
    foreach ($Line in $TestOutput) {
        if ($Line -match "^=+ Part [0-9]+: (.+?)(?: \[Table III: (.+?)\])? =+$") {
            $CurrentOperation = $Matches[1]
            $CurrentStage = $Matches[2]
            continue
        }
        if ($Line -match "^Average time: ([^ ]+)") {
            if ($CurrentOperation -and -not $CurrentOperation.StartsWith("Complete Flow")) {
                $Rows += [PSCustomObject]@{
                    Stage = $CurrentStage
                    Operation = $CurrentOperation
                    Milliseconds = Convert-DurationToMilliseconds $Matches[1]
                }
            }
        }
    }

    if ($Rows.Count -ne 6) {
        throw "Expected six E1 measurement rows, found $($Rows.Count); see $LogPath"
    }

    Write-Host ""
    Write-Host ("{0,-15} {1,-23} {2,11}" -f "Stage", "Operation", "measured")
    Write-Host ("{0,-15} {1,-23} {2,11}" -f ("-" * 15), ("-" * 23), ("-" * 11))
    $Total = 0.0
    foreach ($Row in $Rows) {
        $Total += $Row.Milliseconds
        Write-Host ("{0,-15} {1,-23} {2,8:N2} ms" -f `
            $Row.Stage, $Row.Operation, $Row.Milliseconds)
    }
    Write-Host ("{0,-15} {1,-23} {2,11}" -f ("-" * 15), ("-" * 23), ("-" * 11))
    Write-Host ("{0,-15} {1,-23} {2,8:N2} ms" -f "Total", "(sum of rows)", $Total)
}
finally {
    Pop-Location
}
