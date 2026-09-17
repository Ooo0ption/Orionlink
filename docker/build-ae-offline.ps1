[CmdletBinding()]
param(
    [string]$BaseImage = $(
        if ($env:ORION_BASE_IMAGE) { $env:ORION_BASE_IMAGE }
        else { "orionlink-ae-linux-base:go1.25.1-k6-1.8.0" }
    ),

    [string]$OutputImage = $(
        if ($env:ORION_IMAGE) { $env:ORION_IMAGE }
        else { "orionlink-ae:ndss2027-v2" }
    ),

    [string]$Platform = $env:ORION_PLATFORM
)

$ErrorActionPreference = "Stop"

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

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $ProjectRoot
try {
    & docker image inspect $BaseImage *> $null
    if ($LASTEXITCODE -ne 0) {
        throw @"
missing local base image: $BaseImage
load it first: docker load -i dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar
"@
    }

    $BuildArguments = @("build", "--pull=false", "--network=none")
    if (-not [string]::IsNullOrWhiteSpace($Platform)) {
        $BuildArguments += @("--platform", $Platform)
    }
    $BuildArguments += @(
        "--build-arg", "ORION_BASE_IMAGE=$BaseImage",
        "-f", "Dockerfile.offline",
        "-t", $OutputImage,
        "."
    )

    Invoke-NativeCommand -FilePath docker -ArgumentList $BuildArguments

    Write-Host "offline code image: $OutputImage"
    Invoke-NativeCommand -FilePath docker -ArgumentList @(
        "image", "inspect", $OutputImage,
        "--format", "id={{.Id}} arch={{.Architecture}} size={{.Size}} bytes"
    )
}
finally {
    Pop-Location
}
