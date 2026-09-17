[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Output = "dist/orionlink-ae-linux-base-go1.25.1-k6-1.8.0.tar",

    [string]$BaseImage = $(
        if ($env:ORION_BASE_IMAGE) { $env:ORION_BASE_IMAGE }
        else { "orionlink-ae-linux-base:go1.25.1-k6-1.8.0" }
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
    if ([string]::IsNullOrWhiteSpace($Platform)) {
        Invoke-NativeCommand -FilePath docker -ArgumentList @(
            "build", "-f", "Dockerfile.base", "-t", $BaseImage, "."
        )
    }
    else {
        Invoke-NativeCommand -FilePath docker -ArgumentList @(
            "buildx", "build", "--platform", $Platform, "--load",
            "-f", "Dockerfile.base", "-t", $BaseImage, "."
        )
    }

    $OutputDirectory = Split-Path -Parent $Output
    if ($OutputDirectory) {
        New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    }

    Invoke-NativeCommand -FilePath docker -ArgumentList @(
        "image", "save", "-o", $Output, $BaseImage
    )

    Write-Host "base image: $BaseImage"
    Invoke-NativeCommand -FilePath docker -ArgumentList @(
        "image", "inspect", $BaseImage,
        "--format", "id={{.Id}} arch={{.Architecture}} size={{.Size}} bytes"
    )
    Write-Host "archive: $Output"

    $Hash = (Get-FileHash -Algorithm SHA256 -Path $Output).Hash.ToLowerInvariant()
    $ChecksumPath = "${Output}.sha256"
    $ChecksumFullPath = if ([System.IO.Path]::IsPathRooted($ChecksumPath)) {
        $ChecksumPath
    }
    else {
        Join-Path $ProjectRoot $ChecksumPath
    }
    $ChecksumLine = "${Hash}  ${Output}`n"
    [System.IO.File]::WriteAllText(
        $ChecksumFullPath,
        $ChecksumLine,
        [System.Text.Encoding]::ASCII
    )
    Write-Host $ChecksumLine.TrimEnd()
    Write-Host ""
    Write-Host "Offline machine: docker load -i $Output"
}
finally {
    Pop-Location
}
