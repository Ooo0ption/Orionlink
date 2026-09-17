[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("set-egress", "clear", "status")]
    [string]$Action,

    [Parameter(Position = 1)]
    [string]$Delay,

    [Parameter(Position = 2)]
    [string]$Jitter
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

if ($Action -eq "set-egress" -and [string]::IsNullOrWhiteSpace($Delay)) {
    throw "Usage: .\netem-compose.ps1 set-egress DELAY [JITTER]"
}
if ($Action -ne "set-egress" -and ($Delay -or $Jitter)) {
    throw "Usage: .\netem-compose.ps1 clear | status"
}

$ProjectRoot = $PSScriptRoot
$ComposeFile = if ($env:ORION_COMPOSE_FILE) {
    $env:ORION_COMPOSE_FILE
}
else {
    "docker-compose.yml"
}
$Services = @("tca", "idp", "broker", "rp")

Push-Location $ProjectRoot
try {
    foreach ($Service in $Services) {
        if ($Action -eq "status") {
            Write-Host "===== $Service ====="
        }

        $Arguments = @(
            "compose", "-f", $ComposeFile,
            "exec", "-T", $Service,
            "orion-netem", $Action
        )
        if ($Action -eq "set-egress") {
            $Arguments += $Delay
            if (-not [string]::IsNullOrWhiteSpace($Jitter)) {
                $Arguments += $Jitter
            }
        }

        Invoke-NativeCommand -FilePath docker -ArgumentList $Arguments
    }
}
finally {
    Pop-Location
}
