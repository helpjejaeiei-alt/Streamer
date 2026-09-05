param([Parameter(Mandatory=$true)][string]$Api,[Parameter(Mandatory=$true)][string]$Token,[Parameter(Mandatory=$true)][string]$ExpectedSid)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    if (([Uri]$Api).Scheme -ne 'https' -or $Token -notmatch '^[a-f0-9]{64}$') { throw 'Invalid installation request' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($identity.User.Value -ne $ExpectedSid) { throw 'UAC must use the same Windows account' }
    Write-Host 'Verifying installation...'
    $info = Invoke-RestMethod -Method Post -Uri ($Api + '/redeem') -ContentType 'application/json' -Body (@{token=$Token}|ConvertTo-Json -Compress)
    if ($info.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or [string]::IsNullOrWhiteSpace($info.license)) { throw 'Invalid installer response' }
    $root = Join-Path $env:LOCALAPPDATA 'Programs\StreamerPlus'
    $destination = Join-Path $root $info.sha256.Substring(0,12)
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    $target = Join-Path $destination 'streamer+.exe'
    $temp = Join-Path $destination ([Guid]::NewGuid().ToString('N') + '.download')
    Write-Host 'Installing streamer+...'
    try {
        Invoke-WebRequest -UseBasicParsing -Method Post -Uri ($Api + '/download') -ContentType 'application/json' -Body (@{token=$info.downloadToken}|ConvertTo-Json -Compress) -OutFile $temp
        if ((Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash -ne $info.sha256) { throw 'Installer verification failed' }
        if (Test-Path -LiteralPath $target) {
            if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $info.sha256) { throw 'Existing file does not match' }
        } else { [IO.File]::Move($temp,$target) }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
    Add-Type -AssemblyName System.Security
    $licenseBytes = [Text.Encoding]::UTF8.GetBytes([string]$info.license)
    try {
        $protected = [Security.Cryptography.ProtectedData]::Protect($licenseBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser)
        [IO.File]::WriteAllBytes((Join-Path $root 'license.dpapi'),$protected)
    } finally { [Array]::Clear($licenseBytes,0,$licenseBytes.Length); $info.license = $null }
    Start-Process -FilePath $target -WorkingDirectory $destination
    Write-Host 'Installed. Starting streamer+...'
} catch {
    Write-Host 'Installation could not finish. Contact support for a new installation command.' -ForegroundColor Red
    exit 1
}
