param(
    [string]$ExeUrl,
    [string]$InstallerUrl,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'generated')
)
$ErrorActionPreference = 'Stop'
function RequireHttps([string]$Value) {
    $uri = $null
    if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https') {
        throw 'Enter an absolute HTTPS direct-download URL.'
    }
}
if (-not $ExeUrl) { $ExeUrl = Read-Host 'Direct HTTPS URL for streamer+.exe' }
if (-not $InstallerUrl) { $InstallerUrl = Read-Host 'Planned direct HTTPS URL for Install.ps1' }
RequireHttps $ExeUrl
RequireHttps $InstallerUrl
$template = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install.template.ps1') -Raw -Encoding UTF8
$installer = $template.Replace('__EXE_URL__', $ExeUrl.Replace("'", "''"))
$quotedUrl = $InstallerUrl.Replace("'", "''")
$command = '& { $wc = New-Object System.Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; try { $script = $wc.DownloadString(''' + $quotedUrl + ''') } finally { $wc.Dispose() }; iex $script }'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$utf8 = New-Object System.Text.UTF8Encoding($true)
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'Install.ps1'), $installer, $utf8)
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'command.txt'), $command, $utf8)
Write-Host "Created Install.ps1 and command.txt in $OutputDirectory"
Write-Host 'Upload the EXE and Install.ps1 to the specified URLs before using the command.'
Write-Output $command
