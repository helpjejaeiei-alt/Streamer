& {
    $ErrorActionPreference = 'Stop'
    $url = '__EXE_URL__'
    $expectedHash = 'B24D81C0C7FD9366B94303460804DB5A40340EF16B8FC80FA8A4AC18329E5F6D'
    $destination = Join-Path $env:LOCALAPPDATA ('Programs\StreamerPlus\' + $expectedHash.Substring(0, 12))
    $target = Join-Path $destination 'streamer+.exe'
    $temporaryFile = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString() + '.exe')
    try {
        if (Test-Path -LiteralPath $target) {
            if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $expectedHash) {
                throw 'An unexpected file exists at the install location. No files were overwritten.'
            }
            Write-Host "Already installed: $target"
            return
        }
        Write-Host 'Downloading streamer+.exe...'
        $client = New-Object System.Net.WebClient
        try { $client.DownloadFile($url, $temporaryFile) } finally { $client.Dispose() }
        if ((Get-FileHash -LiteralPath $temporaryFile -Algorithm SHA256).Hash -ne $expectedHash) {
            throw 'SHA-256 mismatch. Installation stopped.'
        }
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        [IO.File]::Move($temporaryFile, $target)
        Write-Host "Installed: $target"
        Write-Host 'Open this EXE to start the application.'
    } finally {
        if (Test-Path -LiteralPath $temporaryFile) {
            Remove-Item -LiteralPath $temporaryFile -Force
        }
    }
}
