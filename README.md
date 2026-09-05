# Streamer

Download `streamer+.exe` from [Releases](https://github.com/helpjejaeiei-alt/Streamer/releases).

## PowerShell installation

```powershell
& { $wc = New-Object System.Net.WebClient; $wc.Encoding = [System.Text.Encoding]::UTF8; try { $script = $wc.DownloadString('https://raw.githubusercontent.com/helpjejaeiei-alt/Streamer/main/Install.ps1') } finally { $wc.Dispose() }; iex $script }
```

The installer downloads the supplied EXE, verifies SHA-256, and copies it to a versioned directory under `%LOCALAPPDATA%\Programs\StreamerPlus`. It does not launch the program automatically. Open the path printed after installation to run it.

SHA-256: `B24D81C0C7FD9366B94303460804DB5A40340EF16B8FC80FA8A4AC18329E5F6D`

This release contains the supplied EXE only. Runtime behavior and any companion-file requirements have not been verified.

`Generate.ps1` and `Install.template.ps1` generate a UTF-8 installer and command for alternative hosting URLs. The template is pinned to the above EXE hash.