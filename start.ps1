# MiTH Terminal — Windows PowerShell 1-command launcher
# Author: MiTH | License: MIT
$ErrorActionPreference = "Stop"

# Ensure UTF-8 console encoding so Unicode QR half-blocks render cleanly
[Console]::InputEncoding  = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding           = [System.Text.Encoding]::UTF8
$env:PYTHONUTF8           = "1"
$env:PYTHONIOENCODING     = "utf-8"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ServerPath = Join-Path (Join-Path $ScriptDir "daemon") "server.py"

$PyExe        = $null
$PyPrefixArgs = @()

$Candidates = @()
if ($env:PYTHON_BIN) {
    $Candidates += ,@($env:PYTHON_BIN)
}
$Candidates += ,@( "python" )
$Candidates += ,@( "py", "-3" )
$Candidates += ,@( "python3" )

foreach ($Entry in $Candidates) {
    $CmdName = $Entry[0]
    $CmdArgs = if ($Entry.Length -gt 1) { $Entry[1..($Entry.Length - 1)] } else { @() }
    $Resolved = Get-Command $CmdName -ErrorAction SilentlyContinue
    if ($null -ne $Resolved) {
        try {
            & $CmdName @CmdArgs -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) {
                $PyExe        = $CmdName
                $PyPrefixArgs = $CmdArgs
                break
            }
        } catch {
            continue
        }
    }
}

if ($null -eq $PyExe) {
    Write-Host "MiTH Terminal requires Python 3.10 or newer — install via 'winget install Python.Python.3.12' or https://www.python.org/downloads/ and re-run .\start.ps1." -ForegroundColor Red
    exit 1
}

& $PyExe @PyPrefixArgs $ServerPath @args
exit $LASTEXITCODE
