<#
.SYNOPSIS
  Start the GUARDIAN dashboard on Windows.

.DESCRIPTION
  Uses the project's virtual environment when it works. A venv only stores the
  path of the Python it was made from; if that interpreter is not visible from
  this shell (for example a venv created inside a sandboxed app), the script
  falls back to any 64-bit Python 3.11+ on the machine and borrows the venv's
  installed packages.

.EXAMPLE
  .\scripts\serve.ps1
  .\scripts\serve.ps1 -Port 8050 -LearnHours 48 -Open
#>
param(
    [int]$Port = 8000,
    [double]$LearnHours = 36,
    [double]$Speed = 20,
    [switch]$Open
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Test-Python([string]$exe) {
    if (-not $exe -or -not (Test-Path $exe)) { return $false }
    # A broken venv launcher writes to stderr; Windows PowerShell 5.1 would turn
    # that into a terminating error under 'Stop', so probe with errors allowed.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $exe -c "import sys; sys.exit(0 if sys.maxsize > 2**32 and sys.version_info >= (3, 11) else 1)" 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $previous
    }
}

$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Python $python)) {
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $ErrorActionPreference = 'Continue'
        foreach ($v in '3.13', '3.12', '3.11') {
            $found = & py "-$v" -c "import sys; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $found) { $candidates += "$found".Trim() }
        }
        $ErrorActionPreference = 'Stop'
    }
    $candidates += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python31*\python.exe" -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName }
    $python = $candidates | Where-Object { Test-Python $_ } | Select-Object -First 1
    if (-not $python) {
        Write-Error "No 64-bit Python 3.11+ found. Run .\scripts\setup.ps1 first."
    }
    $site = Join-Path $root '.venv\Lib\site-packages'
    if (-not (Test-Path $site)) {
        Write-Error "No installed packages in .venv. Run .\scripts\setup.ps1 first."
    }
    $env:PYTHONPATH = "$root\src;$site"
    Write-Host "Using $python with the packages from .venv"
}

if ($Open) {
    Start-Job -ScriptBlock {
        param($url)
        Start-Sleep -Seconds 2
        Start-Process $url
    } -ArgumentList "http://127.0.0.1:$Port" | Out-Null
}

& $python -m guardian serve --port $Port --learn-hours $LearnHours --speed $Speed
