<#
.SYNOPSIS
  Create the project's virtual environment on Windows and install GUARDIAN.

.DESCRIPTION
  Picks a 64-bit Python 3.11+ through the py launcher (32-bit Python cannot
  install scikit-learn's wheels), creates .venv, and installs the package with
  the dashboard and development extras.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = $null
foreach ($v in '3.13-64', '3.12-64', '3.11-64') {
    $found = & py "-$v" -c "import sys; print(sys.executable)" 2>$null
    if ($LASTEXITCODE -eq 0 -and $found) { $python = $found.Trim(); break }
}
if (-not $python) {
    Write-Error "Install a 64-bit Python 3.11 or newer from python.org, then run this again."
}

Write-Host "Creating .venv with $python"
& $python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[dashboard,dev]"
Write-Host "Done. Start the dashboard with .\scripts\serve.ps1 -Open"
