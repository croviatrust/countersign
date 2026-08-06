# Countersign dev install (Windows PowerShell)
# Usage: .\install.ps1
$ErrorActionPreference = "Stop"
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Write-Host ""
Write-Host "Installed. Try:"
Write-Host "  countersign init --log .\witness-log"
Write-Host "  python examples\demo.py"
Write-Host "  pytest -q"
