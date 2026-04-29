# Run DARKSPACE Gray Swan Safeguards adapter locally (repo root).
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
Set-Location $root

$venv = Join-Path $root "safeguards_adapter\.venv"
if (-not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
    python -m venv $venv
}
& (Join-Path $venv "Scripts\python.exe") -m pip install -q -r (Join-Path $root "safeguards_adapter\requirements.txt")

$env:PYTHONPATH = $root
& (Join-Path $venv "Scripts\python.exe") -m uvicorn safeguards_adapter.api:app --host 0.0.0.0 --port 8080
