$ErrorActionPreference = "Stop"

$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
$Python = if (Test-Path $VenvPython) { $VenvPython } else { "python" }

Push-Location $ProjectRoot
try {
    Write-Host "1. Running Django system checks..."
    & $Python manage.py check

    Write-Host "2. Checking for missing migrations..."
    & $Python manage.py makemigrations --check --dry-run

    Write-Host "3. Running automated tests..."
    & $Python manage.py test

    Write-Host "4. Running baseline empirical evaluation..."
    & $Python manage.py evaluate_netaudit `
        --manifest evaluation/manifest.json `
        --output evaluation/results

    Write-Host "5. Checking the local SQLite database..."
    & $Python manage.py migrate --check

    Write-Host ""
    Write-Host "NetAudit local validation completed successfully."
    Write-Host "Start the application with: $Python manage.py runserver"
    Write-Host "Open: http://127.0.0.1:8000/"
}
finally {
    Pop-Location
}