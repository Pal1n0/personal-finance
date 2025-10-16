# --------------------------------------------
# Windows PowerShell script: quick_start.ps1
# Quick start for an existing dev environment with PostgreSQL Docker
# and local start of server backend and frontend
# --------------------------------------------

# --- Load .env variables ---
$projectRoot = Join-Path $PSScriptRoot ".."
$envFile = Join-Path $projectRoot ".env"

if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "=") {
            $parts = $_ -split "=", 2
            $key = $parts[0].Trim()
            $value = $parts[1].Trim()
            [System.Environment]::SetEnvironmentVariable($key, $value)
        }
    }
}

# Paths relative to the script
$backendPath = Join-Path $projectRoot "backend"
$frontendPath = Join-Path $projectRoot "frontend"

# --- 1️⃣ Start PostgreSQL container via Docker Compose ---
Set-Location $projectRoot
Write-Host "Starting PostgreSQL container via Docker Compose..."
docker compose up -d db

# --- 2️⃣ Apply Django migrations locally ---
Set-Location $backendPath
conda activate backend
python manage.py migrate

# --- 3️⃣ Open Django server in new terminal ---
Write-Host "`nOpening Django server in new terminal..."
Start-Process powershell -ArgumentList '-NoExit', "-Command & {cd '$backendPath'; conda activate backend; python manage.py runserver}"

# --- 4️⃣ Open frontend dev server in new terminal ---
Set-Location $frontendPath
Write-Host "`nOpening frontend dev server in new terminal..."
Start-Process powershell -ArgumentList '-NoExit', "-Command & {cd '$frontendPath'; nvm use 22; npm run dev}"

# --- 5️⃣ Keep original terminal in source folder ---
Set-Location $projectRoot
Write-Host "`n✅ Quick start complete! Two terminals opened: one for Django, one for frontend."
Write-Host "PostgreSQL container is running. Original terminal remains here."

Write-Host "`nPress Enter to exit script and keep terminals open..."
Read-Host
