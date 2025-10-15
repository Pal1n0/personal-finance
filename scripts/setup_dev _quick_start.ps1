# --------------------------------------------
# Windows PowerShell script: quick_start.ps1
# Quick start for an existing dev environment with PostgreSQL Docker
# --------------------------------------------

# --- Load .env variables ---
$envFile = "$PSScriptRoot\.env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "=") {
            $parts = $_ -split "="
            [System.Environment]::SetEnvironmentVariable($parts[0], $parts[1])
        }
    }
}

$POSTGRES_DB = $env:POSTGRES_DB
$POSTGRES_USER = $env:POSTGRES_USER
$POSTGRES_PASSWORD = $env:POSTGRES_PASSWORD

# --- 1️⃣ Start PostgreSQL Docker container ---
$pgContainerName = "pg_dev"
$existingContainer = docker ps -a --format "{{.Names}}" | Select-String $pgContainerName

if (-not $existingContainer) {
    Write-Host "PostgreSQL container not found. Creating new container..."
    docker run --name $pgContainerName `
        -e POSTGRES_DB=$POSTGRES_DB `
        -e POSTGRES_USER=$POSTGRES_USER `
        -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD `
        -p 5432:5432 `
        -v pg_dev_data:/var/lib/postgresql/data `
        -d postgres:16
} else {
    Write-Host "PostgreSQL container found. Starting it..."
    docker start $pgContainerName 2>$null | Out-Null
}

# Paths relative to the script
$backendPath = Join-Path $PSScriptRoot "..\backend"
$frontendPath = Join-Path $PSScriptRoot "..\frontend"

# ---2️⃣ Apply Django migrations in source terminal (optional) ---
Write-Host "`nActivating backend environment and applying migrations..."
conda activate backend
Set-Location $backendPath
python manage.py migrate

# --- 3️⃣ Open Django server in new terminal ---
Write-Host "`nOpening Django server in new terminal..."
Start-Process powershell -ArgumentList '-NoExit', "-Command & {cd '$backendPath'; conda activate backend; python manage.py runserver}"

Set-Location $frontendPath


# --- 4️⃣ Open frontend dev server in new terminal ---
Write-Host "`nOpening frontend dev server in new terminal..."
Start-Process powershell -ArgumentList '-NoExit', "-Command & {cd '$frontendPath'; nvm use 22; npm run dev}"

# --- 5️⃣ Keep original terminal in source folder ---
Set-Location "$PSScriptRoot\.."
Write-Host "`n✅ Quick start complete! Two terminals opened: one for Django, one for frontend."
Write-Host "PostgreSQL container is running. Original terminal remains here."

Write-Host "nPress Enter to exit script and keep terminals open..." 
Read-Host

