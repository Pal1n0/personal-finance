# --------------------------------------------
# Windows PowerShell script: setup_dev.ps1
# Safe development setup script for GitHub
# --------------------------------------------

# --- 1️⃣ Project root and .env file ---
$projectRoot = Join-Path $PSScriptRoot ".."
$envFile = Join-Path $projectRoot ".env"

if (-Not (Test-Path $envFile)) {
    Write-Host ".env file not found! Please create one based on .env.example with your local credentials."
    exit 1
}

# --- Load environment variables from .env ---
Get-Content $envFile | ForEach-Object {
    if ($_ -match "=") {
        $parts = $_ -split "=", 2
        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        [System.Environment]::SetEnvironmentVariable($key, $value)
    }
}

# Assign env variables for convenience
$POSTGRES_DB = $env:POSTGRES_DB
$POSTGRES_USER = $env:POSTGRES_USER
$POSTGRES_PASSWORD = $env:POSTGRES_PASSWORD
$SECRET_KEY = $env:SECRET_KEY

# --- 2️⃣ Setup backend: Conda environment ---
$backendPath = Join-Path $projectRoot "backend"
Write-Host "`nSetting up backend Conda environment..."
conda create -y -n backend python=3.12
conda activate backend
Set-Location $backendPath
pip install -r requirements.txt

# --- 3️⃣ Setup frontend: Node environment ---
$frontendPath = Join-Path $projectRoot "frontend"
Write-Host "`nSetting up frontend Node environment..."
Set-Location $frontendPath
nvm use 22
npm install

# --- 4️⃣ PostgreSQL: Docker container ---
Write-Host "`nStarting PostgreSQL container (existing container will be used if present)..."
$pgContainerName = "pg_dev"
$existingContainer = docker ps -a --format "{{.Names}}" | Select-String $pgContainerName

if (-not $existingContainer) {
    Write-Host "PostgreSQL container not found. Creating new container with credentials from .env..."
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

# --- 5️⃣ Ensure the database exists ---
Write-Host "`nEnsuring PostgreSQL database exists..."
$exists = docker exec -i $pgContainerName psql -U $POSTGRES_USER -tc "SELECT 1 FROM pg_database WHERE datname='$POSTGRES_DB';" | ForEach-Object { $_.Trim() }

if ($exists -ne "1") {
    Write-Host "Database $POSTGRES_DB does not exist. Creating..."
    docker exec -i $pgContainerName psql -U $POSTGRES_USER -c "CREATE DATABASE $POSTGRES_DB;"
} else {
    Write-Host "Database $POSTGRES_DB already exists."
}

# --- 6️⃣ Django: apply migrations ---
Write-Host "`nApplying Django migrations..."
Set-Location $backendPath
python manage.py migrate

Write-Host "`n✅ Dev environment setup complete!"
Write-Host "Backend: $backendPath"
Write-Host "Frontend: $frontendPath"
Write-Host "PostgreSQL: localhost:5432 (user: $POSTGRES_USER, database: $POSTGRES_DB)"
Write-Host "Make sure your .env file contains the correct credentials for your local setup."
