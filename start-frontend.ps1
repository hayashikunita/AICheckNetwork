# Frontend Server Start Script

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Network Diagnostic Tool - Starting Frontend" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Starting frontend server..." -ForegroundColor Green
Write-Host "Server will start at http://localhost:3000" -ForegroundColor Cyan
Write-Host "Browser will open automatically" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

# Move to frontend directory
$frontendPath = Join-Path $PSScriptRoot "frontend"
Set-Location -Path $frontendPath

# Suppress deprecation warnings
$env:NODE_OPTIONS = "--no-deprecation"

# Start development server
# Ensure HOST and related vars are set in this session to avoid webpack-dev-server schema errors
# (Use explicit checks; PowerShell's -or returns boolean, so avoid using it for value selection)
if (-not $env:HOST -or $env:HOST -eq '') {
	$env:HOST = '127.0.0.1'
}
# Do not set ALLOWED_HOSTS here to avoid passing invalid values to webpack-dev-server
if (-not $env:WDS_SOCKET_HOST -or $env:WDS_SOCKET_HOST -eq '') {
	$env:WDS_SOCKET_HOST = $env:HOST
}

# Force HOST/ALLOWED_HOSTS to valid string values to avoid previous boolean/empty issues
$env:HOST = '127.0.0.1'
if (-not $env:WDS_SOCKET_HOST -or $env:WDS_SOCKET_HOST -eq '') {
	$env:WDS_SOCKET_HOST = $env:HOST
}

# Ensure ALLOWED_HOSTS is explicitly set to a valid value or removed
if (-not $env:ALLOWED_HOSTS -or $env:ALLOWED_HOSTS -eq '') {
    $env:ALLOWED_HOSTS = '127.0.0.1'  # Set a default valid value
}

# Keep ALLOWED_HOSTS set to a valid value; do not remove it (removing caused empty value issues)

Write-Host "[start-frontend] ENV HOST=$env:HOST ALLOWED_HOSTS=$env:ALLOWED_HOSTS WDS_SOCKET_HOST=$env:WDS_SOCKET_HOST" -ForegroundColor Yellow

npm start
