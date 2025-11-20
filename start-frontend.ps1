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
npm start
