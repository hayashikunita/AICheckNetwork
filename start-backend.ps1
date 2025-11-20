# Backend Server Start Script

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Network Diagnostic Tool - Starting Backend" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "Running with administrator privileges - Packet capture available" -ForegroundColor Green
} else {
    Write-Host "Warning: No administrator privileges" -ForegroundColor Yellow
    Write-Host "Run PowerShell as administrator to use packet capture." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Starting backend server..." -ForegroundColor Green
Write-Host "Server will start at http://localhost:5000" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

# Move to backend directory
Set-Location -Path "$PSScriptRoot\backend"

# Activate virtual environment and start
& ".\venv\Scripts\Activate.ps1"
uvicorn app:app --host 0.0.0.0 --port 5000 --reload
