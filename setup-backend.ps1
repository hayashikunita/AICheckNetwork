# -*- coding: utf-8 -*-
# Backend Setup Script

Write-Host "================================" -ForegroundColor Cyan
Write-Host "Network Diagnostic Tool - Backend Setup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Warning: Not running with administrator privileges" -ForegroundColor Yellow
    Write-Host "Administrator rights are required for packet capture functionality." -ForegroundColor Yellow
    Write-Host ""
}

# Move to backend directory
Set-Location -Path "$PSScriptRoot\backend"

Write-Host "Creating virtual environment..." -ForegroundColor Green
if (Test-Path "venv") {
    Write-Host "Existing virtual environment found." -ForegroundColor Yellow
} else {
    python -m venv venv
    Write-Host "Virtual environment created successfully." -ForegroundColor Green
}

Write-Host ""
Write-Host "Activating virtual environment..." -ForegroundColor Green
& ".\venv\Scripts\Activate.ps1"

Write-Host ""
Write-Host "Installing packages..." -ForegroundColor Green
pip install -r requirements.txt

Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start the backend server:" -ForegroundColor Yellow
Write-Host "  python app.py" -ForegroundColor White
Write-Host ""

if (-not $isAdmin) {
    Write-Host "Note: Run with administrator privileges to use packet capture." -ForegroundColor Yellow
}
