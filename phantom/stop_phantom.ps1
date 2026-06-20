# Script to stop all Phantom-related processes (Redis, FastAPI, Celery, React, Traffic Daemon)
Write-Host "Stopping Phantom processes..." -ForegroundColor Yellow

# Kill Celery Workers
Write-Host "Killing Celery workers..."
Get-Process | Where-Object {$_.ProcessName -match "celery"} | Stop-Process -Force -ErrorAction SilentlyContinue

# Kill Python (FastAPI/Uvicorn, Traffic Daemon)
Write-Host "Killing Python/Uvicorn/Daemon processes..."
Get-Process | Where-Object {$_.ProcessName -match "python"} | Stop-Process -Force -ErrorAction SilentlyContinue

# Kill Node (React frontend)
Write-Host "Killing Node (React) processes..."
Get-Process | Where-Object {$_.ProcessName -match "node"} | Stop-Process -Force -ErrorAction SilentlyContinue

# Kill Redis
Write-Host "Killing Redis server..."
Get-Process | Where-Object {$_.ProcessName -match "redis-server"} | Stop-Process -Force -ErrorAction SilentlyContinue

Write-Host "All Phantom processes have been terminated." -ForegroundColor Green
Write-Host "You can now safely run .\start_phantom.ps1 again to start fresh." -ForegroundColor Cyan
