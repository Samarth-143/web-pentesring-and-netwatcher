Write-Host "Starting PHANTOM Project Components..." -ForegroundColor Green

# Ensure we are in the correct directory (the script's directory)
Set-Location -Path $PSScriptRoot

# 1. Start Redis
Write-Host "Starting Redis Server..." -ForegroundColor Cyan
Start-Process powershell.exe -WorkingDirectory "$PSScriptRoot\backend\redis_bin" -ArgumentList "-NoExit", "-Command", ".\redis-server.exe"

# 2. Start FastAPI Backend
Write-Host "Starting FastAPI Backend..." -ForegroundColor Cyan
Start-Process powershell.exe -WorkingDirectory "$PSScriptRoot\backend" -ArgumentList "-NoExit", "-Command", ".\venv\Scripts\uvicorn.exe app.main:app --reload --env-file .env"

# 3. Start Celery Worker
Write-Host "Starting Celery Worker..." -ForegroundColor Cyan
# Using --pool=solo as standard celery multiprocessing is not supported on Windows natively
Start-Process powershell.exe -WorkingDirectory "$PSScriptRoot\backend" -ArgumentList "-NoExit", "-Command", ".\venv\Scripts\celery.exe -A app.core.celery_app worker --pool=solo --loglevel=info"

# 4. Start React Frontend
Write-Host "Starting React Frontend..." -ForegroundColor Cyan
Start-Process powershell.exe -WorkingDirectory "$PSScriptRoot\frontend" -ArgumentList "-NoExit", "-Command", "npm run dev"

Write-Host "All components started! You should see 4 new terminal windows pop up." -ForegroundColor Green
Write-Host "You can access the dashboard at: http://localhost:5173" -ForegroundColor Yellow

# 5. Start Traffic Daemon (Requires Admin)
Write-Host 'Starting Traffic Daemon...' -ForegroundColor Cyan
Start-Process powershell.exe -ArgumentList "-NoExit", "-Command", "cd backend; .\venv\Scripts\python.exe daemon\traffic_daemon.py"
