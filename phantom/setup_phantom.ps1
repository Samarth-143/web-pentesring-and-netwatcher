Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "       PHANTOM AUTOMATED INSTALLER" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check for Python
Write-Host "[*] Checking for Python 3.11+..." -ForegroundColor Yellow
if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonVersion = python --version
    Write-Host "[+] Python is installed: $pythonVersion" -ForegroundColor Green
} else {
    Write-Host "[!] Python is not installed or not in PATH!" -ForegroundColor Red
    Write-Host "    Please download and install Python 3.11 or newer from python.org"
    Write-Host "    Make sure to check 'Add Python to PATH' during installation."
    Pause
    exit
}

# 2. Check for Node.js
Write-Host "[*] Checking for Node.js..." -ForegroundColor Yellow
if (Get-Command npm -ErrorAction SilentlyContinue) {
    $nodeVersion = node --version
    Write-Host "[+] Node.js is installed: $nodeVersion" -ForegroundColor Green
} else {
    Write-Host "[!] Node.js is not installed or not in PATH!" -ForegroundColor Red
    Write-Host "    Please download and install Node.js from nodejs.org"
    Pause
    exit
}

# 3. Setup Backend Virtual Environment and Dependencies
Write-Host "[*] Setting up Backend Dependencies..." -ForegroundColor Yellow
cd backend
if (!(Test-Path "venv")) {
    Write-Host "[*] Creating Python Virtual Environment..." -ForegroundColor Yellow
    python -m venv venv
}

Write-Host "[*] Installing Python requirements..." -ForegroundColor Yellow
.\venv\Scripts\python.exe -m pip install -r requirements.txt
cd ..

# 4. Setup Frontend Dependencies
Write-Host "[*] Setting up Frontend Dependencies..." -ForegroundColor Yellow
cd frontend
npm install --legacy-peer-deps
cd ..

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "      INSTALLATION COMPLETE!" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "You can now run Phantom by executing 'start_phantom.ps1'"
Pause
