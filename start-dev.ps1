# CAS-SE Unified Development Launcher (PowerShell)
[CmdletBinding()]
param ()

$ErrorActionPreference = "Stop"
$rootDir = $PSScriptRoot
Set-Location $rootDir

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "        CAS-SE Unified Development Launcher        " -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check OPA binary
$opaExe = Join-Path $rootDir "opa\opa.exe"
if (-not (Test-Path $opaExe)) {
    Write-Host "[ERROR] opa\opa.exe not found at $opaExe" -ForegroundColor Red
    exit 1
}

# 2. Determine Python executable
$pythonBin = "python"
if (Test-Path (Join-Path $rootDir ".venv\Scripts\python.exe")) {
    $pythonBin = Join-Path $rootDir ".venv\Scripts\python.exe"
    Write-Host "[INFO] Detected virtual environment at .venv" -ForegroundColor Gray
} elseif (Test-Path (Join-Path $rootDir "backend\.venv\Scripts\python.exe")) {
    $pythonBin = Join-Path $rootDir "backend\.venv\Scripts\python.exe"
    Write-Host "[INFO] Detected virtual environment at backend\.venv" -ForegroundColor Gray
}

# 3. Ensure dev ports are clear
$ports = @(8181, 8000, 5173)
foreach ($port in $ports) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($connections) {
        foreach ($conn in $connections) {
            $pidToKill = $conn.OwningProcess
            try {
                Write-Host "[INFO] Clearing stale process PID $pidToKill on port $port..." -ForegroundColor Yellow
                Start-Process "taskkill" -ArgumentList "/F", "/T", "/PID", "$pidToKill" -NoNewWindow -Wait -ErrorAction SilentlyContinue
            } catch {}
        }
    }
}

# 4. Launch OPA
Write-Host "[1/3] Starting OPA Policy Engine (:8181)..." -ForegroundColor Green
Start-Process cmd.exe -ArgumentList "/k", "title CAS-SE: OPA (:8181) && cd /d `"$rootDir`" && .\opa\opa.exe run --server --addr :8181 opa\policies\"

Start-Sleep -Seconds 2

# 5. Launch Backend API
Write-Host "[2/3] Starting FastAPI Backend (:8000)..." -ForegroundColor Green
Start-Process cmd.exe -ArgumentList "/k", "title CAS-SE: Backend (:8000) && cd /d `"$rootDir`" && `"$pythonBin`" -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000"

# 5. Launch Frontend
Write-Host "[3/3] Starting Vite Frontend (:5173)..." -ForegroundColor Green
Start-Process cmd.exe -ArgumentList "/k", "title CAS-SE: Frontend (:5173) && cd /d `"$rootDir\frontend`" && npm run dev"

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host " All 3 services launched in separate windows!" -ForegroundColor Green
Write-Host "   * OPA Engine:  http://localhost:8181" -ForegroundColor Yellow
Write-Host "   * Backend API: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host "   * Frontend UI: http://localhost:5173" -ForegroundColor Yellow
Write-Host ""
Write-Host " To stop all services cleanly, run .\stop-dev.ps1 or stop-dev.bat" -ForegroundColor Gray
Write-Host "===================================================" -ForegroundColor Cyan
