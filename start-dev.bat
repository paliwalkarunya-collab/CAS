@echo off
setlocal enabledelayedexpansion

title CAS-SE Development Stack Launcher
echo ===================================================
echo        CAS-SE Unified Development Launcher        
echo ===================================================
echo.

cd /d "%~dp0"

:: 1. Verify OPA binary exists
if not exist "opa\opa.exe" (
    echo [ERROR] opa\opa.exe not found at %~dp0opa\opa.exe!
    echo Please make sure opa.exe is located inside the opa\ directory.
    pause
    exit /b 1
)

:: 2. Determine Python executable (virtualenv vs global)
set "PY_BIN=python"
if exist ".venv\Scripts\python.exe" (
    echo [INFO] Detected virtualenv at .venv
    set "PY_BIN=.venv\Scripts\python.exe"
) else if exist "backend\.venv\Scripts\python.exe" (
    echo [INFO] Detected virtualenv at backend\.venv
    set "PY_BIN=backend\.venv\Scripts\python.exe"
)

:: 3. Check and clean up any stale processes on dev ports
echo [INFO] Ensuring ports 8181, 8000, and 5173 are free...
for %%p in (8181 8000 5173) do (
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":%%p .*LISTENING"') do (
        echo [INFO] Releasing port %%p - stopping stale PID %%a...
        taskkill /f /pid %%a >nul 2>&1
    )
)

:: 4. Start OPA Policy Engine
echo [1/3] Starting OPA Policy Engine on http://localhost:8181 ...
start "CAS-SE: OPA (:8181)" cmd /k "title CAS-SE: OPA (:8181) && cd /d "%~dp0" && .\opa\opa.exe run --server --addr :8181 opa\policies\"

:: Brief pause so OPA can initialize socket
ping 127.0.0.1 -n 3 >nul

:: 5. Start FastAPI Backend
echo [2/3] Starting FastAPI Backend on http://localhost:8000 ...
start "CAS-SE: Backend (:8000)" cmd /k "title CAS-SE: Backend (:8000) && cd /d "%~dp0" && !PY_BIN! -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000"

:: 6. Start React Frontend
echo [3/3] Starting Vite Frontend on http://localhost:5173 ...
start "CAS-SE: Frontend (:5173)" cmd /k "title CAS-SE: Frontend (:5173) && cd /d "%~dp0frontend" && npm run dev"

echo.
echo ===================================================
echo  All 3 services have been launched in separate windows!
echo   * OPA Engine:  http://localhost:8181
echo   * Backend API: http://localhost:8000/docs
echo   * Frontend UI: http://localhost:5173
echo.
echo  To stop all services cleanly, run stop-dev.bat
echo ===================================================
echo.
pause
