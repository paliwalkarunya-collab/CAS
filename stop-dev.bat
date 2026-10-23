@echo off
title CAS-SE Development Stack Stopper
echo ===================================================
echo        Stopping CAS-SE Development Services        
echo ===================================================
echo.

echo Freeing ports 8181 (OPA), 8000 (Backend), and 5173 (Frontend)...
echo.

for %%p in (8181 8000 5173) do (
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r /c:":%%p .*LISTENING"') do (
        echo [INFO] Stopping process PID %%a on port %%p...
        taskkill /f /pid %%a >nul 2>&1
    )
)

echo.
echo ===================================================
echo  All dev processes on ports 8181, 8000, 5173 stopped!
echo ===================================================
echo.
pause
