# Stop all CAS-SE development processes
$ports = @(8181, 8000, 5173)

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "        Stopping CAS-SE Development Services        " -ForegroundColor Cyan
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($port in $ports) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($connections) {
        foreach ($conn in $connections) {
            $pidToKill = $conn.OwningProcess
            try {
                $proc = Get-Process -Id $pidToKill -ErrorAction SilentlyContinue
                Write-Host "[INFO] Stopping process tree for PID $pidToKill listening on port $port..." -ForegroundColor Yellow
                Start-Process "taskkill" -ArgumentList "/F", "/T", "/PID", "$pidToKill" -NoNewWindow -Wait -ErrorAction SilentlyContinue
                Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
            } catch {
                # Process might have already exited
            }
        }
    } else {
        Write-Host "[INFO] Port $port is already clear." -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "All CAS-SE dev services stopped!" -ForegroundColor Green
