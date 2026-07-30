@echo off
setlocal

fltmc >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting Administrator privileges...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    if errorlevel 1 (
        echo [-] Administrator elevation was cancelled or failed.
        pause
        exit /b 1
    )
    exit /b 0
)

set "HV_DRIVER=%~dp0..\target\release\matrix_local_diag.sys"
set "HV_AUTOMATION=1"
if not exist "%HV_DRIVER%" (
    echo [-] Local diagnostic driver not found.
    echo     Run scripts\build_local_diag.bat first.
    pause
    exit /b 1
)
call "%~dp0start_hv.bat"
if errorlevel 1 (
    echo [-] Local diagnostic HV did not start; monitors were not launched.
    exit /b 1
)

echo [+] Starting passive Windows event monitor...
start "HV Windows monitor" powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hv_live_monitor.ps1"
echo [+] Starting local HV log viewer...
start "HV local log viewer" powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='C:\hv_diag_live.log'; while (-not (Test-Path -LiteralPath $p)) { Start-Sleep -Milliseconds 250 }; Get-Content -LiteralPath $p -Tail 50 -Wait"
echo [+] Monitoring started. HV log: C:\hv_diag_live.log
exit /b 0
