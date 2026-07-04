@echo off
setlocal

set "ROOT=%~dp0.."
set /p RUN_DIR=<"%ROOT%\logs\watch_pt0_latest.txt"
if "%RUN_DIR%"=="" (
    echo [-] Missing PT0 run dir.
    exit /b 1
)

echo [*] Collecting post-reboot data into: %RUN_DIR%
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0watch_hv_game.ps1" -Mode Collect -RunDir "%RUN_DIR%"
exit /b %errorlevel%
