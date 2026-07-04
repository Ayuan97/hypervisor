@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "ROOT=%~dp0.."
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "STAMP=%%i"
set "RUN_DIR=%ROOT%\logs\watch_pt0_%STAMP%"
set "HV_DRIVER=%ROOT%\target\release\matrix_client_pt0_diag.sys"
set "HV_NO_SEAL=1"

mkdir "%RUN_DIR%" >nul 2>&1
echo %RUN_DIR%>"%ROOT%\logs\watch_pt0_latest.txt"

echo [*] PT0 diagnostic run dir: %RUN_DIR%
echo [*] Starting PT0 diagnostic HV...
call "%~dp0start_hv.bat" <nul >"%RUN_DIR%\00_start_hv_pt0.log" 2>&1
set "START_EXIT=%errorlevel%"
echo %START_EXIT%>"%RUN_DIR%\00_start_hv_pt0.exit"
type "%RUN_DIR%\00_start_hv_pt0.log"
if not "%START_EXIT%"=="0" (
    echo [-] PT0 HV start failed: %START_EXIT%
    exit /b %START_EXIT%
)

echo [*] Starting watch loop. Start the game after this line.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0watch_hv_game.ps1" -Mode Watch -IntervalSeconds 1 -RunDir "%RUN_DIR%" -GameProcess rust
exit /b %errorlevel%
