@echo off
setlocal

if "%~1"=="" (
    echo Usage: scripts\build_stage.bat STAGE
    echo Example: scripts\build_stage.bat 600
    exit /b 2
)

powershell -NoProfile -Command "if ('%~1' -notmatch '^[0-9]+$') { exit 1 }" >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] STAGE must be decimal digits only.
    exit /b 2
)

set "STAGE=%~1"
set "HV_BOOT_STOP_STAGE=%STAGE%"
set "HV_USER_CLIENT_READS=0"
set "DRIVER_PATH=%~dp0..\target\release\matrix_stage_%STAGE%.sys"
set "DLL_PATH=%~dp0..\target\release\matrix.dll"

echo [*] Building stage-gated driver, stop stage %HV_BOOT_STOP_STAGE%...
cd /d "%~dp0.."
cargo clean -p matrix -p hypervisor >nul 2>&1
cargo build -p matrix --release
if %errorlevel% neq 0 (
    echo [-] Build failed.
    exit /b 1
)

echo [*] Finalizing SYS...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0finalize_driver.ps1" -Source "%DLL_PATH%" -Destination "%DRIVER_PATH%"
if %errorlevel% neq 0 (
    echo [-] Finalize failed.
    exit /b 1
)

echo [*] Scanning release strings...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scan_release_strings.ps1" -Driver "%DRIVER_PATH%"
if %errorlevel% neq 0 (
    echo [-] Release string scan failed.
    exit /b 1
)

echo [+] Stage-gated driver ready: %DRIVER_PATH%
