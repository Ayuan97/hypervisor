@echo off
setlocal

set "HV_BOOT_STOP_STAGE="
set "DRIVER_PATH=%~dp0..\target\release\matrix.sys"
set "DLL_PATH=%~dp0..\target\release\matrix.dll"

echo [*] Building release driver...
cd /d "%~dp0.."
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

echo [+] Release driver ready: %DRIVER_PATH%
