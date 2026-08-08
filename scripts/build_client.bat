@echo off
setlocal

set "HV_BOOT_STOP_STAGE="
set "HV_USER_CLIENT_READS=1"
set "DRIVER_PATH=%~dp0..\target\release\matrix_client.sys"
set "DLL_PATH=%~dp0..\target\release\matrix.dll"

echo [*] Building client-read driver...
echo [*] Build flags: HV_USER_CLIENT_READS=%HV_USER_CLIENT_READS%
cd /d "%~dp0.."
:: Ensure a failed remap experiment does not poison this shell.
set "RUSTFLAGS="
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

set "OUT_HV=D:\cheat\output\hv\matrix_client.sys"
echo [*] Copying to workspace deploy path: %OUT_HV%
copy /Y "%DRIVER_PATH%" "%OUT_HV%" >nul
if %errorlevel% neq 0 (
    echo [-] Copy to output\hv failed.
    exit /b 1
)

echo [+] Client-read driver ready: %DRIVER_PATH%
echo [+] Deploy copy: %OUT_HV%
