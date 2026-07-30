@echo off
setlocal

set "HV_BOOT_STOP_STAGE="
set "HV_LOCAL_DIAG=1"
set "HV_USER_CLIENT_READS=1"
set "HV_PT_CONCEAL_MASK=7"
set "CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1"
set "DRIVER_PATH=%~dp0..\target\release\matrix_local_diag.sys"
set "DLL_PATH=%~dp0..\target\release\matrix.dll"

echo [*] Building local-file diagnostic driver...
echo [*] Build flags: HV_LOCAL_DIAG=%HV_LOCAL_DIAG% HV_USER_CLIENT_READS=%HV_USER_CLIENT_READS% HV_PT_CONCEAL_MASK=%HV_PT_CONCEAL_MASK%
cd /d "%~dp0.."
cargo clean -p matrix -p hypervisor >nul 2>&1
cargo build -p matrix --release
if %errorlevel% neq 0 (
    echo [-] Build failed.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0finalize_driver.ps1" -Source "%DLL_PATH%" -Destination "%DRIVER_PATH%"
if %errorlevel% neq 0 (
    echo [-] Finalize failed.
    pause
    exit /b 1
)

echo [+] Local diagnostic driver ready: %DRIVER_PATH%
echo [+] Runtime log: C:\hv_diag_live.log
pause
