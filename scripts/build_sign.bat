@echo off
setlocal

set WDK_BIN=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64
set DRIVER_PATH=%~dp0..\target\release\matrix.sys
set DLL_PATH=%~dp0..\target\release\matrix.dll

echo [*] Building hypervisor...
cd /d %~dp0..
cargo build --release
if %errorlevel% neq 0 (
    echo [-] Build failed.
    exit /b 1
)

echo [*] Copying DLL to SYS...
copy /Y "%DLL_PATH%" "%DRIVER_PATH%" >nul

echo [*] Signing driver...
"%WDK_BIN%\signtool.exe" sign /s PrivateCertStore /n "HypervisorTest" /fd SHA256 "%DRIVER_PATH%"
if %errorlevel% neq 0 (
    echo [-] Signing failed.
    exit /b 1
)

echo [+] Build complete: %DRIVER_PATH%
