@echo off
setlocal

set DRIVER_PATH=%~dp0..\target\release\matrix.sys
set SERVICE_NAME=matrix

echo [*] Loading hypervisor driver...

:: Check if service exists
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Service exists, stopping...
    sc stop %SERVICE_NAME% >nul 2>&1
    timeout /t 1 /nobreak >nul
    sc delete %SERVICE_NAME% >nul 2>&1
    timeout /t 1 /nobreak >nul
)

:: Copy driver to system32\drivers
copy /Y "%DRIVER_PATH%" "%SystemRoot%\system32\drivers\matrix.sys" >nul
if %errorlevel% neq 0 (
    echo [-] Failed to copy driver. Run as Administrator.
    exit /b 1
)

:: Create kernel service
sc create %SERVICE_NAME% type= kernel binPath= "%SystemRoot%\system32\drivers\matrix.sys"
if %errorlevel% neq 0 (
    echo [-] Failed to create service.
    exit /b 1
)

:: Start driver
sc start %SERVICE_NAME%
if %errorlevel% neq 0 (
    echo [-] Failed to start driver. Check serial output for details.
    sc delete %SERVICE_NAME% >nul 2>&1
    exit /b 1
)

echo [+] Hypervisor loaded successfully.
echo [*] Monitor COM2 serial port for debug output.
