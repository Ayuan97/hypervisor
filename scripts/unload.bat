@echo off
setlocal

set "SERVICE_NAME=matrix"

echo [*] Unloading hypervisor driver...

sc query "%SERVICE_NAME%" >nul 2>&1
if %errorlevel% neq 0 (
    echo [+] Service not present.
    exit /b 0
)

sc stop %SERVICE_NAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Failed to stop service.
    echo     A live HV intentionally disables standard DriverUnload.
    echo     Reboot before removing or replacing this service.
    echo     Service was not deleted.
    exit /b 1
)

powershell -NoProfile -Command "Start-Sleep -Seconds 1" >nul 2>&1

sc delete %SERVICE_NAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Failed to delete service.
    exit /b 1
)

echo [+] Hypervisor unloaded.
