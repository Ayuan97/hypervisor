@echo off
setlocal

set SERVICE_NAME=matrix

echo [*] Unloading hypervisor driver...

sc stop %SERVICE_NAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Failed to stop service (may not be running).
)

timeout /t 1 /nobreak >nul

sc delete %SERVICE_NAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Failed to delete service.
    exit /b 1
)

echo [+] Hypervisor unloaded.
