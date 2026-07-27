@echo off
setlocal

set "ROOT=%~dp0.."
echo [*] Registering the HV boot-recovery task. Run this window as Administrator.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0register_hv_resume_task.ps1"
if errorlevel 1 (
    echo [-] Registration failed. Open an elevated PowerShell and retry.
    exit /b 1
)

echo [+] Boot-recovery task installed.
endlocal
