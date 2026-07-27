@echo off
setlocal

set "ROOT=%~dp0.."
if not exist "%ROOT%\scripts\register_hv_resume_task.ps1" set "ROOT=D:\rust-cheat\hypervisor"
echo [*] Registering the HV boot-recovery task. Run this window as Administrator.
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\scripts\register_hv_resume_task.ps1"
if errorlevel 1 (
    echo [-] Registration failed. Open an elevated PowerShell and retry.
    exit /b 1
)

echo [+] Boot-recovery task installed.
endlocal
