@echo off
setlocal

set "ROOT=%~dp0.."
if not exist "%ROOT%\scripts\register_hv_resume_task.ps1" set "ROOT=D:\rust-cheat\hypervisor"
fltmc >nul 2>&1
if errorlevel 1 (
    echo [*] Requesting administrator permission...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%ComSpec%' -Verb RunAs -ArgumentList '/c ""%~f0""'"
    exit /b 0
)

echo [*] Registering the HV boot-recovery and Codex resume tasks.
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\scripts\register_hv_resume_task.ps1"
if errorlevel 1 (
    echo [-] Registration failed.
    exit /b 1
)

echo [+] Boot-recovery task installed.
endlocal
