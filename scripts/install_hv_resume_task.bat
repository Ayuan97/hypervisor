@echo off
setlocal

set "ROOT=%~dp0.."
if not exist "%ROOT%\scripts\register_hv_resume_task.ps1" set "ROOT=D:\rust-cheat\hypervisor"
echo [*] Registering the Codex resume task.
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%\scripts\register_hv_resume_task.ps1"
if errorlevel 1 (
    echo [-] Registration failed.
    exit /b 1
)

echo [+] Codex resume task installed.
endlocal
