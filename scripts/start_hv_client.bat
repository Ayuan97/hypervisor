@echo off
setlocal

:: Prefer freshly built target PE; fall back to workspace deploy copy.
set "HV_DRIVER=%~dp0..\target\release\matrix_client.sys"
if not exist "%HV_DRIVER%" set "HV_DRIVER=D:\cheat\output\hv\matrix_client.sys"
if not exist "%HV_DRIVER%" (
    echo [-] matrix_client.sys not found. Run scripts\build_client.bat first.
    exit /b 3
)
echo [*] Loading client HV: %HV_DRIVER%
call "%~dp0start_hv.bat"
exit /b %errorlevel%
