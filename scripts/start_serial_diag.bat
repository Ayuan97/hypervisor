@echo off
setlocal
set "HV_DRIVER=%~dp0..\target\release\matrix_serial_diag.sys"
if not exist "%HV_DRIVER%" (
    echo [-] Serial diagnostic driver not found.
    echo     Run scripts\build_serial_diag.bat first.
    pause
    exit /b 1
)
call "%~dp0start_hv.bat"
exit /b %errorlevel%
