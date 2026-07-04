@echo off
setlocal

set "HV_DRIVER=%~dp0..\target\release\matrix_client_pt0_diag.sys"
call "%~dp0start_hv.bat"
exit /b %errorlevel%
