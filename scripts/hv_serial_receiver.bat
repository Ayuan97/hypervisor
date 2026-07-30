@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hv_serial_receiver.ps1" %*
if errorlevel 1 pause
exit /b %errorlevel%
