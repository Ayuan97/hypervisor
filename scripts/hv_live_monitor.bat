@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0hv_live_monitor.ps1" %*
exit /b %errorlevel%
