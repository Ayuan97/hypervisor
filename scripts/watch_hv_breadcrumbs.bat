@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0watch_hv_breadcrumbs.ps1" %*
exit /b %errorlevel%
