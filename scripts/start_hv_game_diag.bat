@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_hv_game_diag.ps1" %*
endlocal
