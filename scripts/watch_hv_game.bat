@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0watch_hv_game.ps1" -Mode Watch %*
endlocal
