@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p='C:\hv_diag_live.log'; Write-Host ('Waiting for ' + $p); while (-not (Test-Path -LiteralPath $p)) { Start-Sleep -Milliseconds 250 }; Get-Content -LiteralPath $p -Tail 50 -Wait"
if errorlevel 1 pause
exit /b %errorlevel%
