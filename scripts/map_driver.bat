@echo off
echo [*] Mapping hypervisor driver...
"D:\hello\code\kdmapper\x64\Release\kdmapper_Release.exe" "D:\hello\code\hypervisor\target\release\matrix.sys"
echo.
echo [*] Done. Press any key to close.
pause >nul
