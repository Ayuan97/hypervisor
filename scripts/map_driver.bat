@echo off
echo [*] Mapping hypervisor driver...
"D:\rust-cheat\tools\kdmapper\x64\Release\kdmapper_Release.exe" "D:\rust-cheat\hypervisor\target\release\matrix.sys"
echo.
echo [*] Done. Press any key to close.
pause >nul
