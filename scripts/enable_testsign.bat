@echo off
echo [*] Enabling test signing mode...
bcdedit /set testsigning on
if %errorlevel% neq 0 (
    echo [-] Failed. Run as Administrator.
    exit /b 1
)
echo [+] Test signing enabled. Reboot required.
echo [*] Run 'bcdedit /set testsigning off' to disable later.
pause
