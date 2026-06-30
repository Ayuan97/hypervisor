@echo off
echo ============================================
echo   Restore Game Mode
echo ============================================
echo.
echo [*] Disabling local test-signing boot flags when possible...
bcdedit /set testsigning off >nul 2>&1
bcdedit /set nointegritychecks off >nul 2>&1
echo.
echo [!] If the hypervisor was mapped in this boot session, a reboot is required.
echo [!] Do not launch anti-cheat protected games until after reboot.
echo.
choice /C YN /N /M "Reboot now? [Y/N] "
if errorlevel 2 (
    echo.
    echo [!] Game mode is not fully restored until you reboot.
    pause
    exit /b 0
)
shutdown /r /t 0 /c "Restoring normal game mode after hypervisor testing."
