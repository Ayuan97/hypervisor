@echo off
echo ============================================
echo   Hypervisor Loader
echo ============================================
echo.

:: Clean old diag log
del /F /Q C:\hv_diag.log >nul 2>&1

echo [1/3] Mapping hypervisor driver...
"D:\hello\code\kdmapper\x64\Release\kdmapper_Release.exe" "D:\hello\code\hypervisor\target\release\matrix.sys"
if %errorlevel% neq 0 (
    echo.
    echo [-] kdmapper failed. Make sure:
    echo     - Run as Administrator
    echo     - No anticheat/antivirus running
    echo     - Game not started yet
    pause
    exit /b 1
)

echo.
echo [2/3] Checking diagnostic log...
timeout /t 2 /nobreak >nul
if exist C:\hv_diag.log (
    echo --- hv_diag.log ---
    type C:\hv_diag.log
    echo -------------------
) else (
    echo [!] No diagnostic log found
)

echo.
echo [3/3] Running CPUID ping test...
if exist "D:\hello\code\hypervisor\tools\cpuid_ping.exe" (
    "D:\hello\code\hypervisor\tools\cpuid_ping.exe"
) else (
    echo [!] cpuid_ping.exe not found, skipping
)

echo.
echo ============================================
echo   Hypervisor test session is active.
echo ============================================
echo.
echo [!] Do NOT start anti-cheat protected games in this boot session.
echo [!] The mapped hypervisor is not safely unloadable in-place.
echo [!] Reboot before launching games or other protected software.
echo.
choice /C YN /N /M "Reboot now to restore normal game mode? [Y/N] "
if errorlevel 2 (
    echo.
    echo [!] Leaving this machine in hypervisor test mode until reboot.
    pause
    exit /b 0
)
shutdown /r /t 0 /c "Rebooting to leave the hypervisor test session."
pause
