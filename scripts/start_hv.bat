@echo off
setlocal EnableExtensions EnableDelayedExpansion
set ROOT=%~dp0..
set KDMAPPER=D:\hello\code\kdmapper\x64\Release\kdmapper_Release.exe
set DRIVER=%ROOT%\target\release\matrix.sys
set PING=%ROOT%\tools\cpuid_ping.exe
set PROBE=%ROOT%\tools\probe_test.exe

echo ============================================
echo   Hypervisor Loader
echo ============================================
echo.

echo [1/7] Preflight checks...
if not "%HV_BOOT_STOP_STAGE%"=="" (
    echo [!] HV_BOOT_STOP_STAGE is a build-time switch.
    echo     Rebuild with scripts\build_stage.bat %HV_BOOT_STOP_STAGE% before loading.
)

tasklist | findstr /I "EasyAntiCheat EasyAntiCheat_EOS EOSAntiCheat EAC" >nul 2>&1
if not errorlevel 1 (
    echo [-] Anti-cheat process appears to be running.
    echo     Reboot, run this loader first, then start the game.
    pause
    exit /b 2
)

if not exist "%DRIVER%" (
    echo [-] Driver not found: "%DRIVER%"
    echo     Build release first.
    pause
    exit /b 3
)

if not exist "%KDMAPPER%" (
    echo [-] kdmapper not found: "%KDMAPPER%"
    pause
    exit /b 4
)

if not exist "%PING%" (
    echo [-] cpuid_ping.exe not found: "%PING%"
    echo     Build tools first.
    pause
    exit /b 5
)

if not exist "%PROBE%" (
    echo [-] probe_test.exe not found: "%PROBE%"
    echo     Build tools first.
    pause
    exit /b 6
)

"%PING%" --status > "%TEMP%\hv_status.log" 2>&1
if not errorlevel 1 (
    type "%TEMP%\hv_status.log"
    del /F /Q "%TEMP%\hv_status.log" >nul 2>&1
    echo [-] Hypervisor is already active.
    echo     Do not map again over a running instance. Reboot before loading a new build.
    pause
    exit /b 7
)
del /F /Q "%TEMP%\hv_status.log" >nul 2>&1

:: Clean old diag log
del /F /Q C:\hv_diag.log >nul 2>&1

echo [2/7] Mapping hypervisor driver...
"%KDMAPPER%" "%DRIVER%"
if errorlevel 1 (
    echo.
    echo [-] kdmapper failed. Make sure:
    echo     - Run as Administrator
    echo     - No anticheat/antivirus running
    echo     - Game not started yet
    pause
    exit /b 8
)

echo.
echo [3/7] Driver mapped.
echo     Kernel debug output is on COM2 / I/O base 0x2f8.
if /I "%HV_MAP_ONLY%"=="1" (
    echo [!] HV_MAP_ONLY=1, stopping before CPUID/probe/seal checks.
    pause
    exit /b 0
)

echo.
echo [4/7] Running CPUID ping test...
if exist "%PING%" (
    "%PING%"
    if errorlevel 1 (
        echo.
        echo [-] CPUID verification failed.
        echo     Reboot before retrying; do not start the game with this state.
        pause
        exit /b 9
    )
) else (
    echo [-] cpuid_ping.exe disappeared after preflight.
    pause
    exit /b 10
)

echo.
echo [5/7] Running user-mode probe test...
if exist "%PROBE%" (
    "%PROBE%"
    if errorlevel 1 (
        echo.
        echo [-] User-mode probe verification failed.
        echo     Reboot before retrying; do not start the game with this state.
        pause
        exit /b 11
    )
) else (
    echo [-] probe_test.exe disappeared after preflight.
    pause
    exit /b 12
)

echo.
echo [6/7] Ready check complete.
if /I "%HV_NO_SEAL%"=="1" (
    echo [!] HV_NO_SEAL=1, diagnostic channel left open for monitoring.
) else (
    echo [7/7] Sealing diagnostic channel...
    if exist "%PING%" (
        set "SEAL_LOG=%TEMP%\hv_seal_!RANDOM!.log"
        "%PING%" --seal > "!SEAL_LOG!" 2>&1
        if errorlevel 1 (
            type "!SEAL_LOG!"
            echo.
            echo [-] Failed to seal diagnostic channel.
            echo     Reboot before retrying; do not start the game with this state.
            del /F /Q "!SEAL_LOG!" >nul 2>&1
            pause
            exit /b 13
        )
        type "!SEAL_LOG!"
        findstr /L /C:"[+] diagnostic channel sealed" "!SEAL_LOG!" >nul 2>&1
        if errorlevel 1 (
            echo.
            echo [-] Seal confirmation missing.
            echo     Rebuild tools\cpuid_ping.exe and reboot before retrying.
            del /F /Q "!SEAL_LOG!" >nul 2>&1
            pause
            exit /b 14
        )
        del /F /Q "!SEAL_LOG!" >nul 2>&1
    ) else (
        echo [!] cpuid_ping.exe not found, cannot seal diagnostics
        pause
        exit /b 15
    )
)
echo.
echo ============================================
echo   Done. You can now start the game.
echo ============================================
pause
