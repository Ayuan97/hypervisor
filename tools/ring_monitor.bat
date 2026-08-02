@echo off
set PING=D:\cheat\backends\hypervisor\tools\cpuid_ping.exe
set LOG=D:\cheat\backends\hypervisor\logs\ring_monitor.log
echo [%time%] ring_monitor started > %LOG%
:loop
%PING% >> %LOG% 2>&1
echo --- %time% --- >> %LOG%
timeout /t 1 /nobreak >nul
goto loop
