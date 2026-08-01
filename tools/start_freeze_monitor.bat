@echo off
start /b powershell -NoProfile -ExecutionPolicy Bypass -File "D:\rust-cheat\hypervisor\tools\freeze_monitor.ps1" > nul 2>&1
echo Monitor started
