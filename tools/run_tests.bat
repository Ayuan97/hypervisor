@echo off
echo ========================================
echo  Manual CPUID Test
echo ========================================
echo.

cd /d D:\cheat\backends\hypervisor\tools

echo [1/4] Check HV Status
ping_test.exe
echo.

echo [2/4] Check Hypervisor Bit
check_hv_bit.exe
echo.

echo [3/4] Check Vmexit Counter
cpuid_vmexit_counter.exe
echo.

echo [4/4] Run Comprehensive Test
comprehensive_cpuid_test.exe
echo.

echo ========================================
echo  Test Complete
echo ========================================
pause
