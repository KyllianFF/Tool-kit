@echo off
rem ===========================================================================
rem  Toolkit - portable launcher
rem
rem  Runs Toolkit.ps1, the readable script sitting next to this file. It reads
rem  its data from the data\ folder and its interface from MainWindow.xaml, both
rem  beside it, so nothing is downloaded and the machine stays offline.
rem
rem  -ExecutionPolicy Bypass applies to THIS ONE process only. It does not
rem  change any setting on the machine and it is the documented way to run a
rem  local script. -Sta is required by the graphical interface (WPF).
rem
rem  Windows PowerShell (powershell.exe) is used on purpose: it ships with every
rem  supported Windows and starts in the single-threaded apartment the interface
rem  needs. PowerShell 7 (pwsh) also works but must be started with -Sta.
rem ===========================================================================

setlocal
set "TOOLKIT_DIR=%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Sta -File "%TOOLKIT_DIR%Toolkit.ps1" %*

if errorlevel 1 (
    echo.
    echo Toolkit exited with an error.
    echo If Windows reported the script was blocked, read README.txt, section
    echo "If Windows blocks the script".
    echo.
    pause
)

endlocal
