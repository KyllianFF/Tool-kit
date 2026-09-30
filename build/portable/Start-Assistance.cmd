@echo off
rem ===========================================================================
rem  Toolkit - assistance mode launcher ("My PC")
rem
rem  Opens Toolkit.ps1, next to this file, in its assistance mode: one page
rem  that says in plain words what is wrong with this PC and what you can do,
rem  and prepares a request for support with only what you agree to send.
rem  Nothing in this mode changes the PC or asks for administrator rights.
rem
rem  -ExecutionPolicy Bypass applies to THIS ONE process only. It does not
rem  change any setting on the machine and it is the documented way to run a
rem  local script. -Sta is required by the graphical interface (WPF).
rem ===========================================================================

setlocal
set "TOOLKIT_DIR=%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Sta -File "%TOOLKIT_DIR%Toolkit.ps1" -Assist

if errorlevel 1 (
    echo.
    echo Toolkit exited with an error.
    echo If Windows reported the script was blocked, read README.txt, section
    echo "If Windows blocks the script".
    echo.
    pause
)

endlocal
