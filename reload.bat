@echo off
setlocal EnableDelayedExpansion

echo.
echo ============================================================
echo   Remote Command Server  --  Reload (Uninstall + Reinstall)
echo ============================================================
echo.

REM ── Require Administrator (self-elevate via UAC) ───────────────────────────
net session >nul 2>&1
if %errorlevel% equ 0 goto :ELEVATED

echo [INFO] Requesting administrator privileges...
set "VBS=%temp%\elevate_reload.vbs"
echo Set sh = CreateObject("Shell.Application") > "%VBS%"
echo sh.ShellExecute "cmd.exe", "/c ""%~s0""", "%~sdp0", "runas", 1 >> "%VBS%"
cscript //nologo "%VBS%"
del "%VBS%" >nul 2>&1
exit /b

:ELEVATED
cd /d "%~dp0"

REM ── Step 1 : Uninstall (inlined to avoid stdin-pipe issues) ───────────────
echo [1/2] Uninstalling ...
echo.
echo Stopping service ...
python server.py stop >nul 2>&1
timeout /t 3 /nobreak >nul

echo Removing service ...
python server.py remove
if %errorlevel% neq 0 (
    sc delete RemoteCommandServer >nul 2>&1
)
timeout /t 2 /nobreak >nul

echo Killing residual service host (pythonservice.exe) ...
taskkill /F /IM pythonservice.exe >nul 2>&1

echo Killing watermark indicator ...
wmic process where "commandline like '%%watermark.py%%'" delete >nul 2>&1

echo Removing watermark from Windows Startup ...
set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
del "%STARTUP%\RC-Server-Watermark.bat" >nul 2>&1

echo Removing stale stats file ...
del /f "%~dp0server_stats.json" >nul 2>&1

echo.
echo ============================================================
echo   RemoteCommandServer stopped and uninstalled.
echo ============================================================
echo.

REM ── Step 2 : Reinstall (interactive – press Enter to keep existing password)
echo [2/2] Installing ...
echo.
call "%~dp0install.bat"
