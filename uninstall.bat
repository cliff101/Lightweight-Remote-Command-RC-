@echo off
setlocal

echo.
echo ============================================================
echo   Remote Command Server  --  Uninstaller
echo ============================================================
echo.

REM ── Require Administrator ──────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] This script must be run as Administrator.
    echo         Right-click and choose "Run as administrator".
    pause
    exit /b 1
)

cd /d "%~dp0"

echo Stopping service ...
python server.py stop >nul 2>&1
timeout /t 3 /nobreak >nul

echo Removing service ...
python server.py remove
if %errorlevel% neq 0 (
    echo [WARNING] Could not remove service via Python.  Trying sc.exe ...
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
echo   RemoteCommandServer fully uninstalled.
echo ============================================================
echo.
echo   The following files are kept and can be deleted manually:
echo     config.json   server.crt   server.key
echo     server.log    blacklist.json
echo.
pause
