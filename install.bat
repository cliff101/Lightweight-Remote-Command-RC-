@echo off
setlocal EnableDelayedExpansion

echo.
echo ============================================================
echo   Remote Command Server  --  Installer
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

REM ── Locate Python ──────────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in PATH.
    echo         Install Python 3.8+ from https://python.org and ensure
    echo         "Add Python to PATH" is checked during installation.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo [OK] Found %PYVER%

REM ── Change to the directory containing this script ─────────────────────
cd /d "%~dp0"

REM ── Step 1 : install dependencies ─────────────────────────────────────
echo.
echo [1/5] Installing Python dependencies ...
python -m pip install --quiet -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] pip install failed.  Check your internet connection.
    pause
    exit /b 1
)
echo       Done.

REM ── Step 2 : generate TLS certificate ─────────────────────────────────
echo.
echo [2/5] Generating TLS certificate ...
if exist server.crt (
    echo       server.crt already exists -- skipping.
    echo       To regenerate, delete server.crt and server.key then re-run.
) else (
    set /p SERVER_HOST="       Enter server hostname or IP (default: localhost): "
    if "!SERVER_HOST!"=="" set SERVER_HOST=localhost
    python gen_certs.py --hostname !SERVER_HOST!
    if %errorlevel% neq 0 (
        echo [ERROR] Certificate generation failed.
        pause
        exit /b 1
    )
)

REM ── Step 3 : set server password ──────────────────────────────────────
echo.
echo [3/5] Setting authentication password ...
python setup_password.py --install
if %errorlevel% neq 0 (
    echo [ERROR] Password setup failed.
    pause
    exit /b 1
)

REM ── Step 4 : install Windows service ──────────────────────────────────
echo.
echo [4/5] Installing Windows service ...
sc query RemoteCommandServer >nul 2>&1
if %errorlevel% equ 0 (
    echo       Service already exists -- stopping and removing old installation.
    python server.py stop  >nul 2>&1
    timeout /t 2 /nobreak  >nul
    python server.py remove
)
python server.py --startup auto install
if %errorlevel% neq 0 (
    echo [ERROR] Service installation failed.
    pause
    exit /b 1
)

REM ── Step 5 : configure auto-recovery and start ────────────────────────
echo.
echo [5/5] Configuring service recovery and starting ...
sc failure RemoteCommandServer reset= 86400 actions= restart/5000/restart/10000/restart/30000 >nul 2>&1
python server.py start
if %errorlevel% neq 0 (
    echo [WARNING] Service may not have started immediately.
    echo           Check server.log for details.
) else (
    echo       Service started successfully.
)

REM ── Step 6 : watermark indicator (auto-start + launch now) ───────────
echo.
echo [6/6] Installing taskbar watermark indicator ...

REM Register in Windows Startup folder so it starts with every login
set STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
(echo @echo off & echo start "" /B pythonw "%~dp0watermark.py") > "%STARTUP%\RC-Server-Watermark.bat"

REM Launch immediately (pythonw = no console window)
start "" /B pythonw "%~dp0watermark.py"
echo       Watermark registered and launched (bottom-right corner).

REM ── Summary ────────────────────────────────────────────────────────────
echo.
echo ============================================================
echo   Installation complete!
echo ============================================================
echo.
echo   Service name : RemoteCommandServer
echo   Config file  : %~dp0config.json
echo   Log file     : %~dp0server.log
echo   Blacklist    : %~dp0blacklist.json
echo.
echo   To check status:  sc query RemoteCommandServer
echo   To view logs:     type "%~dp0server.log"
echo.
echo   IMPORTANT: Copy server.crt to every CLIENT machine so the
echo              client can verify the server's TLS certificate.
echo.
echo   Client usage (direct):
echo     python client.py --host ^<this-server-IP^> --cert server.crt
echo.
echo   Client usage (through HTTP proxy):
echo     python client.py --host ^<this-server-IP^> --cert server.crt --proxy proxyhost:8080
echo.
echo   Port 443 is the default – traffic looks like HTTPS and passes most
echo   firewalls without any rule changes.
echo   If port 443 is taken by IIS, change "port" in config.json to 8443.
echo.
pause
