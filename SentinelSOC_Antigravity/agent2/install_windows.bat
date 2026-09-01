@echo off
title SentinelSOC Agent Installer
color 0A
echo ============================================================
echo   SentinelSOC Security Agent — Windows Installer
echo ============================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

echo [OK] Python found.

:: Install dependencies
echo.
echo [*] Installing Python dependencies...
pip install psutil requests pywin32 --quiet
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo [OK] Dependencies installed.

:: Ask for server URL
echo.
set /p SOC_URL="Enter SOC Server URL [http://localhost:4000]: "
if "%SOC_URL%"=="" set SOC_URL=http://localhost:4000

echo.
echo [*] Starting SentinelSOC Agent...
echo     Server: %SOC_URL%
echo     Press Ctrl+C to stop the agent.
echo.

set SOC_SERVER=%SOC_URL%
python "%~dp0sentinel_agent.py"

pause
