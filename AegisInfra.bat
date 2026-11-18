@echo off
setlocal
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo [AegisInfra] Virtual environment not found. Creating venv...
    python -m venv venv
    if errorlevel 1 (
        echo [AegisInfra] ERROR: Failed to create virtual environment. Ensure Python 3.11+ is installed and on PATH.
        pause
        exit /b 1
    )

    echo [AegisInfra] Installing dependencies from requirements.txt...
    venv\Scripts\python.exe -m pip install --upgrade pip
    venv\Scripts\python.exe -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [AegisInfra] ERROR: Failed to install dependencies.
        pause
        exit /b 1
    )
)

venv\Scripts\python.exe start.py %*
pause
