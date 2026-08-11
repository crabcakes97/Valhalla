@echo off
setlocal
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found in PATH.
    pause
    exit /b 1
)

python -c "import customtkinter" >nul 2>nul
if errorlevel 1 (
    echo Installing Python dependencies...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Failed to install dependencies.
        pause
        exit /b 1
    )
)

python "%~dp0ctk_lk_patcher_ui.py"
if errorlevel 1 pause

