@echo off
cd /d "%~dp0"

where python >nul 2>&1
if errorlevel 1 (
  echo Python is required. Install from https://www.python.org/downloads/
  pause
  exit /b 1
)

if not exist ".venv" (
  echo Creating virtual environment...
  python -m venv .venv
)

call .venv\Scripts\activate.bat
pip install -q -r requirements.txt

python main.py --serve
pause
