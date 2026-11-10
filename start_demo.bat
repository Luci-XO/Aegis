@echo off
REM Start the Aegis dashboard on Windows and open it in the browser.
REM Double-click this file, or run start_demo.bat from a terminal.
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
) else (
    where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")
)

%PY% -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>nul
if errorlevel 1 (
    echo Aegis needs Python 3.10 or newer. Install it from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Starting the Aegis dashboard at http://127.0.0.1:8000
echo Close this window or press Ctrl+C to stop it.
%PY% -m aegis.web --open
if errorlevel 1 (
    echo.
    echo The dashboard stopped with an error. If port 8000 is busy, run:
    echo     %PY% -m aegis.web --open --port 8080
    pause
)
