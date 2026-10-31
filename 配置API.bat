@echo off
rem ============================================================
rem  One-click LLM API configuration (any OpenAI-compatible
rem  provider). Writes configs/api.yaml (gitignored).
rem  NOTE: keep this file pure ASCII - see the note in the
rem        launcher bat for the codepage rationale.
rem ============================================================
chcp 65001 >nul 2>&1
cd /d "%~dp0"
setlocal
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

set "PY="
python -c "print(1)" >nul 2>&1
if not errorlevel 1 set "PY=python"
if not defined PY (
    py -c "print(1)" >nul 2>&1
    if not errorlevel 1 set "PY=py"
)
if not defined PY (
    echo.
    echo   [FAIL] No usable Python interpreter found.
    echo          Install Python 3.11+ from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

"%PY%" tools\configure_api.py
if errorlevel 1 (
    echo.
    echo   Configuration not saved or failed. See output above.
)
pause
endlocal
