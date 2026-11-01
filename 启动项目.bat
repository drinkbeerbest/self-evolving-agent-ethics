@echo off
rem ============================================================
rem  Ethics Circuit Breaker Prototype - one-click launcher (Windows)
rem  Double-click this file: env check -> data check -> serve -> open browser
rem  NOTE: keep this file pure ASCII. cmd reads .bat with the OEM
rem        codepage; UTF-8 Chinese bytes can be mis-decoded into
rem        stray parentheses and break block parsing.
rem        All Chinese messages come from tools/start.py instead.
rem ============================================================
chcp 65001 >nul 2>&1
cd /d "%~dp0"
setlocal

rem Force UTF-8 I/O so Python's Chinese output renders correctly in the
rem console (chcp 65001) and stays UTF-8 when redirected to a file.
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
    echo          Please install Python 3.11+ from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo.
echo   Using interpreter: %PY%
echo.

rem Fast start: env check -> module self-check -> datasets (if missing) -> serve.
rem Add --with-data to also rerun the full strategy experiment (takes minutes).
"%PY%" tools\start.py %*

if errorlevel 1 (
    echo.
    echo   Startup failed. See the error output above.
    pause
)
endlocal
