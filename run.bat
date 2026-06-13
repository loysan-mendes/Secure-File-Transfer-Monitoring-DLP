@echo off
echo =======================================================
echo     SECURE FILE TRANSFER MONITORING SYSTEM LAUNCHER
echo =======================================================
echo.

echo [*] Installing python backend dependencies...
pip install -r backend\requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install backend dependencies. Make sure Python and pip are in your PATH.
    pause
    exit /b %errorlevel%
)

echo [*] Initializing SQLite Database...
python backend\db.py

echo [*] Launching FastAPI backend server...
start "DLP Backend API" cmd /k "cd backend && python main.py"

echo [*] Launching Vite React frontend...
start "DLP Frontend App" cmd /k "cd frontend && npm run dev"

echo.
echo =======================================================
echo    System starting!
echo    - Dashboard: http://localhost:5173
echo    - Backend API: http://127.0.0.1:8000/docs
echo =======================================================
echo.
pause
