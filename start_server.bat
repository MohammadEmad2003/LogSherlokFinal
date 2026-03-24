@echo off
echo.
echo ============================================================
echo   Autonomous Forensic Orchestrator
echo ============================================================
echo.
echo   Starting server...
echo.
echo   Open in browser: http://localhost:8000
echo   API Documentation: http://localhost:8000/docs
echo.
echo ============================================================
echo.

cd /d "%~dp0"
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

pause
