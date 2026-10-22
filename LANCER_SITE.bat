@echo off
cd /d "%~dp0"
echo Site : http://localhost:8000
echo Administration : http://localhost:8000/admin
python server.py serve
pause
