@echo off
echo Restarting firewall...
taskkill /F /IM python.exe /T
python main.py
pause
