@echo off
flake8 .
black --check .
echo Linting complete.
pause
