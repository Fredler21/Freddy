@echo off
setlocal
python freddy.py %*
if %errorlevel% neq 0 (
    py -3 freddy.py %*
)
endlocal
