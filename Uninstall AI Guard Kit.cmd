@echo off
setlocal
title AI Guard SE Demo Kit - uninstall
if exist "%USERPROFILE%\.local\bin\uv.exe" set "PATH=%USERPROFILE%\.local\bin;%PATH%"
set UV_SYSTEM_CERTS=1
set UV_NATIVE_TLS=1
set PYTHONUTF8=1
uv run --quiet --python 3.12 --script "%~dp0aiguard_kit.py" uninstall
pause
