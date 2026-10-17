@echo off
rem Launcher for the AI Guard SE demo kit (Windows). Usage: .\aiguard-kit.cmd setup|gui|run|status|teardown
rem Find uv even when this terminal was opened before uv was installed.
if exist "%USERPROFILE%\.local\bin\uv.exe" set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where uv >nul 2>nul
if errorlevel 1 (
  echo uv is not installed. In PowerShell run:
  echo   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
  echo then open a new terminal and run this command again.
  exit /b 1
)
set UV_SYSTEM_CERTS=1
set UV_NATIVE_TLS=1
set PYTHONUTF8=1
rem Python 3.12: every library the kit needs has ready-made builds for it on Windows and Mac.
rem "& exit /b" keeps cmd from reading this file again after the kit exits (an update may have replaced it).
uv run --quiet --python 3.12 --script "%~dp0aiguard_kit.py" %* & exit /b
