@echo off
rem Launcher for the AI Guard SE demo kit (Windows). Usage: .\aiguard-kit.cmd setup|gui|run|status|teardown
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
uv run --quiet --script "%~dp0aiguard_kit.py" %*
