@echo off
setlocal
title AI Guard SE Demo Kit - installer
cd /d "%~dp0"
if not exist "%~dp0aiguard_kit.py" (
  echo.
  echo   This installer is running from inside the zip, so it can't see the rest of the kit.
  echo.
  echo   1. Close this window.
  echo   2. Right-click the aiguard-se-kit zip file and choose "Extract All...", then click Extract.
  echo   3. Open the extracted aiguard-se-kit folder and double-click "Install AI Guard Kit.cmd" there.
  echo.
  pause
  exit /b 1
)
echo.
echo   AI Guard SE Demo Kit - installer
echo   ================================
echo   This will:
echo     - install uv (the free tool the kit runs on) if it isn't installed yet
echo     - copy the kit to %USERPROFILE%\.aiguard-se-kit\app
echo     - add an "AI Guard Demo Console" shortcut to your desktop and Start menu
echo     - let you run "aiguard-kit" from any terminal
echo   Nothing changes in your Zscaler tenant until you finish Setup in the console.
echo.
pause

if exist "%USERPROFILE%\.local\bin\uv.exe" set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where uv >nul 2>nul && goto haveuv

echo.
echo   Installing uv...
powershell -NoProfile -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
if exist "%USERPROFILE%\.local\bin\uv.exe" set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where uv >nul 2>nul && goto haveuv

where winget >nul 2>nul
if not errorlevel 1 (
  echo   The uv installer didn't work here. Trying winget...
  winget install --id=astral-sh.uv -e --accept-source-agreements --accept-package-agreements
  set "PATH=%LOCALAPPDATA%\Microsoft\WinGet\Links;%PATH%"
)
where uv >nul 2>nul && goto haveuv

echo.
echo   Couldn't install uv. Your laptop's security policy may be blocking the download.
echo   Ask IT to allow astral.sh and github.com downloads, or install uv another way:
echo     https://docs.astral.sh/uv/getting-started/installation/
echo   Then double-click this installer again.
echo.
pause
exit /b 1

:haveuv
set UV_SYSTEM_CERTS=1
set UV_NATIVE_TLS=1
set PYTHONUTF8=1
echo.
echo   Preparing Python 3.12 and the kit's libraries (the first time takes a minute or two)...
uv run --quiet --python 3.12 --script "%~dp0aiguard_kit.py" install
if errorlevel 1 (
  echo.
  echo   Install failed. The message above says why.
  pause
  exit /b 1
)
echo.
echo   Opening the console in your browser. It runs in the background, like the desktop shortcut:
echo   use Quit in the console to stop it. This window closes by itself.
start "" "%SystemRoot%\System32\conhost.exe" --headless "%USERPROFILE%\.aiguard-se-kit\app\aiguard-kit.cmd" gui --background
timeout /t 5 >nul
exit /b 0
