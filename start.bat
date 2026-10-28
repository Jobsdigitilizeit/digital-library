@echo off
setlocal
cd /d "%~dp0"
title AI Digital Library

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed. Install the LTS version from https://nodejs.org then run this file again.
  pause
  exit /b 1
)

if not exist node_modules (
  echo Installing dependencies - first run only, this can take a few minutes...
  call npm install
  if errorlevel 1 (
    echo Install failed. Check your internet connection and run this file again.
    pause
    exit /b 1
  )
)

if not exist .env.local (
  echo GEMINI_API_KEY=> .env.local
  echo.>> .env.local
)

echo.
echo Starting the system. Keep this window open.
echo Open  http://localhost:3001  in your browser  (use "localhost", not 127.0.0.1 or an IP address).
echo.
start "" http://localhost:3001
call npm run dev
pause
