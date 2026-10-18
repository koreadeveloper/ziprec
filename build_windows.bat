@echo off
REM ziprec - Windows build script (MSVC)
REM Run from "x64 Native Tools Command Prompt for VS 2022":
REM   build_windows.bat
REM or with clang-cl if you have LLVM installed:
REM   clang-cl /O2 /MT src\*.c /Fe:ziprec.exe

where cl >NUL 2>&1
if errorlevel 1 (
  echo cl.exe not found. Open "x64 Native Tools Command Prompt" first,
  echo or install Visual Studio Build Tools.
  exit /b 1
)

cl /O2 /std:c11 /W3 /wd4996 /MT /Fe:ziprec.exe ^
   src\main.c src\zipfile.c src\crypto.c src\inflate.c src\gen.c ^
   src\engine.c src\ckpt.c src\export.c src\gpu.c

if errorlevel 0 (
  echo.
  echo Built ziprec.exe  -  run "ziprec.exe --selftest" to verify SHA-NI detection
)
