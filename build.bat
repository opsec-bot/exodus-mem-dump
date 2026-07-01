@echo off

call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1

cl /O2 /std:c++17 /EHsc /Fe:build\seed_hunter.exe src\seed_hunter.cpp /link dbghelp.lib psapi.lib

pause