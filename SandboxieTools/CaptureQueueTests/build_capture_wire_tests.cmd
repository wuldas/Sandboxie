@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "%~dp0"
cl /nologo /W4 /WX /wd4201 /DUNICODE /D_UNICODE /EHsc CaptureWireTests.cpp
exit /b %ERRORLEVEL%
