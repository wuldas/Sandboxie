@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "%~dp0"
cl /nologo /W4 /WX /DUNICODE /D_UNICODE /I..\SbieCapture HarTests.c ..\SbieCapture\http11.c ..\SbieCapture\redact.c ..\SbieCapture\har.c
exit /b %ERRORLEVEL%
