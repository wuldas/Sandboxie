@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "%~dp0"
cl /nologo /W4 /WX /DUNICODE /D_UNICODE /I..\SbieCapture FirefoxTrustTests.c ..\SbieCapture\firefox_trust.c /link advapi32.lib
if errorlevel 1 exit /b 1
exit /b 0
