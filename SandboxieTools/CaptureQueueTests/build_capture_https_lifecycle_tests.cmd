@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "%~dp0"
cl /nologo /W4 /WX /DUNICODE /D_UNICODE CaptureHttpsLifecycleTests.c ..\..\Sandboxie\core\svc\capture_https_lifecycle.c
exit /b %ERRORLEVEL%
