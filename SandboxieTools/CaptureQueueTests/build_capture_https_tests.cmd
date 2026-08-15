@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "%~dp0"
cl /nologo /W4 /WX /DUNICODE /D_UNICODE CaptureHttpsTests.c ..\..\Sandboxie\core\drv\capture_https.c ..\..\Sandboxie\core\drv\capture_filter.c
exit /b %ERRORLEVEL%
