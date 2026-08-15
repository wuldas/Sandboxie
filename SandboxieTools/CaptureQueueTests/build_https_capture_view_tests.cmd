@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "%~dp0"
cl /nologo /W4 /WX /DUNICODE /D_UNICODE HttpsCaptureViewTests.c ..\..\SandboxiePlus\SandMan\Views\https_capture_model.c
exit /b %ERRORLEVEL%
