@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "%~dp0"
cl /nologo /W4 /WX /EHsc /utf-8 /DUNICODE /D_UNICODE run_boxed_silent.cpp /link /LIBPATH:"E:\QtProjects\SandboxEx\Sandboxie\Bin\x64\SbieRelease" SbieDll.lib
exit /b %ERRORLEVEL%
