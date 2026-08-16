@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
"%MSBUILD%" "E:\QtProjects\SandboxEx\SandboxieTools\SbieCapture\SbieCapture.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:minimal
exit /b %ERRORLEVEL%
