@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
"%MSBUILD%" "E:\QtProjects\SandboxEx\Sandboxie\core\dll\SboxDll.vcxproj" /p:Configuration=SbieRelease /p:Platform=x64 /p:SolutionDir=E:\QtProjects\SandboxEx\Sandboxie\ /v:minimal
exit /b %ERRORLEVEL%
