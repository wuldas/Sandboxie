@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "%~dp0"
set "VCPKG_INST=D:\vcpkg\installed\x64-windows"
cl /nologo /W4 /WX /DUNICODE /D_UNICODE /I..\SbieCapture /I%VCPKG_INST%\include HttpsMitmTests.c ..\SbieCapture\capture_ca.c ..\SbieCapture\https_mitm.c ..\SbieCapture\http11.c ..\SbieCapture\hpack.c ..\SbieCapture\http2.c ..\SbieCapture\redact.c ..\SbieCapture\har.c ..\SbieCapture\capture_broker.c ..\SbieCapture\capture_https_broker.c ..\SbieCapture\pcapng.c ..\..\Sandboxie\core\dll\crypt_https_trust.c /link /LIBPATH:%VCPKG_INST%\lib libssl.lib libcrypto.lib ws2_32.lib crypt32.lib advapi32.lib user32.lib bcrypt.lib ncrypt.lib
if errorlevel 1 exit /b 1
copy /y %VCPKG_INST%\bin\libssl-3-x64.dll . >nul
copy /y %VCPKG_INST%\bin\libcrypto-3-x64.dll . >nul
exit /b 0
