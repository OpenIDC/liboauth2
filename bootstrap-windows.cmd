@ECHO Requires git installed and an account on github
@SET STARTTIME=%time% 

git submodule update --init --recursive

if "%VSINSTALLDIR%"=="" call "C:\Progra~2\Micros~3\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

if exist "%VCPKG_HOME%\bootstrap-vcpkg.bat" goto VCPKG_COMPLETE

@ECHO cd to vcpkg
cd vcpkg
call bootstrap-vcpkg.bat

.\vcpkg install pcre:x64-windows
.\vcpkg install openssl:x64-windows
.\vcpkg install curl:x64-windows
.\vcpkg install jansson:x64-windows

@REM Please Note:  The paths to the vcpkg builds are set in the VS project files.  I couldn't get the 32bit and 64 bit to work correctly.  

cd..

:VCPKG_COMPLETE

@ECHO Over changes to cjose and mod_auth_openidc so they compile on windows
xcopy changes\*.* /r /q /y /s

@ECHO Downloading Apache http x64 zip files.

if exist ".\target\httpd-2.4.51-win64-VS16" goto APACHE_DOWNLOADED

powershell .\download.ps1

:APACHE_DOWNLOADED

call build.cmd

@ECHO Start Time %STARTTIME%
@ECHO Stop Time %time%
