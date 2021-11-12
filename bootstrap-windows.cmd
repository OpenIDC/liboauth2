@ECHO Requires git installed and an account on github
@SET STARTTIME=%time% 

git submodule update --init --recursive

@ECHO Checking for VS2019 Enterprise
if "%VSINSTALLDIR%"=="" call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsx86_amd64.bat"

@ECHO Checking for VS2019 Professional
if "%VSINSTALLDIR%"=="" call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsx86_amd64.bat"

set ERROR_CODE=0

@REM ==== START VALIDATION ====
if not "%VCPKG_HOME%"=="" goto OK_VCPKG_HOME
echo The VCPKG_HOME environment variable is not defined correctly >&2
echo This environment variable is needed to run this program >&2
goto error

echo The VCPKG_HOME environment variable exists
:OK_VCPKG_HOME
@REM Check if vcpkg is checked out, if not then check it out
if exist "%VCPKG_HOME%\bootstrap-vcpkg.bat" goto VCPKG_GIT
echo The VCPKG_HOME environment variable exists but the code is not checked out, so it will be checked out >&2
git clone https://github.com/microsoft/vcpkg.git %VCPKG_HOME%

:VCPKG_GIT
REM echo The VCPKG_HOME git project is checked out
set VCPKG_CMD="%VCPKG_HOME%/vcpkg.exe"
if exist "%VCPKG_CMD%" goto VCPKG_BUILT
call "%VCPKG_HOME%\bootstrap-vcpkg.bat"

:VCPKG_BUILT
@REM ==== Checking if libraries are built ====
REM echo The %VCPKG_CMD% has already been built
if not exist "%VCPKG_HOME%/installed/x64-windows/include/pcre"       %VCPKG_CMD% install pcre --triplet x64-windows
if not exist "%VCPKG_HOME%/installed/x64-windows/include/openssl"     %VCPKG_CMD% install openssl --triplet x64-windows
if not exist "%VCPKG_HOME%/installed/x64-windows/include/curl"     %VCPKG_CMD% install curl --triplet x64-windows
if not exist "%VCPKG_HOME%/installed/x64-windows/include/jansson" %VCPKG_CMD% install jansson --triplet x64-windows

%VCPKG_CMD% integrate install 

:error
set ERROR_CODE=1

@ECHO Over changes to cjose and mod_auth_openidc so they compile on windows
xcopy changes\*.* /r /q /y /s

pause

@ECHO Downloading Apache http x64 zip files.

if exist ".\target\httpd-2.4.51-win64-VS16" goto APACHE_DOWNLOADED

powershell .\download.ps1

pause

:APACHE_DOWNLOADED

call build.cmd

@ECHO Start Time %STARTTIME%
@ECHO Stop Time %time%

:END
