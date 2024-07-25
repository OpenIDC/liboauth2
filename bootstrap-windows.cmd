@ECHO Requires git installed and an account on github
@SET STARTTIME=%time% 

SET /P TRUSTSUBMODULE=Do you want to reset all submodules? (Choose Y first time you run or retest) (Y/[N])?
IF /I "%TRUSTSUBMODULE%" NEQ "Y" GOTO SKIP_SUBMODULE

REM Remove all untracked content of the module
git submodule foreach --recursive git clean -xfd
REM Force all changed track files to be default values.
git submodule foreach --recursive git reset --hard
REM Update to the Latest and greatest in the submodule
git submodule update --recursive --remote

@ECHO Copy over changes to cjose and mod_auth_openidc so they compile on windows
xcopy changes\*.* /r /q /y /s

:SKIP_SUBMODULE

@ECHO Checking for VS2019 Enterprise
if "%VSINSTALLDIR%"=="" call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvarsx86_amd64.bat"

@ECHO Checking for VS2019 Professional
if "%VSINSTALLDIR%"=="" call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvarsx86_amd64.bat"

set ERROR_CODE=0

@REM ==== START VALIDATION ====
if not "%VCPKG_HOME%"=="" goto OK_VCPKG_HOME

SET BASE_DIR=%cd%
set VCPKG_HOME=%BASE_DIR%/vcpkg
mkdir "%VCPKG_HOME%"

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
if not exist "%VCPKG_HOME%/installed/x64-windows/include/openssl"     %VCPKG_CMD% install openssl --triplet x64-windows
if not exist "%VCPKG_HOME%/installed/x64-windows/include/curl"     %VCPKG_CMD% install curl --triplet x64-windows
if not exist "%VCPKG_HOME%/installed/x64-windows/include/jansson" %VCPKG_CMD% install jansson --triplet x64-windows
if not exist "%VCPKG_HOME%/installed/x64-windows/include/pcre2"     %VCPKG_CMD% install pcre2 --triplet x64-windows

%VCPKG_CMD% integrate install 

goto continue

:error
echo ==== WE GOT AN ERROR ====
set ERROR_CODE=1
exit

:continue
@ECHO Downloading Apache http x64 zip files.

if exist ".\target\httpd-latest" goto APACHE_DOWNLOADED

powershell .\download.ps1

:APACHE_DOWNLOADED

call build.cmd

@ECHO Start Time %STARTTIME%
@ECHO Stop Time %time%

:END
