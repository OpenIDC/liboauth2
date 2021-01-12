call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

msbuild.exe "cjose/cjose.vcxproj" /p:Configuration=Release /p:Platform="x64"
msbuild.exe "liboauth2.vcxproj" /p:Configuration=Release /p:Platform="x64"

mkdir target
mkdir target\liboauth2
mkdir target\liboauth2\x64
mkdir target\liboauth2\x64\Release
mkdir target\liboauth2\x86
mkdir target\liboauth2\x86\Release
copy x64\Release\liboauth2.dll target\liboauth2\x64\Release\liboauth2.dll
copy win32\Release\liboauth2.dll target\liboauth2\x86\Release\liboauth2.dll

del target\liboauth2-1.4.0_1-win64-VS16.zip
del target\liboauth2-1.4.0_1-win32-VS16.zip

REM This next step is perplexing.  Something verifies the case of the dll that it is loading and libeay32.dll must be uppercase 
REM following the import statements. vcpkg creates a lower case dll, but the imports from the lib file have the dll name unppercase.
mkdir target\x64
del target\x64\LIBEAY32.dll
copy  vcpkg\installed\x64-windows\bin\libeay32.dll target\x64\LIBEAY32.dll

mkdir target\x86
del target\x86\LIBEAY32.dll
copy  vcpkg\installed\x86-windows\bin\libeay32.dll target\x86\LIBEAY32.dll

powershell Compress-Archive -Path target\x64\LIBEAY32.dll -DestinationPath target\liboauth2-1.4.0_1-win64-VS16.zip
powershell Compress-Archive -Path target\liboauth2\x64\Release\liboauth2.dll -Update -DestinationPath target\liboauth2-1.4.0_1-win64-VS16.zip

powershell Compress-Archive -Path target\x86\LIBEAY32.dll -DestinationPath target\mod_auth_openidc-2.4.0_3-win32-VS16.zip
powershell Compress-Archive -Path target\liboauth2\x86\Release\liboauth2.dll -Update -DestinationPath target\liboauth2-1.4.0_1-win32-VS16.zip