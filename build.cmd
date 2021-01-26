call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

msbuild.exe "cjose/cjose.vcxproj" /p:Configuration=Release /p:Platform="x64"
msbuild.exe "liboauth2.vcxproj" /p:Configuration=Release /p:Platform="x64"

mkdir target
mkdir target\liboauth2
mkdir target\liboauth2\x64
mkdir target\liboauth2\x64\Release
copy x64\Release\liboauth2.lib target\liboauth2\x64\Release\liboauth2.lib
