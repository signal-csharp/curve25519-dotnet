REM MSBuild EXE path
SET MSBuildPath="C:\Program Files (x86)\MSBuild\14.0\Bin\MSBuild.exe"
set StagingPath=deploy\staging

REM change to the source root directory
pushd ..


REM ======================= clean =======================================

REM ensure any previously created package is deleted
del deploy\*.nupkg

REM ======================= build =======================================

REM build AnyCPU
%MSBuildPath% curve25519-dotnet\curve25519-dotnet.csproj /property:Configuration=Release

REM create NuGet package
pushd deploy
nuget pack ..\curve25519-dotnet\curve25519-dotnet.nuspec  -outputdirectory .
popd


REM ============================ done ==================================


REM go back to the build dir
popd
