cd /D "%~dp0..\src"
RMDIR /S /Q ..\publish
dotnet publish -c Release  -r win-x64 -o ..\publish