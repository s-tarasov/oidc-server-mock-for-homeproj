pushd src
dotnet publish -c Release  -r win-x64 -o ..\publish --self-contained true
popd