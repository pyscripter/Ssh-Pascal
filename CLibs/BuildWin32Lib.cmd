echo -------------  Building zlib  ---------------------
pushd zlib
git clean -d -f -x
cmake -G "Visual Studio 16 2019" -A Win32 -DCMAKE_INSTALL_PREFIX=./ZlibBin --build .
cmake --build . --target install --config "Release"
cd ZLibBin\lib
del zlib.lib
ren zlibstatic.lib zlib.lib
popd
echo -----------  Building libssh2  ------------------
pushd libssh2
git clean -d -f -x
cmake -G "Visual Studio 16 2019" -A Win32 -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DENABLE_ZLIB_COMPRESSION=ON -DCRYPTO_BACKEND=WinCNG -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=./WinX32 --build .
cmake --build . --target install --config "Release"
popd
copy libssh2\WinX32\Bin\libssh2.dll ..\Bin\Win32