Set CurrentDIR=%CD%
echo -------------  Building zlib  ---------------------
pushd zlib
git clean -d -f -x
cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DCMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH=OFF -DCMAKE_INSTALL_PREFIX=./ZlibBin .
cmake --build . --target install --config "Release"
cd ZLibBin\lib
del zlib.lib
ren zlibstatic.lib zlib.lib
popd
echo -----------  Building libssh2  ------------------
pushd libssh2
git clean -d -f -x
cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DCMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DENABLE_ZLIB_COMPRESSION=ON -DCRYPTO_BACKEND=WinCNG -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=./WinX64 -DZLIB_LIBRARY=%CurrentDIR%/zlib/ZlibBin/lib/zlib.lib -DZLIB_INCLUDE_DIR=%CurrentDIR%/zlib/ZlibBin/Include" .
cmake --build . --target install --config "Release"
popd
copy libssh2\WinX64\Bin\libssh2.dll ..\Bin\Win64    