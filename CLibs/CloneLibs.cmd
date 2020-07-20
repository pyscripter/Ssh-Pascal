git clone https://github.com/libssh2/libssh2.git
git clone https://github.com/madler/zlib.git
pushd libssh2
git apply --ignore-space-change --ignore-whitespace --whitespace=nowarn ..\zliblocation.diff
popd