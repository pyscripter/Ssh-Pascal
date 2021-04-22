## libssh.dll

Ssh-Pacal requires the presence of libssh2.dll in the same directory as the executable. This directory contains Win32 and Win64 binaries created from the latest sources (see the folder CLibs for details).  These dynamic libraries are compiled with the WinCng (bcrypt.dll part of the Windows system) cryptographic backend and have no further dependencies. 


## Alternative libssh.dll using OpenSSL

Alternative you can replace them with dynamic libraries that use the OpenSSL backend. If you do so you would need to deploy

- libssh2.dll
- libcrypto-1_1.dll
- libssl-1_1.dll

in the same directory as the executable.

Windows binaries for the above can be found at the [PHP repository](https://windows.php.net/downloads/php-sdk/deps/).
