# Ssh-pascal
Pascal Ssh library based on [libssh2](https://www.libssh2.org/).  Libssh2 is a mature ssh library used by PHP (built-in), Rust and many other languages and applications.

## Features
- High-level pascal-friendly, interface-based wrapping of ssh functionality.
- Allows lower-level usage.
- Extensive ssh features
    - Supports different authorization methods (publickey, password, agent, hostbased and keyboard-interactive)
    - Execution of commads on the host capturing stdout and stderr
    - Comprehensive sftp support
    - Port forwarding (currently only local)
    - scp support

## Deployment
The following dynamic libraries should be deployed in the same directory as the executable.
- libssh2.dll
- libcrypto-1_1.dll
- libssl-1_1.dll

Win32 and Win64 binaries can be found in the Bin directory.  Updated Windows binaries can be foudn at the [PHP repository](https://windows.php.net/downloads/php-sdk/deps/).

## Documentation
Currently the best (only) way to learn how to use the library is to study the demos and the source code.

## Limitations
- scp does not work with Windows hosts (Sftp does though).
- keyboard-interactive authorization does not work with Windows hosts (it reverts to password authorization).

## Credits
The C header translation draw from https://bitbucket.org/ZeljkoMarjanovic/libssh2-delphi
Copyright (c) 2010, Zeljko Marjanovic (MPL 1.1).  Everything else was written from scratch.
