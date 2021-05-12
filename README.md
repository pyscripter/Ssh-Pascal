# Ssh-Pascal
Pascal Ssh library based on [libssh2](https://www.libssh2.org/). Libssh2 is a mature ssh library used by PHP (built-in), Rust and many other languages and applications.

## Features
- Extensive ssh features
  - Support for different authorization methods (publickey, password, agent, hostbased and keyboard-interactive)
  - Known host management.
  - Execution of commands on the host capturing stdout and stderr
  - Comprehensive sftp support
  - Port forwarding (currently only local)
  - scp support
- High-level pascal-friendly, interface-based wrapping of ssh functionality.
- Lower-level usage is possible.

## Installation
There are no components to install.  Just clone the repository and add the Source folder to your library path.

## Deployment
The libssh2.dll dynamic library should be deployed in the same directory as the executable. The Bin directory contains Win32 and Win64 binaries. 

## Documentation
Currently the best (only) way to learn how to use the library is to study the demos and the source code.

## Platform and FPC support
Currently only Delphi (versions with generics) and Windows 32-bit and 64-bit are supported
libssh2 is available on Linux, iOS, OSX, and other platforms.  So the library could be extended to provide support for such platforms.  Pull requests to provide compatibility with other platforms and/or FPC would be welcome.

## Limitations
- scp does not work with Windows hosts (Sftp does though).
- keyboard-interactive authorization does not work with Windows hosts (it reverts to password authorization).

## Credits
The C header translations draw from https://bitbucket.org/ZeljkoMarjanovic/libssh2-delphi
Copyright (c) 2010, Zeljko Marjanovic (MPL 1.1).  Everything else was written from scratch.
