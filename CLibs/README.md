## Instructions for generating the dynamic libraries from the latest sources

### Requirements
- [Git for Windows](https://git-scm.com/download/win) installed
- [Visual Studio](https://visualstudio.microsoft.com/) installed. [Community edition](https://visualstudio.microsoft.com/vs/community/) will do.
- Visual Studio includes [CMake](https://cmake.org/) but you need to make sure is accessible from the system path before executing the following steps.

### Steps
- Run CloneLibs.cmd to clone zlib and libssh2
- Run BuildWin64Lib to build libssh2.dll 64 bits. It will build the dll with the WinCng (bcrypt.dll part of the Windows system) backend and copy it to the Bin\Win64 directory
- Run BuildWin32Lib to build libssh2.dll 32 bits. It will build the dll with the WinCng (bcrypt.dll part of the Windows system) backend and copy it to the Bin\Win32 directory
