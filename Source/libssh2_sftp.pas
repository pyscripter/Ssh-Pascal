{ **
  *  Delphi/Pascal Wrapper around the library "libssh2"
  *    Base repository:
  *      https://bitbucket.org/ZeljkoMarjanovic/libssh2-delphi
  *        Contributors:
  *          https://bitbucket.org/jeroenp/libssh2-delphi
  *          https://bitbucket.org/VadimLV/libssh2_delphi
  *          https://github.com/pult/libssh2_delphi/
  * }
unit libssh2_sftp;

// **zm ** translated to pascal

interface

uses
  WinApi.Windows,
  libssh2;

{+// Copyright (c) 2004-2008, Sara Golemon <sarag@libssh2.org> }
{-* All rights reserved. }
{-* }
{-* Redistribution and use in source and binary forms, }
{-* with or without modification, are permitted provided }
{-* that the following conditions are met: }
{-* }
{-* Redistributions of source code must retain the above }
{-* copyright notice, this list of conditions and the }
{-* following disclaimer. }
{-* }
{-* Redistributions in binary form must reproduce the above }
{-* copyright notice, this list of conditions and the following }
{-* disclaimer in the documentation and/or other materials }
{-* provided with the distribution. }
{-* }
{-* Neither the name of the copyright holder nor the names }
{-* of any other contributors may be used to endorse or }
{-* promote products derived from this software without }
{-* specific prior written permission. }
{-* }
{-* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND }
{-* CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, }
{-* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES }
{-* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE }
{-* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR }
{-* CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, }
{-* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, }
{-* BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR }
{-* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS }
{-* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, }
{-* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING }
{-* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE }
{-* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY }
{-* OF SUCH DAMAGE. }
{= }

{+// Note: Version 6 was documented at the time of writing }
{-* However it was marked as "DO NOT IMPLEMENT" due to pending changes }
{-* }
{-* Let's start with Version 3 (The version found in OpenSSH) and go from there }
{= }
const
  LIBSSH2_SFTP_VERSION = 3;

  LIBSSH2_SFTP_PACKET_MAXLEN = 40000;

type
  _LIBSSH2_SFTP = record end;
  LIBSSH2_SFTP_HANDLE = record end;
  _LIBSSH2_SFTP_HANDLE = LIBSSH2_SFTP_HANDLE;
  PLIBSSH2_SFTP = ^_LIBSSH2_SFTP;
  PLIBSSH2_SFTP_HANDLE = ^LIBSSH2_SFTP_HANDLE;

const
  LIBSSH2_SFTP_OPENFILE = 0;
  LIBSSH2_SFTP_OPENDIR_ = 1;
{+// Flags for rename_ex()*/ }
  LIBSSH2_SFTP_RENAME_OVERWRITE = $00000001;
  LIBSSH2_SFTP_RENAME_ATOMIC = $00000002;
  LIBSSH2_SFTP_RENAME_NATIVE = $00000004;
{+// Flags for stat_ex()*/ }
  LIBSSH2_SFTP_STAT_ = 0;
  LIBSSH2_SFTP_LSTAT_ = 1;
  LIBSSH2_SFTP_SETSTAT_ = 2;
{+// Flags for symlink_ex()*/ }
  LIBSSH2_SFTP_SYMLINK_ = 0;
  LIBSSH2_SFTP_READLINK_ = 1;
  LIBSSH2_SFTP_REALPATH_ = 2;
{+// SFTP attribute flag bits*/ }
  LIBSSH2_SFTP_ATTR_SIZE = $00000001;
  LIBSSH2_SFTP_ATTR_UIDGID = $00000002;
  LIBSSH2_SFTP_ATTR_PERMISSIONS = $00000004;
  LIBSSH2_SFTP_ATTR_ACMODTIME = $00000008;
  LIBSSH2_SFTP_ATTR_EXTENDED = $80000000;

{+// If flags & ATTR_* bit is set, then the value in this struct will be }
{-* meaningful Otherwise it should be ignored }
{= }
type
  _LIBSSH2_SFTP_ATTRIBUTES = record
    flags: LongWord;
    filesize: LIBSSH2_UINT64_T;
    uid, gid: LongWord;
    permissions: LongWord;
    atime, mtime: LongWord;
  end;

  LIBSSH2_SFTP_ATTRIBUTES  =  _LIBSSH2_SFTP_ATTRIBUTES;
  PLIBSSH2_SFTP_ATTRIBUTES  =  ^_LIBSSH2_SFTP_ATTRIBUTES;

  _LIBSSH2_SFTP_STATVFS = record
    f_bsize,    {/* file system block size */}
    f_frsize,   {/* fragment size */}
    f_blocks,   {/* size of fs in f_frsize units */}
    f_bfree,    {/* # free blocks */}
    f_bavail,   {/* # free blocks for non-root */}
    f_files,    {/* # inodes */}
    f_ffree,    {/* # free inodes */}
    f_favail,   {/* # free inodes for non-root */}
    f_fsid,     {/* file system ID */}
    f_flag,     {/* mount flags */}
    f_namemax: libssh2_uint64_t;  {/* maximum filename length */}
  end;
  TLIBSSH2_SFTP_STATVFS = _LIBSSH2_SFTP_STATVFS;
  PLIBSSH2_SFTP_STATVFS = ^TLIBSSH2_SFTP_STATVFS;

const
{+// SFTP filetypes*/ }
  LIBSSH2_SFTP_TYPE_REGULAR = 1;
  LIBSSH2_SFTP_TYPE_DIRECTORY = 2;
  LIBSSH2_SFTP_TYPE_SYMLINK = 3;
  LIBSSH2_SFTP_TYPE_SPECIAL = 4;
  LIBSSH2_SFTP_TYPE_UNKNOWN = 5;
  LIBSSH2_SFTP_TYPE_SOCKET = 6;
  LIBSSH2_SFTP_TYPE_CHAR_DEVICE = 7;
  LIBSSH2_SFTP_TYPE_BLOCK_DEVICE = 8;
  LIBSSH2_SFTP_TYPE_FIFO = 9;

{+// }
{-* Reproduce the POSIX file modes here for systems that are not POSIX }
{-* compliant. }
{-* }
{-* These is used in "permissions" of "struct _LIBSSH2_SFTP_ATTRIBUTES" }
{= }
{+// File type*/ }

  LIBSSH2_SFTP_S_IFMT = 61440; {/* type of file mask*/}
  LIBSSH2_SFTP_S_IFIFO = 4096; {/* named pipe (fifo)*/}
  LIBSSH2_SFTP_S_IFCHR = 8192; {/* character special*/}
  LIBSSH2_SFTP_S_IFDIR = 16384; {/* directory*/}
  LIBSSH2_SFTP_S_IFBLK = 24576; {/* block special*/}
  LIBSSH2_SFTP_S_IFREG = 32768; {/* regular*/}
  LIBSSH2_SFTP_S_IFLNK = 40960; {/* symbolic link*/}
  LIBSSH2_SFTP_S_IFSOCK = 49152; {/* socket*/}

{+// File mode*/ }
{+// Read, write, execute/search by owner*/ }
  LIBSSH2_SFTP_S_IRWXU = 448; {/* RWX mask for owner*/}
  LIBSSH2_SFTP_S_IRUSR = 256; {/* R for owner*/}
  LIBSSH2_SFTP_S_IWUSR = 128; {/* W for owner*/}
  LIBSSH2_SFTP_S_IXUSR = 64; {/* X for owner*/}
{+// Read, write, execute/search by group*/ }
  LIBSSH2_SFTP_S_IRWXG = 56; {/* RWX mask for group*/}
  LIBSSH2_SFTP_S_IRGRP = 32; {/* R for group*/}
  LIBSSH2_SFTP_S_IWGRP = 16; {/* W for group*/}
  LIBSSH2_SFTP_S_IXGRP = 8; {/* X for group*/}
{+// Read, write, execute/search by others*/ }
  LIBSSH2_SFTP_S_IRWXO = 7; {/* RWX mask for other*/}
  LIBSSH2_SFTP_S_IROTH = 4; {/* R for other*/}
  LIBSSH2_SFTP_S_IWOTH = 2; {/* W for other*/}
  LIBSSH2_SFTP_S_IXOTH = 1; {/* X for other*/}

// ** zm: setuid/gid i sticky bit nisu definisani u originalnom header-u
  LIBSSH2_SFTP_S_ISUID = 2048; // set UID bit
  LIBSSH2_SFTP_S_ISGID = 1024; // set-group-ID bit
  LIBSSH2_SFTP_S_ISVTX = 512;  // sticky bit

{+// SFTP File Transfer Flags -- (e.g. flags parameter to sftp_open()) }
{=* Danger will robinson... APPEND doesn't have any effect on OpenSSH servers }
  LIBSSH2_FXF_READ = $00000001;
  LIBSSH2_FXF_WRITE = $00000002;
  LIBSSH2_FXF_APPEND = $00000004;
  LIBSSH2_FXF_CREAT = $00000008;
  LIBSSH2_FXF_TRUNC = $00000010;
  LIBSSH2_FXF_EXCL = $00000020;

{+// SFTP Status Codes (returned by libssh2_sftp_last_error() )*/ }
  LIBSSH2_FX_OK = 0;
  LIBSSH2_FX_EOF = 1;
  LIBSSH2_FX_NO_SUCH_FILE = 2;
  LIBSSH2_FX_PERMISSION_DENIED = 3;
  LIBSSH2_FX_FAILURE = 4;
  LIBSSH2_FX_BAD_MESSAGE = 5;
  LIBSSH2_FX_NO_CONNECTION = 6;
  LIBSSH2_FX_CONNECTION_LOST = 7;
  LIBSSH2_FX_OP_UNSUPPORTED = 8;
  LIBSSH2_FX_INVALID_HANDLE = 9;
  LIBSSH2_FX_NO_SUCH_PATH = 10;
  LIBSSH2_FX_FILE_ALREADY_EXISTS = 11;
  LIBSSH2_FX_WRITE_PROTECT = 12;
  LIBSSH2_FX_NO_MEDIA = 13;
  LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM = 14;
  LIBSSH2_FX_QUOTA_EXCEEDED = 15;
//  LIBSSH2_FX_UNKNOWN_PRINCIPLE = 16; {/* Initial mis-spelling*/}
  LIBSSH2_FX_UNKNOWN_PRINCIPAL = 16;
//  LIBSSH2_FX_LOCK_CONFlICT = 17; {/* Initial mis-spelling*/}
  LIBSSH2_FX_LOCK_CONFLICT = 17;
  LIBSSH2_FX_DIR_NOT_EMPTY = 18;
  LIBSSH2_FX_NOT_A_DIRECTORY = 19;
  LIBSSH2_FX_INVALID_FILENAME = 20;
  LIBSSH2_FX_LINK_LOOP = 21;

{+// Returned by any function that would block during a read/write opperation*/ }
  LIBSSH2SFTP_EAGAIN = LIBSSH2_ERROR_EAGAIN;
{+// SFTP API*/ }

function libssh2_sftp_init(session: PLIBSSH2_SESSION): PLIBSSH2_SFTP; cdecl;

function libssh2_sftp_shutdown(sftp: PLIBSSH2_SFTP): Integer; cdecl;

function libssh2_sftp_last_error(sftp: PLIBSSH2_SFTP): ULong; cdecl;

function libssh2_sftp_get_channel(sftp: PLIBSSH2_SFTP):PLIBSSH2_CHANNEL; cdecl;

{+// File / Directory Ops*/ }

function libssh2_sftp_open_ex(sftp: PLIBSSH2_SFTP;
                              const filename: PAnsiChar;
                              filename_len: UInt;
                              flags: ULong;
                              mode: LongInt;
                              open_type: Integer): PLIBSSH2_SFTP_HANDLE; cdecl;

function libssh2_sftp_open(sftp: PLIBSSH2_SFTP;
                           const filename: PAnsiChar;
                           flags: ULong;
                           mode: LongInt): PLIBSSH2_SFTP_HANDLE; inline;

function libssh2_sftp_opendir(sftp: PLIBSSH2_SFTP;
                              const path: PAnsiChar): PLIBSSH2_SFTP_HANDLE; inline;

function libssh2_sftp_read(handle: PLIBSSH2_SFTP_HANDLE;
                           buffer: PAnsiChar;
                           buffer_maxlen: size_t): ssize_t; cdecl;

function libssh2_sftp_readdir_ex(handle: PLIBSSH2_SFTP_HANDLE;
                                 buffer: PAnsiChar;
                                 buffer_maxlen: size_t;
                                 longentry: PAnsiChar;
                                 longentry_maxlen: size_t;
                                 attrs: PLIBSSH2_SFTP_ATTRIBUTES): Integer; cdecl;

function libssh2_sftp_readdir(handle: PLIBSSH2_SFTP_HANDLE;
                              buffer: PAnsiChar;
                              buffer_maxlen: size_t;  attrs: PLIBSSH2_SFTP_ATTRIBUTES): Integer; inline;

function libssh2_sftp_write(handle: PLIBSSH2_SFTP_HANDLE;
                            const buffer: PAnsiChar;
                            count: size_t): ssize_t; cdecl;

function libssh2_sftp_close_handle(handle: PLIBSSH2_SFTP_HANDLE): Integer; cdecl;

function libssh2_sftp_close(handle: PLIBSSH2_SFTP_HANDLE): Integer; inline;

function libssh2_sftp_closedir(handle: PLIBSSH2_SFTP_HANDLE): Integer; inline;

procedure libssh2_sftp_seek(handle: PLIBSSH2_SFTP_HANDLE;
                           offset: size_t); cdecl;

procedure libssh2_sftp_seek64(handle: PLIBSSH2_SFTP_HANDLE;
                             offset: LIBSSH2_UINT64_T); cdecl;

procedure libssh2_sftp_rewind(handle: PLIBSSH2_SFTP_HANDLE); inline;

function libssh2_sftp_tell(handle: PLIBSSH2_SFTP_HANDLE): UInt; cdecl;

function libssh2_sftp_tell64(handle: PLIBSSH2_SFTP_HANDLE): UInt64; cdecl;

function libssh2_sftp_fstat_ex(handle: PLIBSSH2_SFTP_HANDLE;
                               var attrs: LIBSSH2_SFTP_ATTRIBUTES;
                               setstat: Integer): Integer; cdecl;

function libssh2_sftp_fstat(handle: PLIBSSH2_SFTP_HANDLE;
                            var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer; inline;

function libssh2_sftp_fsetstat(handle: PLIBSSH2_SFTP_HANDLE;
                               var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer; inline;

{+// Miscellaneous Ops*/ }

function libssh2_sftp_rename_ex(sftp: PLIBSSH2_SFTP;
                                const source_filename: PAnsiChar;
                                srouce_filename_len: UInt;
                                const dest_filename: PAnsiChar;
                                dest_filename_len: UInt;
                                flags: LongInt): Integer; cdecl;

function libssh2_sftp_rename(sftp: PLIBSSH2_SFTP;
                             const source_filename: PAnsiChar;
                             const dest_filename: PAnsiChar): Integer; inline;

function libssh2_sftp_unlink_ex(sftp: PLIBSSH2_SFTP;
                                const filename: PAnsiChar;
                                filename_len: UInt): Integer; cdecl;

function libssh2_sftp_unlink(sftp: PLIBSSH2_SFTP;
                             const filename: PAnsiChar): Integer; inline;

function libssh2_sftp_fstatvfs(handle: PLIBSSH2_SFTP_HANDLE;
                                      var st: TLIBSSH2_SFTP_STATVFS): Integer; cdecl;

function libssh2_sftp_statvfs(sftp: PLIBSSH2_SFTP;
                              const path: PAnsiChar;
                              path_len: size_t;
                              var st: TLIBSSH2_SFTP_STATVFS): Integer; cdecl;

function libssh2_sftp_mkdir_ex(sftp: PLIBSSH2_SFTP;
                               const path: PAnsiChar;
                               path_len: UInt;
                               mode: LongInt): Integer; cdecl;

function libssh2_sftp_mkdir(sftp: PLIBSSH2_SFTP;
                            const path: PAnsiChar;
                            mode: LongInt): Integer; inline;

function libssh2_sftp_rmdir_ex(sftp: PLIBSSH2_SFTP;
                               const path: PAnsiChar;
                               path_len: UInt): Integer; cdecl;

function libssh2_sftp_rmdir(sftp: PLIBSSH2_SFTP;
                            const path: PAnsiChar): Integer; inline;

function libssh2_sftp_stat_ex(sftp: PLIBSSH2_SFTP;
                              const path: PAnsiChar;
                              path_len: UInt;
                              stat_type: Integer;
                              var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer; cdecl;

function libssh2_sftp_stat(sftp: PLIBSSH2_SFTP;
                           const path: PAnsiChar;
                           var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer; inline;

function libssh2_sftp_lstat(sftp: PLIBSSH2_SFTP;
                            const path: PAnsiChar;
                            var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer; inline;

function libssh2_sftp_setstat(sftp: PLIBSSH2_SFTP;
                              const path: PAnsiChar;
                              var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer; inline;

function libssh2_sftp_symlink_ex(sftp: PLIBSSH2_SFTP;
                                 const path: PAnsiChar;
                                 path_len: UInt;
                                 target: PAnsiChar;
                                 target_len: UInt;
                                 link_type: Integer): Integer; cdecl;

function libssh2_sftp_symlink(sftp: PLIBSSH2_SFTP;
                              const orig: PAnsiChar;
                              linkpath: PAnsiChar): Integer; inline;

function  libssh2_sftp_readlink(sftp: PLIBSSH2_SFTP;
                                const path: PAnsiChar;
                                target: PAnsiChar;
                                maxlen: UInt): Integer; inline;

function  libssh2_sftp_realpath(sftp: PLIBSSH2_SFTP;
                                const path: PAnsiChar;
                                target: PAnsiChar;
                                maxlen: UInt): Integer; inline;

implementation

{$WARN SYMBOL_PLATFORM OFF} // W002

function libssh2_sftp_init; external libssh2_name delayed;
function libssh2_sftp_shutdown; external libssh2_name delayed;
function libssh2_sftp_last_error; external libssh2_name delayed;
function libssh2_sftp_get_channel; external libssh2_name delayed;
function libssh2_sftp_open_ex; external libssh2_name delayed;
function libssh2_sftp_read; external libssh2_name delayed;
function libssh2_sftp_readdir_ex; external libssh2_name delayed;
function libssh2_sftp_write; external libssh2_name delayed;
function libssh2_sftp_close_handle; external libssh2_name delayed;
procedure libssh2_sftp_seek; external libssh2_name delayed;
procedure libssh2_sftp_seek64; external libssh2_name delayed;
function libssh2_sftp_tell; external libssh2_name delayed;
function libssh2_sftp_tell64; external libssh2_name delayed;
function libssh2_sftp_fstat_ex; external libssh2_name delayed;
function libssh2_sftp_rename_ex; external libssh2_name delayed;
function libssh2_sftp_unlink_ex; external libssh2_name delayed;
function libssh2_sftp_fstatvfs; external libssh2_name delayed;
function libssh2_sftp_statvfs; external libssh2_name delayed;
function libssh2_sftp_mkdir_ex; external libssh2_name delayed;
function libssh2_sftp_rmdir_ex; external libssh2_name delayed;
function libssh2_sftp_stat_ex; external libssh2_name delayed;
function libssh2_sftp_symlink_ex; external libssh2_name delayed;

function libssh2_sftp_open(sftp: PLIBSSH2_SFTP; const filename: PAnsiChar; flags: ULong; mode: LongInt): PLIBSSH2_SFTP_HANDLE;
begin
  Result := libssh2_sftp_open_ex(sftp, filename, Length(filename), flags, mode, LIBSSH2_SFTP_OPENFILE);
end;

function libssh2_sftp_opendir(sftp: PLIBSSH2_SFTP; const path: PAnsiChar): PLIBSSH2_SFTP_HANDLE;
begin
  Result := libssh2_sftp_open_ex(sftp, path, Length(path), 0, 0, LIBSSH2_SFTP_OPENDIR_);
end;

function libssh2_sftp_readdir(handle: PLIBSSH2_SFTP_HANDLE; buffer: PAnsiChar; buffer_maxlen: size_t; attrs: PLIBSSH2_SFTP_ATTRIBUTES): Integer;
begin
  Result := libssh2_sftp_readdir_ex(handle, buffer, buffer_maxlen, nil, 0, attrs);
end;

function libssh2_sftp_close(handle: PLIBSSH2_SFTP_HANDLE): Integer;
begin
  Result := libssh2_sftp_close_handle(handle);
end;

function libssh2_sftp_closedir(handle: PLIBSSH2_SFTP_HANDLE): Integer;
begin
  Result := libssh2_sftp_close_handle(handle);
end;

procedure libssh2_sftp_rewind(handle: PLIBSSH2_SFTP_HANDLE);
begin
  libssh2_sftp_seek64(handle, 0);
end;

function libssh2_sftp_fstat(handle: PLIBSSH2_SFTP_HANDLE; var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer; inline;
begin
  Result := libssh2_sftp_fstat_ex(handle, attrs, 0);
end;

function libssh2_sftp_fsetstat(handle: PLIBSSH2_SFTP_HANDLE; var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer; inline;
begin
  Result := libssh2_sftp_fstat_ex(handle, attrs, 1);
end;

function libssh2_sftp_rename(sftp: PLIBSSH2_SFTP; const source_filename: PAnsiChar; const dest_filename: PAnsiChar): Integer;
begin
  Result :=  libssh2_sftp_rename_ex(sftp,
    source_filename, Length(source_filename),
    dest_filename, Length(dest_filename),
    LIBSSH2_SFTP_RENAME_OVERWRITE or LIBSSH2_SFTP_RENAME_ATOMIC or LIBSSH2_SFTP_RENAME_NATIVE);
end;

function libssh2_sftp_unlink(sftp: PLIBSSH2_SFTP; const filename: PAnsiChar): Integer;
begin
  Result := libssh2_sftp_unlink_ex(sftp, filename, Length(filename));
end;

function libssh2_sftp_mkdir(sftp: PLIBSSH2_SFTP; const path: PAnsiChar; mode: LongInt): Integer;
begin
  Result :=  libssh2_sftp_mkdir_ex(sftp, path, Length(path), mode);
end;

function libssh2_sftp_rmdir(sftp: PLIBSSH2_SFTP; const path: PAnsiChar): Integer;
begin
  Result := libssh2_sftp_rmdir_ex(sftp, path, Length(path));
end;

function libssh2_sftp_stat(sftp: PLIBSSH2_SFTP; const path: PAnsiChar; var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer;
begin
  Result := libssh2_sftp_stat_ex(sftp, path, Length(path), LIBSSH2_SFTP_STAT_, attrs);
end;

function libssh2_sftp_lstat(sftp: PLIBSSH2_SFTP; const path: PAnsiChar; var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer;
begin
  Result := libssh2_sftp_stat_ex(sftp, path, Length(path), LIBSSH2_SFTP_LSTAT_, attrs);
end;

function libssh2_sftp_setstat(sftp: PLIBSSH2_SFTP; const path: PAnsiChar; var attrs: LIBSSH2_SFTP_ATTRIBUTES): Integer;
begin
  Result := libssh2_sftp_stat_ex(sftp, path, Length(path), LIBSSH2_SFTP_SETSTAT_, attrs);
end;

function libssh2_sftp_symlink(sftp: PLIBSSH2_SFTP; const orig: PAnsiChar; linkpath: PAnsiChar): Integer;
begin
  Result := libssh2_sftp_symlink_ex(sftp, orig, Length(orig), linkpath, Length(linkpath), LIBSSH2_SFTP_SYMLINK_);
end;

function  libssh2_sftp_readlink(sftp: PLIBSSH2_SFTP; const path: PAnsiChar; target: PAnsiChar; maxlen: UInt): Integer;
begin
  Result := libssh2_sftp_symlink_ex(sftp, path, Length(path), target, maxlen, LIBSSH2_SFTP_READLINK_);
end;

function  libssh2_sftp_realpath(sftp: PLIBSSH2_SFTP; const path: PAnsiChar; target: PAnsiChar; maxlen: UInt): Integer;
begin
  Result := libssh2_sftp_symlink_ex(sftp, path, Length(path), target, maxlen, LIBSSH2_SFTP_REALPATH_);
end;

end.
