unit SftpClient;
{

    Copyright (c) 2020 Kiriakos Vlahos (PyScripter)
    Delphi wrapper of libssh2 (https://www.libssh2.org/)

    The C header translation and the SFTP implementation draw from
    https://bitbucket.org/ZeljkoMarjanovic/libssh2-delphi
    Copyright (c) 2010, Zeljko Marjanovic (MPL 1.1)

    Released under the MIT Licence
}

interface

Uses
  WinApi.Windows,
  System.SysUtils,
  System.Classes,
  System.Generics.Collections,
  libssh2,
  libssh2_sftp,
  Ssh2Client;

type
  ESftpErr = class(Exception);
  TSFTPItemType = (sitUnknown, sitDirectory, sitFile, sitSymbolicLink,
    sitBlockDev, sitCharDev, sitFIFO, sitSocket);

  TSFTPStatData = record
  end;

  TSftpItem = record
    FileName: string;
    LongEntry: string;
    ItemType: TSFTPItemType;
    FileSize: UInt64;
    UID: UInt;
    GID: UInt;
    Permissions: TFilePermissions;
    LastAccessTime: TDateTime;          // UTC
    LastModificationTime: TDateTime;    // UTC
    Hidden: Boolean;
  end;

  TSftpItems = TArray<TSftpItem>;

  ISftpClient = interface
    ['{3F365360-444A-42B8-9FD3-AD9AAE497F60}']
    procedure SetBufferSize(Size: Int64);
    procedure SetTransferProgressCallback(Callback: TTransferProgressCallback);
    procedure Cancel;
    property BufferSize: Int64 write SetBufferSize;
    procedure RaiseLastSFTPError(Const Op: string);
    function SftpType(Name: string; FollowLink: Boolean = True): TSFTPItemType;
    function GetPathDelimiter: AnsiChar;
    function GetWindowsHost: Boolean;
    // Directories
    function GetCurrentDir: string;
    function CreateDir(const Dir: string; Permissions: TFilePermissions = FPDefault): Boolean;
    function ForceDirectories(Dir: string): Boolean;
    function RemoveDir(const Dir: string): Boolean;
    function DirectoryExists(const Directory: string; FollowLink: Boolean = True): Boolean;
    function ExcludeTrailingPathDelimiter(const S: string): string;
    function IncludeTrailingPathDelimiter(const S: string): string;
    function ExtractFileName(const FileName: string): string;
    function DirContent(const Dir: string): TSftpItems;
    // Files
    function FileExists(const FileName: string; FollowLink: Boolean = True): Boolean;
    function DeleteFile(const FileName: string): Boolean;
    function Rename(const OldName, NewName: string): Boolean;  // also works with directories
    function ExtractFilePath(const FileName: string): string;
    // Symbolic Links
    function RealPath(Name: string): string;
    function CreateSymLink(const Link, Target: string): Boolean;
    //Send and Receive
    procedure Receive(const RemoteFile: string; Stream: TStream); overload;
    procedure Receive(const RemoteFile, LocalFile: string; Overwrite:Boolean = True); overload;
    procedure Send(Stream: TStream; const RemoteFile: string;
      Overwrite: Boolean = True; Permissions: TFilePermissions = FPDefault); overload;
    procedure Send(const LocalFile, RemoteFile: string;
      Overwrite: Boolean = True; Permissions: TFilePermissions = FPDefault); overload;
    // Copy Files and Directories
    // Source can be a file or a directory and may include a file mask
    // Dest is either a file or a directory
    procedure CopyToHost(const Source, Dest: string; Recursive: Boolean = True;
      Overwrite: Boolean = True; Permissions: TFilePermissions = FPDefault); overload;
    procedure CopyFromHost(const Source, Dest: string; Recursive: Boolean = True;
      Overwrite: Boolean = True); overload;
    property WindowsHost: Boolean read GetWindowsHost;

    property PathDelimiter: AnsiChar read GetPathDelimiter;
    property CurrentDir: string read GetCurrentDir;
  end;

// Factory method
function CreateSftpClient(Session: ISshSession): ISftpClient;

implementation
Uses
  System.SysConst,
  System.Types,
  System.DateUtils,
  System.IOUtils,
  System.Masks,
  System.Generics.Defaults;

{$region Support stuff}
resourcestring
  Err_SftpInit = 'Could not initialize Sftp';
  Err_Sftp = 'Sftp error: %s (%d), on API "%s"';
  Err_FX_EOF = 'End of file';
  Err_FX_NO_SUCH_FILE = 'No such file';
  Err_FX_PERMISSION_DENIED = 'Permission denied';
  Err_FX_FAILURE = 'Failure';
  Err_FX_BAD_MESSAGE = 'Bad messagge';
  Err_FX_NO_CONNECTION = 'No connection';
  Err_FX_CONNECTION_LOST = 'Connection lost';
  Err_FX_OP_UNSUPPORTED = 'Operation unsupported';
  Err_FX_INVALID_HANDLE = 'Invalid handle';
  Err_FX_NO_SUCH_PATH = 'No such path';
  Err_FX_FILE_ALREADY_EXISTS = 'File exists';
  Err_FX_WRITE_PROTECT = 'Write protect';
  Err_FX_NO_MEDIA = 'No media';
  Err_FX_NO_SPACE_ON_FILESYSTEM = 'No space on filesystem';
  Err_FX_QUOTA_EXCEEDED = 'Quota exceeded';
  Err_LIBSSH2_FX_UNKNOWN_PRINCIPAL = 'Unknown principal';
  Err_LIBSSH2_FX_LOCK_CONFLICT = 'Lock conflict';
  Err_LIBSSH2_FX_DIR_NOT_EMPTY = 'Directory not empty';
  Err_LIBSSH2_FX_NOT_A_DIRECTORY = 'Not a directory';
  Err_LIBSSH2_FX_INVALID_FILENAME = 'Invalid filename';
  Err_LIBSSH2_FX_LINK_LOOP = 'Link loop';
  Err_LIBSSH2_UNKNOWN = 'Unknown error';
  Err_NotAFile = '"%s" is not a file';
  Err_SessionNotAuth = 'The session is not connected and authorised';
  Err_InvalideSource = 'The source of a copy operation is not valid';
  Err_InvalideDest = 'The destination of a copy operation is not valid';

function SftpErrorMsg(ErrNo: ULong): string;
begin
  case ErrNo of
    LIBSSH2_FX_EOF:
      Result := Err_FX_EOF;
    LIBSSH2_FX_NO_SUCH_FILE:
      Result := Err_FX_NO_SUCH_FILE;
    LIBSSH2_FX_PERMISSION_DENIED:
      Result := Err_FX_PERMISSION_DENIED;
    LIBSSH2_FX_FAILURE:
      Result := Err_FX_FAILURE;
    LIBSSH2_FX_BAD_MESSAGE:
      Result := Err_FX_BAD_MESSAGE;
    LIBSSH2_FX_NO_CONNECTION:
      Result := Err_FX_NO_CONNECTION;
    LIBSSH2_FX_CONNECTION_LOST:
      Result := Err_FX_CONNECTION_LOST;
    LIBSSH2_FX_OP_UNSUPPORTED:
      Result := Err_FX_OP_UNSUPPORTED;
    LIBSSH2_FX_INVALID_HANDLE:
      Result := Err_FX_INVALID_HANDLE;
    LIBSSH2_FX_NO_SUCH_PATH:
      Result := Err_FX_NO_SUCH_PATH;
    LIBSSH2_FX_FILE_ALREADY_EXISTS:
      Result := Err_FX_FILE_ALREADY_EXISTS;
    LIBSSH2_FX_WRITE_PROTECT:
      Result := Err_FX_WRITE_PROTECT;
    LIBSSH2_FX_NO_MEDIA:
      Result := Err_FX_NO_MEDIA;
    LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM:
      Result := Err_FX_NO_SPACE_ON_FILESYSTEM;
    LIBSSH2_FX_QUOTA_EXCEEDED:
      Result := Err_FX_QUOTA_EXCEEDED;
    LIBSSH2_FX_UNKNOWN_PRINCIPAL:
      Result := Err_LIBSSH2_FX_UNKNOWN_PRINCIPAL;
    LIBSSH2_FX_LOCK_CONFlICT:
      Result := Err_LIBSSH2_FX_LOCK_CONFLICT;
    LIBSSH2_FX_DIR_NOT_EMPTY:
      Result := Err_LIBSSH2_FX_DIR_NOT_EMPTY;
    LIBSSH2_FX_NOT_A_DIRECTORY:
      Result := Err_LIBSSH2_FX_NOT_A_DIRECTORY;
    LIBSSH2_FX_INVALID_FILENAME:
      Result := Err_LIBSSH2_FX_INVALID_FILENAME;
    LIBSSH2_FX_LINK_LOOP:
      Result := Err_LIBSSH2_FX_LINK_LOOP;
    else
      Result := Err_LIBSSH2_UNKNOWN;
  end;
end;

procedure CheckSftpResult(ReturnCode: Integer; const Op: string);
var
  ErrMsg: string;
begin
  if ReturnCode < 0 then
  begin
    // LIBSSH2_ERROR_EAGAIN indicates no result in non-blocking mode
    if ReturnCode = LIBSSH2_ERROR_EAGAIN then Exit;
    ErrMsg := SftpErrorMsg(ReturnCode);
    raise ESftpErr.CreateResFmt(@Err_Sftp,
      [ErrMsg, ReturnCode, Op])
  end;
end;

function TestBit(const ABits, AVal: Cardinal): Boolean; inline;
begin
  Result := ABits and AVal { = AVal } <> 0;
end;
function AttrsToFileType(const Attributes: LIBSSH2_SFTP_ATTRIBUTES): TSFTPItemType;
begin
  if TestBit(Attributes.Flags, LIBSSH2_SFTP_ATTR_PERMISSIONS) then
  begin
    case Attributes.Permissions and LIBSSH2_SFTP_S_IFMT of
      LIBSSH2_SFTP_S_IFDIR:
        Result := sitDirectory;
      LIBSSH2_SFTP_S_IFBLK:
        Result := sitBlockDev;
      LIBSSH2_SFTP_S_IFIFO:
        Result := sitFIFO;
      LIBSSH2_SFTP_S_IFCHR:
        Result := sitCharDev;
      LIBSSH2_SFTP_S_IFSOCK:
        Result := sitSocket;
      LIBSSH2_SFTP_S_IFLNK:
        Result := sitSymbolicLink;
      LIBSSH2_SFTP_S_IFREG:
        Result := sitFile;
      else
        Result := sitUnknown;
    end;
  end
  else
    Result := sitUnknown;
end;
{$endregion}

{$region TSFtpClient}
type

  TSFtpClient = class(TInterfacedObject, ISftpClient)
  private
    FSession: ISshSession;
    FSftp: PLIBSSH2_SFTP;
    FBufferSize: Int64;
    FCancelled: Boolean;
    FPathDelim: AnsiChar;
    FWindowsHost: Boolean;
    FTransferCallback: TTransferProgressCallback;
    procedure SetBufferSize(Size: Int64);
    procedure SetTransferProgressCallback(Callback: TTransferProgressCallback);
    procedure RaiseLastSFTPError(Const Op: string);
    procedure Cancel;
    function SftpType(Name: string; FollowLink: Boolean = True): TSFTPItemType;
    function GetPathDelimiter: AnsiChar;
    function GetWindowsHost: Boolean;
    function ExpandTilde(const S: string): string;
    // Directories
    function GetCurrentDir: string;
    function CreateDir(const Dir: string; Permissions: TFilePermissions = FPDefault): Boolean;
    function ForceDirectories(Dir: string): Boolean;
    function RemoveDir(const Dir: string): Boolean;
    function DirectoryExists(const Directory: string; FollowLink: Boolean = True): Boolean;
    function ExcludeTrailingPathDelimiter(const S: string): string;
    function IncludeTrailingPathDelimiter(const S: string): string;
    function ExtractFileName(const FileName: string): string;
    function DirContent(const Dir: string): TSftpItems;
    // Files
    function FileExists(const FileName: string; FollowLink: Boolean = True): Boolean;
    function DeleteFile(const FileName: string): Boolean;
    function Rename(const OldName, NewName: string): Boolean;  // also works with directories
    function ExtractFilePath(const FileName: string): string;
    // Symbolic Links
    function RealPath(Name: string): string;
    function CreateSymLink(const Link, Target: string): Boolean;
    // Send and Receive
    procedure Receive(const RemoteFile: string; Stream: TStream); overload;
    procedure Receive(const RemoteFile, LocalFile: string; Overwrite: Boolean = True); overload;
    procedure Send(Stream: TStream; const RemoteFile: string;
      Overwrite: Boolean = True; Permissions: TFilePermissions = FPDefault); overload;
    procedure Send(const LocalFile, RemoteFile: string;
      Overwrite: Boolean = True; Permissions: TFilePermissions = FPDefault); overload;
    // Copy Files and Directories
    // Source can be a file or a directory and may include a file mask
    // Dest is either a file or a directory
    procedure CopyToHost(const Source, Dest: string; Recursive: Boolean = True;
      Overwrite: Boolean = True; Permissions: TFilePermissions = FPDefault); overload;
    procedure CopyFromHost(const Source, Dest: string; Recursive: Boolean = True;
      Overwrite: Boolean = True); overload;
  public
    constructor Create(Session: ISshSession);
    destructor Destroy; override;
  end;

{ TSFtpClient }

procedure TSFtpClient.Cancel;
begin
  FCancelled := True;
end;

procedure TSFtpClient.CopyFromHost(const Source, Dest: string; Recursive,
  Overwrite: Boolean);
Var
  Mask: string;
  FilePath: string;
  IsFile: Boolean;
  IsPath: Boolean;
  HasMask: Boolean;
  Items: TSftpItems;
  Item: TSftpItem;
begin
  Mask := ExtractFileName(Source);
  HasMask := Mask.IndexOfAny(['?','*']) >= 0;
  if HasMask then
  begin
    IsFile := False;
    FilePath := ExtractFilePath(Source);
    IsPath := DirectoryExists(FilePath);
  end
  else
  begin
    IsFile := FileExists(FilePath, False);
    if IsFile then
      IsPath := False
    else
    begin
      IsPath := DirectoryExists(Source, False);
      FilePath := IncludeTrailingPathDelimiter(Source);
    end;
  end;
  if not (IsFile or IsPath) then
    raise ESftpErr.CreateRes(@Err_InvalideSource);

  if IsFile then
    Receive(Source, Dest, Overwrite)
  else // IsPath
  begin
    // Dest needs to be a directory - Create if needed
    if not System.SysUtils.ForceDirectories(Dest) then
      raise ESftpErr.CreateRes(@Err_InvalideDest);
    Items := DirContent(FilePath);
    for Item in Items do
    case Item.ItemType of
      sitDirectory:
        if Recursive and (Item.FileName <> '.') and (Item.FileName <> '..') then
          CopyFromHost(FilePath + Item.FileName,
            IncludeTrailingPathDelimiter(Dest) + Item.FileName,
            True, Overwrite);
      sitFile:
        if not HasMask or MatchesMask(Item.FileName, Mask) then
          Receive(FilePath + Item.FileName,
            System.SysUtils.IncludeTrailingPathDelimiter(Dest) + Item.FileName,
            Overwrite);
    end;
  end;
end;

procedure TSFtpClient.CopyToHost(const Source, Dest: string; Recursive,
  Overwrite: Boolean; Permissions: TFilePermissions);
Var
  Mask: string;
  FilePath: string;
  IsFile: Boolean;
  IsPath: Boolean;
  HasMask: Boolean;
  Files: TStringDynArray;
  Dirs: TStringDynArray;
  FName: string;
  Dir: string;
begin
  Mask := System.SysUtils.ExtractFileName(Source);
  HasMask := Mask.IndexOfAny(['?','*']) >= 0;
  if HasMask then
  begin
    IsFile := False;
    FilePath := System.SysUtils.ExtractFilePath(Source);
    IsPath := System.SysUtils.DirectoryExists(FilePath, False);
  end
  else
  begin
    IsFile := System.SysUtils.FileExists(FilePath, False);
    if IsFile then
      IsPath := False
    else
    begin
      IsPath := System.SysUtils.DirectoryExists(Source);
      FilePath := System.SysUtils.IncludeTrailingPathDelimiter(Source);
    end;
  end;
  if not (IsFile or IsPath) then
    raise ESftpErr.CreateRes(@Err_InvalideSource);

  if IsFile then
    Send(Source, Dest, Overwrite, Permissions)
  else // IsPath
  begin
    // Dest needs to be a directory - Create if needed
    if not ForceDirectories(Dest) then
      raise ESftpErr.CreateRes(@Err_InvalideDest);
    Files := TDirectory.GetFiles(FilePath);
    for FName in Files do
    begin
      if not HasMask or MatchesMask(System.SysUtils.ExtractFileName(FName), Mask) then
        Send(FName, IncludeTrailingPathDelimiter(Dest) +
          System.SysUtils.ExtractFileName(FName), Overwrite, Permissions)
    end;
    if Recursive then
    begin
      Dirs := TDirectory.GetDirectories(FilePath);
      for Dir in Dirs do
        CopyToHost(Dir, IncludeTrailingPathDelimiter(Dest) + System.SysUtils.ExtractFileName(Dir),
          True, Overwrite, Permissions);
    end;
  end;
end;

constructor TSFtpClient.Create(Session: ISshSession);
begin
  inherited Create;
  if Session.SessionState <> session_Authorized then
    raise ESftpErr.CreateRes(@Err_SessionNotAuth);
  FSession := Session;
  FWindowsHost := Session.WindowsHost;
  if FWindowsHost then
    FPathDelim := '\'
  else
    FPathDelim := '/';

  FSftp := libssh2_sftp_init(Session.Addr);
  FBufferSize := 32 * 1024;
  if FSftp = nil then
    raise ESftpErr.CreateRes(@Err_SftpInit);
end;

function TSFtpClient.CreateDir(const Dir: string; Permissions: TFilePermissions): Boolean;
Var
  M: TMarshaller;
begin
  Result := libssh2_sftp_mkdir(FSFtp,
    M.AsAnsi(ExpandTilde(Dir), FSession.CodePage).ToPointer, LongInt(Word(Permissions))) = 0;
end;

function TSFtpClient.DeleteFile(const FileName: string): Boolean;
Var
  M: TMarshaller;
begin
  Result := libssh2_sftp_unlink(FSFtp,  M.AsAnsi(ExpandTilde(FileName), FSession.CodePage).ToPointer) = 0;
end;

destructor TSFtpClient.Destroy;
begin
  if FSFtp <> nil then
    libssh2_sftp_shutdown(FSFtp);

  inherited;
end;

function ParseItemInfo(AName, ALongEntry: PAnsiChar; CodePage: Word;
  Attribs: LIBSSH2_SFTP_ATTRIBUTES): TSftpItem;
begin
  Result := Default(TSftpItem);
  Result.FileName := AnsiToUnicode(AName, CodePage);
  Result.LongEntry := AnsiToUnicode(ALongEntry, CodePage);
  Result.ItemType := AttrsToFileType(Attribs);
  if TestBit(Attribs.Flags, LIBSSH2_SFTP_ATTR_PERMISSIONS) then
    Result.Permissions := TFilePermissions(LongRec(Attribs.permissions).Lo and $01FF);
  if TestBit(Attribs.Flags, LIBSSH2_SFTP_ATTR_SIZE) then
    Result.FileSize := Attribs.FileSize;
  if TestBit(Attribs.Flags, LIBSSH2_SFTP_ATTR_UIDGID) then
  begin
    Result.UID := Attribs.UID;
    Result.GID := Attribs.GID;
  end;
 if TestBit(Attribs.Flags, LIBSSH2_SFTP_ATTR_ACMODTIME) then
  begin
    Result.LastAccessTime := UnixToDateTime(Attribs.ATime);
    Result.LastModificationTime := UnixToDateTime(Attribs.MTime);
  end
end;

function TSFtpClient.DirContent(const Dir: string): TSftpItems;
const
  BUF_LEN = 4 * 1024;
var
  EntryBuffer: array [0 .. BUF_LEN - 1] of AnsiChar;
  LongEntry: array [0 .. BUF_LEN - 1] of AnsiChar;
  DirHandle: PLIBSSH2_SFTP_HANDLE;
  List: TList<TSFTPItem>;
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
  Count: Integer;
  M: TMarshaller;
begin
  DirHandle := libssh2_sftp_opendir(FSFtp, M.AsAnsi(RealPath(Dir),
    FSession.CodePage).ToPointer);
  if DirHandle = nil then
    RaiseLastSFTPError('libssh2_sftp_opendir');

  List := TList<TSFTPItem>.Create(TDelegatedComparer<TSFTPItem>.Create(
    function(const Left, Right: TSFTPItem): Integer
    begin
      Result := AnsiCompareStr(Left.FileName, Right.FileName);
    end));
  try
    FCancelled := False;
    repeat
      Count := libssh2_sftp_readdir_ex(DirHandle, EntryBuffer, BUF_LEN,
        LongEntry, BUF_LEN, @Attribs);
      if (Count > 0) then
        List.Add(ParseItemInfo(EntryBuffer, LongEntry, FSession.CodePage, Attribs));
    until (Count <= 0) or FCancelled;
    List.Sort;
    Result := List.ToArray;
  finally
    List.Free;
    libssh2_sftp_closedir(DirHandle);
  end;
end;

function TSFtpClient.DirectoryExists(const Directory: string;
  FollowLink: Boolean): Boolean;
begin
  try
    Result := SftpType(Directory, FollowLink) = sitDirectory;
  except
    Result := False;
  end;
end;

function TSFtpClient.ExcludeTrailingPathDelimiter(const S: string): string;
begin
  Result := S;
  if Result[High(Result)] = Char(FPathDelim) then
    SetLength(Result, Length(Result)-1);
end;

function TSFtpClient.ExpandTilde(const S: string): string;
begin
  if not FWindowsHost and (Length(S) > 1) and (S[1] = '~') then
    Result := '/home/' + FSession.UserName + Copy(S, 2)
  else
    Result := S;
end;

function TSFtpClient.ExtractFileName(const FileName: string): string;
var
  I: Integer;
  Delims: string;
begin
  Delims := FPathDelim;
  if FWindowsHost then
    Delims := Delims +  DriveDelim;

  I := LastDelimiter(Delims, FileName);
  if I >= 0 then
    Result := Copy(FileName, I + 2)
  else
    Result := FileName;
end;

function TSFtpClient.ExtractFilePath(const FileName: string): string;
var
  I: Integer;
  Delims: String;
begin
  Delims := FPathDelim;
  if FWindowsHost then
    Delims := Delims +  DriveDelim;

  I := LastDelimiter(Delims, FileName);
  Result := Copy(FileName, 1, I + 1);
end;

function TSFtpClient.FileExists(const FileName: string;
  FollowLink: Boolean): Boolean;
begin
  try
    Result := SftpType(FileName, FollowLink) in [sitFile, sitSymbolicLink];
  except
    Result := False;
  end;
end;

function TSFtpClient.ForceDirectories(Dir: string): Boolean;
begin
  Result := True;
  if Dir = '' then
    raise ESftpErr.CreateRes(@SCannotCreateDir);

  Dir := ExcludeTrailingPathDelimiter(Dir);
  if DirectoryExists(Dir) then
    Exit;

  if FWindowsHost then
  begin
   if ((Length(Dir) < 3) or (ExtractFilePath(Dir) = Dir)) then
     Exit(CreateDir(Dir))
  end
  else
    Dir := ExpandTilde(Dir);
  Result := ForceDirectories(ExtractFilePath(Dir)) and CreateDir(Dir);
end;

function TSFtpClient.GetCurrentDir: string;
const
  BUF_LEN = 4 * 1024;
var
  DirHandle: PLIBSSH2_SFTP_HANDLE;
  Buf: PAnsiChar;
begin
  Result := '';

  DirHandle := libssh2_sftp_opendir(FSFtp, '.');
  if DirHandle <> nil then
  begin
    GetMem(Buf, BUF_LEN);
    try
      libssh2_sftp_realpath(FSFtp, nil, Buf, BUF_LEN);
      libssh2_sftp_close(DirHandle);
      Result := AnsiToUnicode(Buf, FSession.CodePage);
    finally
      FreeMem(Buf);
    end;
  end
  else
    RaiseLastSftpError('libssh2_sftp_opendir');
end;

function TSFtpClient.GetPathDelimiter: AnsiChar;
begin
  Result := FPathDelim;
end;

function TSFtpClient.GetWindowsHost: Boolean;
begin
  Result := FWindowsHost;
end;

function TSFtpClient.IncludeTrailingPathDelimiter(const S: string): string;
begin
  Result := S;
  if Ord(High(Result)) <> Ord(FPathDelim) then
    Result := Result + Char(Ord(FPathDelim));
end;

function TSFtpClient.CreateSymLink(const Link, Target: string): Boolean;
Var
  M: TMarshaller;
begin
  Result :=
    libssh2_sftp_symlink(FSFtp, M.AsAnsi(RealPath(Target), FSession.CodePage).ToPointer,
    M.AsAnsi(ExpandTilde(Link), FSession.CodePage).ToPointer) = 0;
end;

procedure TSFtpClient.Receive(const RemoteFile: string; Stream: TStream);
var
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
  Transfered, Total: UInt64;
  FHandle: PLIBSSH2_SFTP_HANDLE;
  Buf: PAnsiChar;
  R, N: ssize_t;
  M: TMarshaller;
begin
  FCancelled := False;
  CheckSftpResult(libssh2_sftp_stat(FSFtp,
    M.AsAnsi(ExpandTilde(RemoteFile), FSession.CodePage).ToPointer, Attribs),
    'libssh2_sftp_stat');

  if AttrsToFileType(Attribs) <> sitFile then
    raise ESftpErr.CreateResFmt(@Err_NotAFile, [RemoteFile]);

  Assert(TestBit(Attribs.Flags, LIBSSH2_SFTP_ATTR_SIZE));

  FHandle := libssh2_sftp_open(FSftp,
    M.AsAnsi(RealPath(RemoteFile), FSession.CodePage).ToPointer,
    LIBSSH2_FXF_READ, 0);
  if FHandle = nil then
    RaiseLastSftpError('libssh2_sftp_open');

  Total := Attribs.FileSize;

  Transfered := 0;
  GetMem(Buf, FBufferSize);
  try
    repeat
      R := libssh2_sftp_read(FHandle, Buf, FBufferSize);
      if R > 0 then
      begin
        N := Stream.Write(Buf^, R);
        Assert(N = R);
        Inc(Transfered, N);
        if Assigned(FTransferCallback) then
          FTransferCallback(RemoteFile, Transfered, Total);
      end
      else if R < 0 then
        CheckSftpResult(R, 'libssh2_sftp_read');
    until (R = 0) or FCancelled;
  finally
    FreeMem(Buf);
    libssh2_sftp_close(FHandle);
  end;
end;

procedure TSFtpClient.RaiseLastSFTPError(const Op: string);
begin
  CheckSftpResult(libssh2_sftp_last_error(FSftp), Op);
end;

function TSFtpClient.RealPath(Name: string): string;
const
  BUF_LEN = 4 * 1024;
var
  Target: array [0 .. BUF_LEN - 1] of AnsiChar;
  M: TMarshaller;
begin
  Result := '';
  CheckSftpResult(libssh2_sftp_realpath(FSFtp, M.AsAnsi(ExpandTilde(Name), FSession.CodePage).ToPointer,
    PAnsiChar(@Target), BUF_LEN), 'libssh2_sftp_realpath');
  Result := AnsiToUnicode(PAnsiChar(@Target), FSession.CodePage);
end;

procedure TSFtpClient.Receive(const RemoteFile, LocalFile: string; Overwrite:Boolean);
Var
  FileStream: TFileStream;
   Mode: Word;
begin
  if Overwrite then
    Mode := fmCreate or fmOpenWrite
  else
    Mode := fmCreate;
  FileStream := TFileStream.Create(LocalFile, Mode);
  try
    Receive(RemoteFile, FileStream);
  finally
    FileStream.Free;
  end;
end;

function TSFtpClient.RemoveDir(const Dir: string): Boolean;
Var
  M: TMarshaller;
begin
  Result := libssh2_sftp_rmdir(FSFtp, M.AsAnsi(ExpandTilde(Dir), FSession.CodePage).ToPointer) = 0;
end;

function TSFtpClient.Rename(const OldName, NewName: string): Boolean;
var
  M: TMarshaller;
begin
  Result := libssh2_sftp_rename(FSFtp,
    M.AsAnsi(ExpandTilde(OldName), FSession.CodePage).ToPointer,
    M.AsAnsi(ExpandTilde(NewName), FSession.CodePage).ToPointer) = 0;
end;

procedure TSFtpClient.Send(Stream: TStream; const RemoteFile: string;
  Overwrite: Boolean; Permissions: TFilePermissions);
var
  R, N, K: Integer;
  Flags: Integer;
  FHandle: PLIBSSH2_SFTP_HANDLE;
  Buf, StartBuf: PAnsiChar;
  Transfered, Total: UInt64;
  M: TMarshaller;
begin
  FCancelled := False;
  Flags := LIBSSH2_FXF_WRITE or LIBSSH2_FXF_CREAT;
  if Overwrite then
    Flags := Flags or LIBSSH2_FXF_TRUNC
  else
    Flags := Flags or LIBSSH2_FXF_EXCL; // ensure call fails if file exists

  FHandle := libssh2_sftp_open(FSFtp, M.AsAnsi(RealPath(RemoteFile), FSession.CodePage).ToPointer,
    Flags, LongInt(Word(Permissions)));
  if FHandle = nil then
    RaiseLastSftpError('libssh2_sftp_open');

  GetMem(Buf, FBufferSize);
  StartBuf := Buf;
  Transfered := 0;
  Total := Stream.Size - Stream.Position;
  try
    repeat
      N := Stream.Read(Buf^, FBufferSize);
      if N > 0 then
      begin
        K := N;
        repeat
          R := libssh2_sftp_write(FHandle, Buf, K);
          if R < 0 then
            CheckSftpResult(R, 'libssh2_sftp_read');
          Inc(Transfered, R);
          Inc(Buf, R);
          Dec(K, R);
          if Assigned(FTransferCallback) then
            FTransferCallback(RemoteFile, Transfered, Total);
        until (K <= 0) or FCancelled;
        Buf := StartBuf;
      end;
    until (N <= 0) or FCancelled;
  finally
    FreeMem(StartBuf);
    libssh2_sftp_close(FHandle);
  end;
end;

procedure TSFtpClient.Send(const LocalFile, RemoteFile: string;
  Overwrite: Boolean; Permissions: TFilePermissions);
Var
  FileStream: TFileStream;
begin
  FileStream := TFileStream.Create(LocalFile, fmOpenRead);
  try
    Send(FileStream, RemoteFile, Overwrite, Permissions);
  finally
    FileStream.Free;
  end;
end;

procedure TSFtpClient.SetBufferSize(Size: Int64);
begin
  FBufferSize := Size;
end;

procedure TSFtpClient.SetTransferProgressCallback(
  Callback: TTransferProgressCallback);
begin
  FTransferCallback := Callback;
end;

function TSFtpClient.SftpType(Name: string; FollowLink: Boolean): TSFTPItemType;
var
  ReturnCode: integer;
  Attribs: LIBSSH2_SFTP_ATTRIBUTES;
  M: TMarshaller;
begin
  if FollowLink then
    ReturnCode :=
      libssh2_sftp_stat(FSFtp, M.AsAnsi(ExpandTilde(Name), FSession.CodePage).ToPointer, Attribs)
  else
    ReturnCode :=
      libssh2_sftp_lstat(FSFtp, M.AsAnsi(ExpandTilde(Name), FSession.CodePage).ToPointer, Attribs);
  CheckSftpResult(ReturnCode, 'SftpType');
  Result := AttrsToFileType(Attribs);
end;
{$endregion}

{$region 'Factory Methods'}
function CreateSftpClient(Session: ISshSession): ISftpClient;
begin
  Result := TSFtpClient.Create(Session);
end;
{$endregion}

end.
