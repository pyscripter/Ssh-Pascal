program SftpSend;
{
  Includes testing of different Sftp features
}

{$APPTYPE CONSOLE}

uses
  Winapi.Winsock2,
  System.SysUtils,
  System.NetEncoding,
  System.Classes,
  libssh2 in '..\..\Source\libssh2.pas',
  SocketUtils in '..\..\Source\SocketUtils.pas',
  Ssh2Client in '..\..\Source\Ssh2Client.pas',
  libssh2_sftp in '..\..\Source\libssh2_sftp.pas',
  SftpClient in '..\..\Source\SftpClient.pas';

function KeybIntCallback(const AuthName, AuthInstruction, Prompt: string;
    Echo: Boolean): string;
begin
  if AuthName <> '' then WriteLn('Authorization Name: ', AuthName);
  if AuthInstruction <> '' then WriteLn('Authorization Instruction: ', AuthInstruction);
  Write(Prompt);
  // if Echo is False then you should mask the input
  // See https://stackoverflow.com/questions/3671042/mask-password-input-in-a-console-app
  ReadLn(Result);
end;

procedure Main;
Var
  Host: string;
  UserName: string;
  Session: ISshSession;
  Sftp: ISftpClient;
  RemotePath: string;
  LocalPath: string;
  FilePath: string;
begin

   if ParamCount <> 4 then begin
    WriteLn('Usage: SftpSend Host, UserName, RemoteFile, LocalFile');
    Exit;
  end;

  Host := ParamStr(1);
  UserName := ParamStr(2);
  LocalPath := ParamStr(3);
  RemotePath := ParamStr(4);

  Session := CreateSession(Host, 22);
  //Session.UseCompression := True;
  Session.SetKeybInteractiveCallback(KeybIntCallback);

  Session.Connect;
  WriteLn(Session.HostBanner);
  WriteLn(Session.SessionMethods);

  //if not Session.UserAuthInteractive(UserName) then
  if not Session.UserAuth(UserName) then
  begin
    WriteLn('Authorization Failure');
    Exit;
  end;

  Sftp := CreateSftpClient(Session);
  WriteLn('Current directory: ', Sftp.GetCurrentDir);

  FilePath := Sftp.ExtractFilePath(RemotePath);
  Assert(Sftp.DirectoryExists(FilePath));

  FilePath := FilePath + 'tempdir';
  Assert(Sftp.CreateDir(FilePath));
  Assert(not Sftp.FileExists(FilePath));
  Assert(Sftp.DirectoryExists(FilePath));
  Assert(Sftp.RemoveDir(FilePath));
  Assert(not Sftp.DirectoryExists(FilePath));

  // tilde expansion
  Assert(Sftp.ForceDirectories('~/tmpdir/tmpdir'));
  Assert(Sftp.RemoveDir('~/tmpdir/tmpdir'));
  Assert(Sftp.RemoveDir('~/tmpdir'));

  // ForceDirectories
  FilePath := Sftp.ExtractFilePath(RemotePath);
  FilePath := FilePath + 'tempdir' + string(Sftp.PathDelimiter) + 'tempdir';
  Assert(Sftp.ForceDirectories(FilePath));
  Assert(Sftp.DirectoryExists(FilePath));
  Assert(Sftp.RemoveDir(FilePath));
  Assert(Sftp.RemoveDir(Sftp.ExtractFilePath(FilePath)));

  //Symbolic links - tilde expansion
  Assert(Sftp.CreateSymLink('~/link', RemotePath));
  Assert(Sftp.SftpType('~/link', False) = sitSymbolicLink);
  Assert(Sftp.DeleteFile('~/link'));

  Sftp.Send(LocalPath, RemotePath);
  Assert(Sftp.RealPath(RemotePath) = RemotePath);
  Assert(Sftp.FileExists(RemotePath));
  Assert(not Sftp.DirectoryExists(RemotePath));
  Assert(Sftp.DeleteFile(RemotePath));
  Assert(not Sftp.FileExists(RemotePath));

  Writeln('All done!');
end;

begin
  ReportMemoryLeaksOnShutdown := True;
  try
    Main;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
  ReadLn;
end.
