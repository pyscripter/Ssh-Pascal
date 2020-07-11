program ScpRecv;

{$APPTYPE CONSOLE}

uses
  Winapi.Winsock2,
  System.SysUtils,
  System.NetEncoding,
  System.Classes,
  libssh2 in '..\..\Source\libssh2.pas',
  SocketUtils in '..\..\Source\SocketUtils.pas',
  Ssh2Client in '..\..\Source\Ssh2Client.pas',
  libssh2_sftp in '..\..\Source\libssh2_sftp.pas';

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
  RemotePath: string;
  LocalPath: string;
  Session: ISshSession;
  Scp: IScp;
begin

  if ParamCount <> 4 then begin
    WriteLn('Usage: SpcRecv Host, UserName, RemoteFile, LocalFile');
    Exit;
  end;

  Host := ParamStr(1);
  UserName := ParamStr(2);
  RemotePath := ParamStr(3);
  LocalPath := ParamStr(4);

  Session := CreateSession(Host, 22);
  //Session.UseCompression := True;
  Session.SetKeybInteractiveCallback(KeybIntCallback);

  Session.Connect;
  WriteLn(Session.HostBanner);
  WriteLn(Session.SessionMethods);

  if not Session.UserAuth(UserName) then
  begin
    WriteLn('Authorization Failure');
    Exit;
  end;

  Scp := CreateScp(Session);
  Scp.Receive(RemotePath, LocalPath);

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
