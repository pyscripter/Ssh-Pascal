program SshExec;

{$APPTYPE CONSOLE}

uses
  Winapi.Winsock2,
  System.SysUtils,
  System.Classes,
  libssh2 in '..\..\Source\libssh2.pas',
  SocketUtils in '..\..\Source\SocketUtils.pas',
  Ssh2Client in '..\..\Source\Ssh2Client.pas',
  libssh2_sftp in '..\..\Source\libssh2_sftp.pas',
  SFtpClient in '..\..\Source\SFtpClient.pas';

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
  Command: string;
  Session: ISshSession;
  SshExec: ISshExec;
  Output: string;
  ErrOutput: string;
  ExitCode: Integer;
begin

  if ParamCount <> 3 then begin
    WriteLn('Usage: SshExec Host, UserName, Command');
    Exit;
  end;

  Host := ParamStr(1);
  UserName := ParamStr(2);
  Command := ParamStr(3);

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

  SshExec := CreateSshExec(Session);
  SshExec.Exec(Command, Output, ErrOutput, ExitCode);
  WriteLn('Command:', Command);
  WriteLn('Output:');
  if Output <> '' then WriteLn(Output);
  WriteLn('Error Output:');
  if ErrOutput <> '' then WriteLn(ErrOutput);
  WriteLn('Exit Code:', ExitCode.ToString);
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
