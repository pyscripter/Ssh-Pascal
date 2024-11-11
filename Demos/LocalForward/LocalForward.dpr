program LocalForward;
{
  Run and while the project is running open a browser at http://localhost:12345/
  You should see http://detectportal.firefox.com/success.txt
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
  SshTunnel in '..\..\Source\SshTunnel.pas';

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
const
  SshPort = 22;
  RemoteHost = 'detectportal.firefox.com';
  LocalPort = 12345;
  RemotePort = 80;
var
  Host: string;
  UserName: string;
  Session: ISshSession;
  SshTunnel: ISshTunnel;
  Thread: TThread;
begin
   if ParamCount <> 2 then begin
    WriteLn('Usage: LocalForward Host, UserName');
    Exit;
  end;

  Host := ParamStr(1);
  UserName := ParamStr(2);

  Session := CreateSession(Host, SshPort);
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

  SshTunnel := CreateSshTunnel(Session);
  Thread := TThread.CreateAnonymousThread(
    procedure
    begin
      SshTunnel.ForwardLocalPort(LocalPort, RemoteHost, RemotePort);
    end);
  Thread.FreeOnTerminate := False;
  Thread.Start;
  WriteLn;
  WriteLn('Tunnel from localhost:', LocalPort, ' to ', RemoteHost, ':',
    RemotePort, ' established');
  WriteLn;
  WriteLn('Press Enter to terminate');
  ReadLn;
  SshTunnel.Cancel;
  if not Thread.Finished then
  begin
    Thread.WaitFor;
    Thread.Free;
  end;
  WriteLn('All done!');
end;

begin
  ReportMemoryLeaksOnShutdown := True;
  try
    Main;
  except
    on E: Exception do
      WriteLn(E.ClassName, ': ', E.Message);
  end;
  ReadLn;
end.
