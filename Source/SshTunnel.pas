unit SshTunnel;
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
  System.SysUtils,
  Ssh2Client;

type
  ESshTunnelError = class(Exception);

  ISshTunnel = interface
    ['{EB106E13-F168-43A5-BD44-301915814600}']
    procedure SetBufferSize(Size: Int64);
    procedure Cancel;
    // Forwards a local port to a RemoteHost:RemotePort until Cancelled
    procedure ForwardLocalPort(const LocalPort: Word; const RemoteHost: string;
      const RemotePort: Word);
    property BufferSize: Int64 write SetBufferSize;
  end;

  // Factory Method
  function CreateSshTunnel(Session: ISshSession): ISshTunnel;

implementation

Uses
  WinApi.Windows,
  System.Classes,
  libssh2,
  Winapi.Winsock2,
  SocketUtils;

resourcestring
  Err_SessionNotAuth = 'The session is not connected and authorised';
  Err_ConnClosed = 'The connection has been closed';

{$region 'TSshTunnel'}
type
  TSshTunnel = class(TInterfacedObject, ISshTunnel)
  private
    FSession: ISshSession;
    FCancelled: Boolean;
    FBufferSize: Int64;
    procedure SetBufferSize(Size: Int64);
    procedure Cancel;
    procedure ForwardLocalPort(const LocalPort: Word; const RemoteHost: string;
      const RemotePort: Word);
 public
    constructor Create(Session: ISshSession);
  end;
{ TSshTunnel }

procedure TSshTunnel.Cancel;
begin
  FCancelled := True;
end;

constructor TSshTunnel.Create(Session: ISshSession);
begin
  inherited Create;
  if Session.SessionState <> session_Authorized then
    raise ESshTunnelError.CreateRes(@Err_SessionNotAuth);
  FSession := Session;
  FBufferSize := 32 * 1024 - 1;
end;

procedure TSshTunnel.ForwardLocalPort(const LocalPort: Word;
  const RemoteHost: string; const RemotePort: Word);
{
   Note that currently the procedure handles only the first connection that come in
}
Var
  ListenSock: TSocket;
  ForwardSock: TSocket;
  ChannelSock: TSocket;
  Channel: PLIBSSH2_CHANNEL;
  SocketOption : Integer;
  ReadFds: TFdSet;
  TimeVal: TTimeVal;
  ReturnCode: integer;
  Buf: TBytes;
  Read: Integer;
  Total : Integer;
  Written: Integer;
  M: TMarshaller;
begin
  FCancelled := False;
  ForwardSock := INVALID_SOCKET;
  Channel := nil;
  TimeVal.tv_sec := 1;  // check for cancel every one second
  TimeVal.tv_usec := 0;

  ListenSock := GetWinSock.CreateSocketAndListen('localhost', LocalPort);
  setsockopt(ListenSock, SOL_SOCKET, SO_REUSEADDR, @SocketOption, sizeof(SocketOption));
  try
    // Wait for TCP connection on LocalPort
    Repeat
      FD_ZERO(ReadFds);
      _FD_SET(ListenSock, ReadFds);
      ReturnCode := select(0, @ReadFds, nil, nil, @TimeVal);
      if ReturnCode < 0 then CheckSocketResult(WSAGetLastError, 'select');
    Until (ReturnCode > 0) or FCancelled;
    if FCancelled then Exit;

    ForwardSock := accept(listensock, nil, nil);
    if ForwardSock = INVALID_SOCKET then
      CheckSocketResult(WSAGetLastError, 'accept');

    Channel := libssh2_channel_direct_tcpip_ex(FSession.Addr,
      M.AsAnsi(RemoteHost, FSession.CodePage).ToPointer,
      RemotePort, '127.0.0.1', LocalPort);
    if Channel = nil then
      CheckLibSsh2Result(libssh2_session_last_errno(FSession.Addr),
        FSession, 'libssh2_channel_direct_tcpip_ex');
    ChannelSock := FSession.Socket;

    // Must use non-blocking IO hereafter due to the current libssh2 API
    FSession.Blocking := False;

    // Now transfer date
    // ForwardSocket -> Channel
    // Channel -> ForwardSocket

    SetLength(Buf, FBufferSize);
    while not FCancelled do
    begin
      FD_ZERO(ReadFds);
      _FD_SET(ForwardSock, ReadFds);
      _FD_SET(ChannelSock, ReadFds);
      // wait for action
      ReturnCode := select(0, @ReadFds, nil, nil, @TimeVal);
      if ReturnCode < 0 then CheckSocketResult(ReturnCode, 'select');
      if ReturnCode = 0 then Continue;

      // we should be able to read now
      if FD_ISSET(ForwardSock, ReadFds) then begin
        Read := recv(Forwardsock, Buf[0], FBufferSize, 0);
        if Read = SOCKET_ERROR then
          CheckSocketResult(WSAGetLastError, 'recv');
        if Read = 0 then
          raise ESshTunnelError.CreateRes(@Err_ConnClosed);
        Total := 0;
        While (Total < Read) do
        begin
          Written := libssh2_channel_write(Channel, PAnsiChar(Buf) + Total, Read - Total);
          // Takes care of LIBSSH2_ERROR_EAGAIN
          CheckLibSsh2Result(Written, FSession, 'libssh2_channel_write');
          Inc(Total, Written);
        end;
      end;
      if FD_ISSET(ChannelSock, ReadFds) then begin
        Read := libssh2_channel_read(channel, PAnsiChar(Buf), FBufferSize);
        if Read = LIBSSH2_ERROR_EAGAIN then
          // Go to Wait state again
          Continue;
        CheckLibSsh2Result(Read, FSession, 'libssh2_channel_read');
        Total := 0;
        While (Total < Read) do
        begin
          Written := send(forwardsock, Buf[Total], Read - Total, 0);
          if Written = SOCKET_ERROR then
            CheckSocketResult(WSAGetLastError, 'send');
          Inc(Total, Written);
        end;
      end;
    end;
  finally
    if Channel <> nil then libssh2_channel_free(Channel);
    if ForwardSock <> INVALID_SOCKET then closesocket(ForwardSock);
    if ListenSock <> INVALID_SOCKET then closesocket(ListenSock);
  end;
end;

procedure TSshTunnel.SetBufferSize(Size: Int64);
begin
  FBufferSize := Size;
end;
{$endregion}


{$region 'Factory Methods'}
function CreateSshTunnel(Session: ISshSession): ISshTunnel;
begin
  Result := TSshTunnel.Create(Session);
end;
{$endregion}


end.
