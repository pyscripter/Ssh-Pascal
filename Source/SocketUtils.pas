unit SocketUtils;

interface
Uses
  WinApi.Windows,
  Winapi.WinSock2,
  System.SysUtils,
  System.RTLConsts;

type

ESocketError = class(Exception);

TIPVersion = (IPvUNSPEC = 0, IPv4 = AF_INET, IPv6 = AF_INET6);

IWinSock = interface
  ['{D2C84E61-0060-475E-9D8C-97EBF6C6AA28}']
  function CreateAndConnectSocket(Host: string; Port: Word; IPVersion: TIPVersion = IPv4): TSocket;
  function CreateSocketAndListen(Host: string; Port: Word;
    IPVersion: TIPVersion = IPv4; Backlog: Integer = 2): TSocket;
end;

function GetWinSock: IWinSock;
procedure CheckSocketResult(ResultCode: Integer; const Op: string);

implementation

type
  PAddrInfoW = ^ADDRINFOW;
  ADDRINFOW = record
    ai_flags        : Integer;      // AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST
    ai_family       : Integer;      // PF_xxx
    ai_socktype     : Integer;      // SOCK_xxx
    ai_protocol     : Integer;      // 0 or IPPROTO_xxx for IPv4 and IPv6
    ai_addrlen      : size_t;        // Length of ai_addr
    ai_canonname    : PWideChar;    // Canonical name for nodename
    ai_addr         : PSOCKADDR;    // Binary address
    ai_next         : PAddrInfoW;   // Next structure in linked list
  end;
  TAddrInfoW = ADDRINFOW;

{$WARN SYMBOL_PLATFORM OFF}
function  GetAddrInfoW(NodeName: PWideChar; ServiceName: PWideChar;
  Hints: PaddrinfoW; var pResult: PaddrinfoW): Integer; stdcall;
  external 'ws2_32.dll' name 'GetAddrInfoW' delayed;
procedure FreeAddrInfoW(ai: PaddrinfoW); stdcall;
  external 'ws2_32.dll' name 'FreeAddrInfoW' delayed;
{$WARN SYMBOL_PLATFORM ON}

procedure StartWinSock;
var
  Data: WSAData;
  ErrorCode: Integer;
begin
  ErrorCode := WSAStartup(WINSOCK_VERSION, Data);
  if ErrorCode <> 0 then
    raise ESocketError.CreateResFmt(@sWindowsSocketError,
      [SysErrorMessage(ErrorCode), ErrorCode, 'WSAStartup']);
end;

type
  TWinSock  = class(TInterfacedObject, IWinSock)
  class var FInstanceCount: Integer;
  private
    function CreateAndConnectSocket(Host: string; Port: Word; IPVersion: TIPVersion = IPv4): TSocket;
    function CreateSocketAndListen(Host: string; Port: Word;
      IPVersion: TIPVersion = IPv4; Backlog: Integer = 2): TSocket;
    function CreateSocket(Host: string; Port: Word; IPVersion: TIPVersion; var AddrInfo: PAddrInfoW): TSocket;
  public
    constructor Create;
    destructor Destroy; override;
  end;

function GetWinSock: IWinSock;
begin
  Result := TWinSock.Create;
end;

procedure CheckSocketResult(ResultCode: Integer; const Op: string);
begin
  if ResultCode <> 0 then
  begin
    if ResultCode <> WSAEWOULDBLOCK then
      raise ESocketError.CreateResFmt(@sWindowsSocketError,
        [SysErrorMessage(ResultCode), ResultCode, Op]);
  end;
end;

{ TWinSock }

function TWinSock.CreateAndConnectSocket(Host: string; Port: Word; IPVersion: TIPVersion = IPv4): TSocket;
Var
  AddrInfo: PaddrinfoW;
  ReturnCode : Integer;
begin
  AddrInfo := nil;
  Result := CreateSocket(Host, Port, IPVersion, AddrInfo);

  try
    ReturnCode := 0;
    while AddrInfo <> nil do
    begin
      ReturnCode := connect(Result, AddrInfo^.ai_addr^, AddrInfo^.ai_addrlen);
      if ReturnCode = 0 then break;
      AddrInfo := AddrInfo^.ai_next;
    end;
    CheckSocketResult(ReturnCode, 'connect');
  finally
    if AddrInfo <> nil then FreeAddrInfoW(AddrInfo);
  end;
end;

function TWinSock.CreateSocketAndListen(Host: string; Port: Word;
  IPVersion: TIPVersion; Backlog: Integer): TSocket;
Var
  AddrInfo: PaddrinfoW;
  ReturnCode : Integer;
begin
  AddrInfo := nil;
  Result := CreateSocket(Host, Port, IPVersion, AddrInfo);

  try
    ReturnCode := 0;
    while AddrInfo <> nil do
    begin
      ReturnCode := bind(Result, AddrInfo^.ai_addr^, AddrInfo^.ai_addrlen);
      if ReturnCode = 0 then break;
      AddrInfo := AddrInfo^.ai_next;
    end;
    CheckSocketResult(ReturnCode, 'bind');
    CheckSocketResult(listen(Result, 2), 'listen');
  finally
    if AddrInfo <> nil then FreeAddrInfoW(AddrInfo);
  end;
end;


constructor TWinSock.Create;
begin
  inherited;
  if AtomicIncrement(FInstanceCount) = 1 then
    StartWinSock;
end;

destructor TWinSock.Destroy;
begin
  if AtomicDecrement(FInstanceCount) = 0 then
    WSACleanup;
  inherited;
end;

function TWinSock.CreateSocket(Host: string; Port: Word;
  IPVersion: TIPVersion; var AddrInfo: PAddrInfoW): TSocket;
var
  Hints: TAddrInfoW;
begin
  Result := socket(Ord(IpVersion), SOCK_STREAM, IPPROTO_TCP);
  if Result = INVALID_SOCKET then
    CheckSocketResult(WSAGetLastError, 'socket');
  FillChar(Hints, sizeof(Hints), 0);
  Hints.ai_family := Ord(IpVersion);
  Hints.ai_socktype := SOCK_STREAM;
  Hints.ai_protocol := IPPROTO_TCP;
  CheckSocketResult(GetaddrinfoW(PChar(Host), PChar(Port.ToString), @Hints, AddrInfo), 'GetaddrinfoW');
end;

end.

