unit Ssh2Client;
{

    Copyright (c) 2020 Kiriakos Vlahos (PyScripter)
    Delphi wrapper of libssh2 (https://www.libssh2.org/)

    The C header translation and the SFTP implementation draw from
    https://bitbucket.org/ZeljkoMarjanovic/libssh2-delphi
    Copyright (c) 2010, Zeljko Marjanovic (MPL 1.1)

    Released under the MIT Licence
}

interface
uses
  WinApi.Windows,
  WinApi.Winsock2,
  System.SysUtils,
  System.Classes,
  SocketUtils,
  libssh2;

type
  ESshError = class(Exception);
  // Used for user input (password entry, known host verification)
  // If Echo is False the response should be masked
  TKeybInteractiveCallback = function(const AuthName, AuthInstruction, Prompt: string;
    Echo: Boolean): string;
  TTransferProgressCallback = procedure(const AFileName: string; ATransfered, ATotal: UInt64);

  TAuthMethod = (amInteractive, amPassword, amKey, amHostBased);
  TAuthMethods = set of TAuthMethod;

  TSessionState = (session_Disconnected, session_Connected, session_Authorized);

  //KwonHost related
  TKnownHostCheckState = (khcsMatch, khcsMisMatch, khcsNotFound, khcsFailure);
  TKnownHostCheckAction = (khcaContinue, khcaStop, khcaAsk);
  TKnownHostCheckPolicy = array [TKnownHostCheckState] of TKnownHostCheckAction;
var
  DefKnownHostCheckPolicy: TKnownHostCheckPolicy = (khcaContinue, khcaAsk, khcaAsk, khcaAsk);

type
  TFilePermission = (fpOtherExec, fpOtherWrite, fpOtherRead,
                     fpGroupExec, fpGroupWrite, fpGroupRead,
                     fpUserExec, fpUserWrite, fpUserRead);
  TFilePermissions = set of TFilePermission;

const
   FPAllUser =  [fpUserRead, fpUserWrite, fpUserExec];
   FPAllGroup = [fpGroupRead, fpGroupWrite, fpGroupExec];
   FPAllOther = [fpOtherRead, fpOtherWrite, fpOtherExec];
   FPDefault =  FPAllUser + [fpGroupRead, fpGroupExec, fpOtherRead, fpOtherExec];

type
  ILibSsh2 = interface
    ['{EF87E36A-957B-49CA-9680-FEFBF1CE92B2}']
    function GetVersion: string;
    property Version: string read GetVersion;
  end;

  ISshSession = interface
    ['{D1921C45-7838-4E30-B511-6C4AE6C6E4DC}']
    function GetAddr: PLIBSSH2_SESSION;
    function GetSocket: TSocket;
    function GetSessionState: TSessionState;
    function GetBlocking: Boolean;
    procedure SetBlocking(Block: Boolean);
    procedure SetUseCompression(Compress: Boolean);
    function GetHostBanner: string;
    function GetSessionMethods: string;
    function GetWindowsHost: Boolean;
    function GetCodePage: Word;
    procedure SetCodePage(const CP: Word);
    procedure SetKeybInteractiveCallback(Callback: TKeybInteractiveCallback);
    procedure ConfigKeepAlive(WantServerReplies: Boolean; IntervalInSecs: Cardinal);
    procedure ConfigKnownHostCheckPolicy(EnableCheck: Boolean;
      const Policy: TKnownHostCheckPolicy; const KnownHostsFile: string = '');
    procedure Connect(IPVersion: TIPVersion = IPv4);
    procedure Disconnect;
    function AuthMethods(UserName: string): TAuthMethods;
    {
      UserAuth tries None, Agent, Interactive and Password authorizations.
      For the latter two the KeybInteractiveCallback needs to be set
    }
    function UserAuth(const UserName: string): Boolean;
    function UserAuthNone(const UserName: string): Boolean;
    function UserAuthPass(const UserName, Password: string): Boolean;
    function UserAuthInteractive(const UserName: string): Boolean;
    // Uses TKeybInteractiveCallback (needs to be set) to get the passphrase
    function UserAuthKey(const UserName: string; PrivateKeyFile: string): Boolean; overload;
    // PassPhrase can be nil
    function UserAuthKey(const UserName: string; PrivateKeyFile: string; PassPhrase: string): Boolean; overload;
    function UserAuthAgent(const UserName: string): Boolean;
    function GetUserName: string;
    // Set timeout for blocking functions
    // - aTimeoutInMs: Timeout in milliseconds.
    procedure SetTimeout(aTimeoutInMs: LongInt);
    property Addr: PLIBSSH2_SESSION read GetAddr;
    property SessionState: TSessionState read GetSessionState;
    property Blocking: Boolean read GetBlocking write SetBlocking;
    property UseCompression: Boolean write SetUseCompression;
    property HostBanner: string read GetHostBanner;
    property WindowsHost: Boolean read GetWindowsHost;
    property SessionMethods: string read GetSessionMethods;
    { The host code page.  Default CP_UTF8}
    property CodePage: Word read GetCodePage write SetCodePage;
    property UserName: string read GetUserName;
    property Socket: TSocket read GetSocket;
  end;

type
  IScp = interface
    ['{A780AD77-2D29-499F-8062-B1B18F9E55A8}']
    procedure SetBufferSize(Size: Int64);
    procedure SetTransferProgressCallback(Callback: TTransferProgressCallback);
    procedure Cancel;
    procedure Receive(const RemoteFile: string; Stream: TStream); overload;
    procedure Receive(const RemoteFile, LocalFile: string); overload;
    procedure Send(Stream: TStream; const RemoteFile: string;
      Permissions: TFilePermissions = FPDefault;
      MTime: TDateTime = 0; ATime: TDateTime = 0); overload;
    procedure Send(const LocalFile, RemoteFile: string;
      Permissions: TFilePermissions = FPDefault;
      MTime: TDateTime = 0; ATime: TDateTime = 0); overload;
    property BufferSize: Int64 write SetBufferSize;
  end;

  { Execute commands on the host and get Output/Errorcode back }
  ISshExec = interface
    ['{CA97A730-667A-4800-AF5D-77D5A4DDB192}']
    procedure SetBufferSize(Size: Int64);
    procedure Cancel;
    procedure Exec(const Command: string; var Output, ErrOutput: string; var ExitCode: Integer);
    property BufferSize: Int64 write SetBufferSize;
  end;

// Factory functions
function GetLibSsh2: ILibSsh2;
function CreateSession(Host: string; Port: Word = 22): ISshSession;
function CreateScp(Session: ISshSession): IScp;
function CreateSshExec(Session: ISshSession): ISshExec;

// support routines
function AnsiToUnicode(P: PAnsiChar; CP: Word): string; overload;
function AnsiToUnicode(P: PAnsiChar; Len: Int64; CP: Word): string; overload;
procedure CheckLibSsh2Result(ResultCode: Integer; Session: ISshSession; const Op: string);

var
  // Default timeout in milliseconds for block functions
  gDefaultSshTimeout: Integer = 30000;

implementation

uses
  System.Math,
  System.AnsiStrings,
  System.DateUtils;

{$region 'Support stuff'}
resourcestring
  Err_LibSsh2 = 'LibSSh2 error: %s (%d), on API "%s"';
  Err_SessionInit = 'LibSsh2 error: Failed to initialize session';
  Err_SessionAuth = 'LibSsh2 session is not connected and authorised';
  Err_SessionUnKnownHost = 'The authenticity of host "%s" can''t be established.';
  UnKnownHostPrompt = 'Do you want to continue connecting (yes/no)?';
  Msg_Disconnect = 'Bye';
  Msg_Password = 'Password: ';
  Msg_PrivateKeyInstruction = 'Private key password for "%s"';

function AnsiToUnicode(P: PAnsiChar; CP: Word): string;
Var
  S: RawByteString;
begin
  if P = nil then Exit('');

  S:= P;
  SetCodePage(S, CP, False);
  Result := string(S);
end;

function AnsiToUnicode(P: PAnsiChar; Len: Int64; CP: Word): string;
Var
  S: RawByteString;
begin
  if P = nil then Exit('');

  SetString(S, P, Len);
  SetCodePage(S, CP, False);
  Result := string(S);
end;

procedure CheckLibSsh2Result(ResultCode: Integer; Session: ISshSession; const Op: string);
var
  I: Integer;
  P: PAnsiChar;
  ErrMsg: string;
begin
  if ResultCode < 0 then
  begin
    if Session <> nil then
    begin
      // LIBSSH2_ERROR_EAGAIN indicates no result in non-blocking mode
      if ResultCode = LIBSSH2_ERROR_EAGAIN then Exit;
      libssh2_session_last_error(Session.Addr, P, I, 0);
      ErrMsg := AnsiToUnicode(P, I, Session.CodePage);
    end;
    raise ESshError.CreateResFmt(@Err_LibSsh2,
      [ErrMsg, ResultCode, Op])
  end;
end;
{$endregion}

{$region 'TLibSSh2'}
type
  TLibSSh2  = class(TInterfacedObject, ILibSsh2)
  private
    class var FInstanceCount: Integer;
    function GetVersion: string;
  public
    constructor Create;
    destructor Destroy; override;
  end;

{ TLibSSh2 }

constructor TLibSSh2.Create;
begin
  inherited;
  if AtomicIncrement(FInstanceCount) = 1 then
    CheckLibSsh2Result(libssh2_init(0), nil, 'libssh2_init');
end;

destructor TLibSSh2.Destroy;
begin
  if AtomicDecrement(FInstanceCount) = 0 then
    libssh2_exit();
  inherited;
end;

function TLibSSh2.GetVersion: string;
begin
  Result := string(libssh2_version(0));
end;
{$endregion}

{$region 'TSshSession'}
type
  TKnownHostCheckSettings = record
    EnableCheck: Boolean;
    Policy: TKnownHostCheckPolicy;
    KnownHostsFile: string;
  end;

  TSshSession = class(TInterfacedObject, ISshSession)
  private
    FState: TSessionState;
    FWinSock: IWinSock;
    FLibSsh2: ILibSsh2;
    FSock: TSocket;
    FAddr: PLIBSSH2_SESSION;
    FHost: string;
    FPort: Word;
    FUserName: string;
    FCompression: Boolean;
    FCodePage: Word;
    FAuthMethods: TAuthMethods;
    FAuthMethodsCached: Boolean;
    FKnownHostCheckSettings: TKnownHostCheckSettings;
    FKeybIntEvent: TKeybInteractiveCallback;
    function GetAddr: PLIBSSH2_SESSION;
    function GetSocket: TSocket;
    function GetSessionState: TSessionState;
    function GetBlocking: Boolean;
    procedure SetBlocking(Block: Boolean);
    procedure SetUseCompression(Compress: Boolean);
    function GetHostBanner: string;
    function GetSessionMethods: string;
    function GetWindowsHost: Boolean;
    function GetCodePage: Word;
    procedure SetCodePage(const CP: Word);
    procedure SetKeybInteractiveCallback(Callback: TKeybInteractiveCallback);
    procedure ConfigKeepAlive(WantServerReplies: Boolean; IntervalInSecs: Cardinal);
    procedure ConfigKnownHostCheckPolicy(EnableCheck: Boolean;
      const Policy: TKnownHostCheckPolicy; const KnownHostsFile: string = '');
    procedure Connect(IPVersion: TIPVersion = IPv4);
    procedure CheckKnownHost;
    function AuthMethods(UserName: string): TAuthMethods;
    function UserAuth(const UserName: string): Boolean;
    function UserAuthNone(const UserName: string): Boolean;
    function UserAuthPass(const UserName, Password: string): Boolean;
    function UserAuthInteractive(const UserName: string): Boolean;
    function UserAuthKey(const UserName: string; PrivateKeyFile: string): Boolean; overload;
    function UserAuthKey(const UserName: string; PrivateKeyFile: string; PassPhrase: string): Boolean; overload;
    function UserAuthAgent(const UserName: string): Boolean;
    function GetUserName: string;
    procedure Disconnect;
    // Set timeout for blocking functions
    // - aTimeoutInMs: Timeout in milliseconds.
    procedure SetTimeout(aTimeoutInMs: LongInt);
  public
    constructor Create(Host: string; Port: Word);
    destructor Destroy; override;
  end;

{ ----------------------------------------------------- }
{       Memory                                          }
{ ----------------------------------------------------- }

function  malloc(size: size_t; abstract: PPointer): Pointer; cdecl;
begin
  Result := AllocMem(size);
end;

function realloc(P: Pointer; NewSize: size_t; abstract: PPointer): Pointer; cdecl;
begin
  ReallocMem(P, Newsize);
  Result := P;
end;

procedure mfree(pBlock: Pointer; abstract: PPointer); cdecl;
begin
  FreeMem(pBlock);
end;

{ TSshSession }

procedure TSshSession.CheckKnownHost;
Var
  KnownHosts: PLIBSSH2_KNOWNHOSTS;
  ReturnCode: integer;
  M: TMarshaller;
  FingerPrint: PAnsiChar;
  KeyLen: NativeUInt;
  Typ: Integer;
  HostResult: PLIBSSH2_KNOWNHOST;
  Handle: THandle;

  procedure HandleState(State: TKnownHostCheckState);
  var
    Action: TKnownHostCheckAction;
  begin
    Action := FKnownHostCheckSettings.Policy[State];
    if (Action = khcaAsk) then
    begin
      if not Assigned(FKeybIntEvent) then
        Action := khcaStop
      else begin
        if FKeybIntEvent('', Format(Err_SessionUnKnownHost, [FHost]),
          UnKnownHostPrompt, True) = 'yes'
        then
          Action := khcaContinue
        else
          Action := khcaStop;
      end;
    end;
    if (Action = khcaContinue) and Assigned(KnownHosts) and Assigned(Fingerprint) then
    begin
      if libssh2_knownhost_addc(KnownHosts, M.AsAnsi(FHost, FCodePage).ToPointer, nil, FingerPrint,
        Keylen, nil, 0, LIBSSH2_KNOWNHOST_TYPE_PLAIN or LIBSSH2_KNOWNHOST_KEYENC_RAW
        //  LIBSSH2_HOSTKEY_TYPE_ -> LIBSSH2_KNOWNHOST_KEY_
        or (Succ(typ) shl LIBSSH2_KNOWNHOST_KEY_SHIFT), HostResult) = 0
      then
        libssh2_knownhost_writefile(KnownHosts,
          M.AsAnsi(FKnownHostCheckSettings.KnownHostsFile, FCodePage).ToPointer,
          LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    end;
    if Action = khcaStop then
      raise Exception.CreateResFmt(@Err_SessionUnKnownHost, [FHost]);
  end;

begin
  KnownHosts := nil;
  FingerPrint := nil;
  if not FileExists(FKnownHostCheckSettings.KnownHostsFile) then
  begin
    Handle := FileCreate(FKnownHostCheckSettings.KnownHostsFile);
    if Handle = INVALID_HANDLE_VALUE then
    begin
      HandleState(khcsFailure);
      Exit;
    end
    else
      FileClose(Handle);
  end;

  Fingerprint := libssh2_session_hostkey(FAddr, KeyLen, Typ);
  if FingerPrint = nil then
  begin
    HandleState(khcsFailure);
    Exit;
  end;

  KnownHosts := libssh2_knownhost_init(FAddr);
  if KnownHosts = nil then
  begin
    HandleState(khcsFailure);
    Exit;
  end;

  try
    ReturnCode := libssh2_knownhost_readfile(KnownHosts,
      M.AsAnsi(FKnownHostCheckSettings.KnownHostsFile, FCodePage).ToPointer,
      LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    if ReturnCode < 0 then
      HandleState(khcsFailure)
    else if ReturnCode = 0 then
      HandleState(khcsNotFound);
    if ReturnCode <= 0 then
      Exit;

    ReturnCode := libssh2_knownhost_checkp(KnownHosts, M.AsAnsi(FHost, FCodePage).ToPointer,
      FPort, Fingerprint, KeyLen, LIBSSH2_KNOWNHOST_TYPE_PLAIN or
      LIBSSH2_KNOWNHOST_KEYENC_RAW, HostResult);

    if ReturnCode <> LIBSSH2_KNOWNHOST_CHECK_MATCH then
      HandleState(TKnownHostCheckState(ReturnCode));

  finally
    libssh2_knownhost_free(KnownHosts);
  end;
end;

procedure TSshSession.ConfigKeepAlive(WantServerReplies: Boolean;
  IntervalInSecs: Cardinal);
{Note that non-blocking applications are responsible for sending the
keepalive messages using libssh2_keepalive_sendbegin}
begin
  libssh2_keepalive_config(FAddr, IfThen(WantServerReplies, 1, 0), IntervalInSecs);
end;

procedure TSshSession.ConfigKnownHostCheckPolicy(EnableCheck: Boolean;
  const Policy: TKnownHostCheckPolicy; const KnownHostsFile: string);
begin
  FKnownHostCheckSettings.EnableCheck := EnableCheck;
  if KnownHostsFile <> '' then
    FKnownHostCheckSettings.KnownHostsFile :=  KnownHostsFile;
  FKnownHostCheckSettings.Policy := Policy;
end;

procedure TSshSession.Connect(IPVersion: TIPVersion = IPv4);
begin
  FSock := FWinSock.CreateAndConnectSocket(FHost, FPort, IPVersion);
  FAddr := libssh2_session_init_ex(malloc, mfree, realloc, Pointer(Self));
  if Faddr = nil then
    raise ESshError.CreateRes(@Err_SessionInit);
  libssh2_session_flag(FAddr, LIBSSH2_FLAG_COMPRESS, IfThen(FCompression, 1, 0));

  //  libssh2_session_method_pref(FAddr, LIBSSH2_METHOD_KEX, 'curve25519-sha256');
  //  libssh2_session_method_pref(FAddr, LIBSSH2_METHOD_CRYPT_CS, 'aes256-ctr');
  //  libssh2_session_method_pref(FAddr, LIBSSH2_METHOD_CRYPT_SC, 'aes256-ctr');
  //  libssh2_session_method_pref(FAddr, LIBSSH2_METHOD_MAC_CS, 'hmac-sha2-512');
  //  libssh2_session_method_pref(FAddr, LIBSSH2_METHOD_MAC_SC, 'hmac-sha2-512');
  //  libssh2_session_method_pref(FAddr, LIBSSH2_METHOD_LANG_CS, 'en-US');
  //  libssh2_session_method_pref(FAddr, LIBSSH2_METHOD_LANG_SC, 'en-US');

  CheckLibSsh2Result(
    libssh2_session_handshake(FAddr, FSock),
    Self as TSshSession, 'libssh2_session_handshake');
  SetBlocking(True);  // blocking by default
  FState := session_Connected;
  SetTimeout(gDefaultSshTimeout);

  if FKnownHostCheckSettings.EnableCheck then
    try
      CheckKnownHost;
    except
      Disconnect;
      raise
    end;
end;

constructor TSshSession.Create(Host: string; Port: Word);
  function ExpandEnvStrings(const AString: String): String;
  var
    bufsize: Integer;
  begin
    bufsize := ExpandEnvironmentStrings(PChar(AString), nil, 0);
    SetLength(result, bufsize);
    ExpandEnvironmentStrings(PChar(AString), PChar(result), bufsize);
    result := TrimRight(result);
  end;
begin
  inherited Create;
  FKnownHostCheckSettings.EnableCheck := True;
  FKnownHostCheckSettings.Policy := DefKnownHostCheckPolicy;
  FKnownHostCheckSettings.KnownHostsFile := ExpandEnvStrings(
    IncludeTrailingPathDelimiter('%USERPROFILE%') + '.ssh\known_hosts');
  FWinSock := GetWinSock;
  FLibSsh2 := GetLibSsh2;
  FHost := Host;
  FPort := Port;
  FCodePage := CP_UTF8;
  FSock := INVALID_SOCKET;
end;

destructor TSshSession.Destroy;
begin
  Disconnect;
  FLibSsh2 := nil;
  FWinSock := nil;
  inherited;
end;

procedure TSshSession.Disconnect;
var
  M: TMarshaller;
begin
  if FAddr <> nil then
  begin
    libssh2_session_disconnect(FAddr, M.AsAnsi(Msg_Disconnect, FCodePage).ToPointer);
    libssh2_session_free(FAddr);
  end;
  FAddr := nil;
  if FSock <> INVALID_SOCKET then
    closesocket(FSock);
  FSock := INVALID_SOCKET;
  FState := session_Disconnected;
end;

function TSshSession.GetAddr: PLIBSSH2_SESSION;
begin
  Result := FAddr;
end;

function TSshSession.GetBlocking: Boolean;
begin
  Result := libssh2_session_get_blocking(FAddr) <> 0;
end;

function TSshSession.GetCodePage: Word;
begin
  Result := FCodePage;
end;

function TSshSession.GetHostBanner: string;
Var
  S: RawByteString;
begin
  S := libssh2_session_banner_get(FAddr);
  System.SetCodePage(S, FCodePage, False);
  Result := string(S);
end;

function TSshSession.GetSessionMethods: string;
begin
  Result := '';
  if FAddr <> nil then
    Result := Format('KEX: %s, CRYPT: %s, MAC: %s, COMP: %s, LANG: %s',
      [libssh2_session_methods(FAddr, LIBSSH2_METHOD_KEX), libssh2_session_methods(FAddr,
        LIBSSH2_METHOD_CRYPT_CS), libssh2_session_methods(FAddr, LIBSSH2_METHOD_MAC_CS),
      libssh2_session_methods(FAddr, LIBSSH2_METHOD_COMP_CS) + ' ' +
      libssh2_session_methods(FAddr, LIBSSH2_METHOD_COMP_SC),
      libssh2_session_methods(FAddr, LIBSSH2_METHOD_LANG_CS)]);
end;

function TSshSession.GetSessionState: TSessionState;
begin
   Result := FState;
end;

function TSshSession.GetSocket: TSocket;
begin
  Result := FSock;
end;

function TSshSession.GetUserName: string;
begin
  Result := FUserName;
end;

function TSshSession.GetWindowsHost: Boolean;
begin
  Result := Pos('Windows', GetHostBanner) > 0;
end;

procedure TSshSession.SetBlocking(Block: Boolean);
begin
  libssh2_session_set_blocking(Faddr, IfThen(Block, 1, 0))
end;

procedure TSshSession.SetCodePage(const CP: Word);
begin
  FCodePage := CP;
end;

procedure TSshSession.SetKeybInteractiveCallback(Callback: TKeybInteractiveCallback);
begin
  FKeybIntEvent := Callback;
end;

procedure TSshSession.SetUseCompression(Compress: Boolean);
begin
  FCompression := Compress;
end;

function TSshSession.AuthMethods(UserName: string): TAuthMethods;
var
  M: TMarshaller;
  PList: PAnsiChar;
  List: string;
begin
  if FAuthMethodsCached then Exit(FAuthMethods);

  FAuthMethods := [];
  PList := libssh2_userauth_list(FAddr, M.AsAnsi(UserName, FCodePage).ToPointer, Length(UserName));
  if Assigned(PList) then
  begin
    List := AnsiToUnicode(PList, FCodePage);
    if Pos('password', List) > 0 then Include(FAuthMethods, amPassword);
    if Pos('publickey', List) > 0 then Include(FAuthMethods, amKey);
    if Pos('keyboard-interactive', List) > 0 then Include(FAuthMethods, amInteractive);
    if Pos('hostbased', List) > 0 then Include(FAuthMethods, amHostBased);
  end
  else if libssh2_userauth_authenticated(FAddr) <> 0 then
    // Unlikely but SSH_USERAUTH_NONE succeded!
    FState := session_Connected;
  Result := FAuthMethods;
end;

procedure KbdInteractiveCallback(const Name: PAnsiChar; name_len: Integer;
  const instruction: PAnsiChar; instruction_len: Integer; num_prompts: Integer;
  const prompts: PLIBSSH2_USERAUTH_KBDINT_PROMPT;
  responses: PLIBSSH2_USERAUTH_KBDINT_RESPONSE;
    _abstract: PPointer); cdecl;
var
  Session: TSshSession;
  SName, SInstruction, SPrompt : RawByteString;
  PromptNo: Integer;
  Echo: Boolean;
  P: Pointer;
  Response: string;
  M: TMarshaller;
begin
  if _abstract = nil then Exit;
  Session := TSshSession(_abstract^);
  if not Assigned(Session.FKeybIntEvent) then Exit;

  SetString(SName, Name, name_len);
  SetCodePage(SName, Session.FCodePage, False);
  SetString(SInstruction, Instruction, instruction_len);
  SetCodePage(SInstruction, Session.FCodePage, False);
  {$POINTERMATH ON}
  for PromptNo := 0 to num_prompts - 1 do
  begin
    Echo := prompts[PromptNo].Echo <> 0;
    SetString(SPrompt, prompts[PromptNo].text, prompts[PromptNo].length);
    Response :=Session.FKeybIntEvent(
      string(SName), string(SInstruction), string(SPrompt), Echo);
    if Response <> '' then
    begin
      // libssh2 will be freeing the allocated memory!!
      P := AllocMem(Length(Response)+1);
      System.AnsiStrings.StrCopy(PAnsiChar(P),
        PAnsiChar(M.AsAnsi(Response, Session.FCodePage).ToPointer));
      responses[PromptNo].text := P;
      responses[PromptNo].length := Length(Response);
    end;
  end;
  {$POINTERMATH OFF}
end;

function TSshSession.UserAuth(const UserName: string): Boolean;
begin
  if FState = session_Authorized then Exit(True);
  if FState <> session_Connected then Exit(False);

  // Also sets FAuthMethods
  if UserAuthNone(UserName) then Exit(True);
  if (amKey in FAuthMethods) and UserAuthAgent(UserName) then Exit(True);
  // UserAuthInteractive also tries password authorization
  if (FAuthMethods * [amInteractive, amPassword] <> [])
    and UserAuthInteractive(UserName)
  then
    Exit(True)
  else
    Exit(False);
end;

function TSshSession.UserAuthNone(const UserName: string): Boolean;
begin
  if FState = session_Authorized then Exit(True);
  if FState <> session_Connected then Exit(False);

  FAuthMethods := AuthMethods(UserName);
  Result := FState = session_Authorized;
  if Result  then
    FUserName := UserName;
end;

function TSshSession.UserAuthAgent(const UserName: string): Boolean;
{
  Note that only pagent from Putty is supported on Windows
  https://github.com/libgit2/libgit2/issues/4958
}
var
  Agent: PLIBSSH2_AGENT;
  Identity, PrevIdentity: PLIBSSH2_AGENT_PUBLICKEY;
  ReturnCode: integer;
  M: TMarshaller;
begin
  if FState = session_Authorized then Exit(True);
  if (FState <> session_Connected) or not (amKey in AuthMethods(UserName)) then Exit(False);

  Result := False;
  Agent := libssh2_agent_init(FAddr);
  if not Assigned(Agent) then Exit(False);

  ReturnCode := libssh2_agent_connect(Agent);
  if ReturnCode = 0 then
  begin
    try
      ReturnCode := libssh2_agent_list_identities(Agent);
      if ReturnCode = 0 then
      begin
        PrevIdentity := nil;
        while True do
        begin
          ReturnCode := libssh2_agent_get_identity(Agent, Identity, PrevIdentity);
          if ReturnCode <> 0 then
            break;
          ReturnCode := libssh2_agent_userauth(Agent, M.AsAnsi(UserName, FCodePage).ToPointer, Identity);
          if ReturnCode = 0 then
          begin
            Result := True;
            break;
          end;
          PrevIdentity := Identity;
        end;
      end;
    finally
      libssh2_agent_disconnect(Agent);
      libssh2_agent_free(Agent);
    end;
  end;

  if Result then
  begin
    FState := session_Authorized;
    FUserName := UserName;
  end;
end;

function TSshSession.UserAuthInteractive(const UserName: string): Boolean;
{
  For some reason libssh2_userauth_keyboard_interactive does not work
  with Windows Hosts.  Do a libssh2_userauth_password instead if possible.
}
Var
  UName: TMarshaller;
  Methods: TAuthMethods;
begin
  if FState = session_Authorized then Exit(True);
  if (FState <> session_Connected) or not Assigned(FKeybIntEvent) then
    Exit(False);

  Methods := AuthMethods(UserName);
  if (amInteractive in Methods) and not GetWindowsHost then
    Result :=
      libssh2_userauth_keyboard_interactive(FAddr,
         UName.AsAnsi(UserName, FCodePage).ToPointer,
         KbdInteractiveCallback) = 0
  else if amPassword in Methods then
    Result := UserAuthPass(UserName, FKeybIntEvent('', '', Msg_Password, False))
  else
    Result := False;
  if Result then
  begin
    FState := session_Authorized;
    FUserName := UserName;
  end;
end;

function TSshSession.UserAuthKey(const UserName: string; PrivateKeyFile,
  PassPhrase: string): Boolean;
Var
  M: TMarshaller;
begin
  if FState = session_Authorized then Exit(True);
  if FState <> session_Connected then Exit(False);

  if amKey in AuthMethods(UserName) then
    Result := libssh2_userauth_publickey_fromfile(FAddr,
      M.AsAnsi(UserName, FCodePage).ToPointer,
      nil, M.AsAnsi(PrivateKeyFile, FCodePage).ToPointer,
      M.AsAnsi(PassPhrase, FCodePage).ToPointer) = 0
  else
    Result := False;

  if Result then
  begin
    FState := session_Authorized;
    FUserName := UserName;
  end;
end;

function TSshSession.UserAuthKey(const UserName: string;
  PrivateKeyFile: string): Boolean;
begin
  if FState = session_Authorized then Exit(True);
  if not Assigned(FKeybIntEvent) or not (amKey in AuthMethods(UserName)) then Exit(False);

  Result := UserAuthKey(UserName, PrivateKeyFile,
      FKeybIntEvent('', Format(Msg_PrivateKeyInstruction, [PrivateKeyFile]),
      Msg_Password, False));
end;

function TSshSession.UserAuthPass(const UserName, Password: string): Boolean;
Var
  M: TMarshaller;
begin
  if FState = session_Authorized then Exit(True);
  if FState <> session_Connected then Exit(False);

  Result :=
    (amPassword in AuthMethods(UserName)) and
    (libssh2_userauth_password(FAddr,
       M.AsAnsi(UserName, FCodePage).ToPointer,
       M.AsAnsi(PassWord, FCodePage).ToPointer) = 0);
  if Result then
  begin
    FState := session_Authorized;
    FUserName := UserName;
  end;
end;

procedure TSshSession.SetTimeout(aTimeoutInMs: LongInt);
begin
  libssh2_session_set_timeout(Faddr, aTimeoutInMs);
end;

{$endregion}

{$region 'TScp'}
type
  TScp = class(TInterfacedObject, IScp)
  private
    FBufferSize: Int64;
    FCancelled: Boolean;
    FTransferCallback: TTransferProgressCallback;
    FSession : ISshSession;
    procedure SetBufferSize(Size: Int64);
    procedure SetTransferProgressCallback(Callback: TTransferProgressCallback);
    procedure Cancel;
    procedure Receive(const RemoteFile: string; Stream: TStream); overload;
    procedure Receive(const RemoteFile, LocalFile: string); overload;
    procedure Send(Stream: TStream; const RemoteFile: string;
      Permissions: TFilePermissions = FPDefault;
      MTime: TDateTime = 0; ATime: TDateTime = 0); overload;
    procedure Send(const LocalFile, RemoteFile: string;
      Permissions: TFilePermissions = FPDefault;
      MTime: TDateTime = 0; ATime: TDateTime = 0); overload;
  public
    constructor Create(Session: ISshSession);
  end;

{ TScp }

procedure TScp.Cancel;
begin
  FCancelled := True;
end;

constructor TScp.Create(Session: ISshSession);
begin
  inherited Create;
  FSession := Session;
  FBufferSize := 8 * 1024 - 1;
end;

procedure TScp.Receive(const RemoteFile, LocalFile: string);
Var
  FileStream: TFileStream;
begin
  FileStream := TFileStream.Create(LocalFile, fmCreate or fmOpenWrite);
  try
    Receive(RemoteFile, FileStream);
  finally
    FileStream.Free;
  end;
end;

procedure TScp.Receive(const RemoteFile: string; Stream: TStream);
{ Assumes blocking session}
var
  Channel: PLIBSSH2_CHANNEL;
  Buffer: TBytes;
  M : TMarshaller;
  Stat: struct_stat;
  TotalBytesRead: ssize_t;
  BytesRead: ssize_t;
begin
  if FSession.SessionState <>  session_Authorized then
    raise ESshError.CreateRes(@Err_SessionAuth);

  FCancelled := False;
  Channel := libssh2_scp_recv2(FSession.Addr, M.AsAnsi(RemoteFile, FSession.CodePage).ToPointer, Stat);
  if Channel = nil then
    CheckLibSsh2Result(libssh2_session_last_errno(FSession.Addr), FSession, 'libssh2_scp_recv2');
  try
    SetLength(Buffer, FBufferSize);
    TotalBytesRead := 0;
    while TotalBytesRead < Stat.st_size do begin
      if FCancelled then Break;
      BytesRead := libssh2_channel_read(channel, PAnsiChar(Buffer), FBufferSize);
      if BytesRead < 0 then
        CheckLibSsh2Result(BytesRead, FSession, 'libssh2_channel_read');
      Inc(TotalBytesRead, BytesRead);
      if TotalBytesRead > Stat.St_Size then Dec(BytesRead);  // The last byte is #0
      Stream.Write(Buffer, BytesRead);
      if Assigned(FTransferCallback) then
        FTransferCallback(RemoteFile, TotalBytesRead, Stat.st_size);
    end;
  finally
    libssh2_channel_free(Channel);
  end;
end;

procedure TScp.Send(Stream: TStream; const RemoteFile: string;
  Permissions: TFilePermissions; MTime: TDateTime; ATime: TDateTime);
var
  Channel: PLIBSSH2_CHANNEL;
  M: TMarshaller;
  Buffer: TBytes;
  N, K, R: ssize_t;
  Buf: PAnsiChar;
  Transfered: UInt64;
begin
  if FSession.SessionState <>  session_Authorized then
    raise ESshError.CreateRes(@Err_SessionAuth);
  //
  FCancelled := False;
  Channel := libssh2_scp_send64(FSession.Addr,
    M.AsAnsi(RemoteFile, FSession.CodePage).ToPointer,
    Integer(Word(Permissions)), Stream.Size, IfThen(MTime = 0, DateTimeToUnix(MTime)),
    IfThen(ATime = 0, 0, DateTimeToUnix(ATime)));
  if Channel = nil then
    CheckLibSsh2Result(libssh2_session_last_errno(FSession.Addr), FSession, 'libssh2_scp_send64');

  SetLength(Buffer, FBufferSize);
  Transfered := 0;
  try
    repeat
      N := Stream.Read(Buffer, FBufferSize);
      if N > 0 then
      begin
        Buf := PAnsiChar(Buffer);
        K := N;
        repeat
          R := libssh2_channel_write(Channel, Buf, K);
          if R < 0 then
            CheckLibSsh2Result(R, FSession, 'libssh2_channel_write');;
          Inc(Transfered, R);
          Inc(Buf, R);
          Dec(K, R);
          if Assigned(FTransferCallback) then
            FTransferCallback(RemoteFile, Transfered, Stream.Size);
        until (K <= 0) or FCancelled;
      end;
    until (N <= 0) or FCancelled;
    libssh2_channel_send_eof(Channel);
    libssh2_channel_wait_eof(Channel);
    libssh2_channel_wait_closed(Channel);
  finally
    libssh2_channel_free(Channel);
  end;
end;

procedure TScp.Send(const LocalFile, RemoteFile: string;
  Permissions: TFilePermissions; MTime: TDateTime; ATime: TDateTime);
Var
  FileStream: TFileStream;
begin
  FileStream := TFileStream.Create(LocalFile, fmOpenRead);
  try
    Send(FileStream, RemoteFile, Permissions, MTime, ATime);
  finally
    FileStream.Free;
  end;
end;

procedure TScp.SetBufferSize(Size: Int64);
begin
  FBufferSize := Size;
end;

procedure TScp.SetTransferProgressCallback(Callback: TTransferProgressCallback);
begin
  FTransferCallback := Callback;
end;
{$endregion}

{$region 'TSshExec'}
type
  TSshExec = class(TInterfacedObject, ISshExec)
  private
    FSession : ISshSession;
    FBufferSize: Int64;
    FCancelled: Boolean;
    procedure SetBufferSize(Size: Int64);
    procedure Cancel;
    procedure Exec(const Command: string; var Output, ErrOutput: string; var ExitCode: Integer);
  public
    constructor Create(Session: ISshSession);
  end;

{ TSshExec }

procedure TSshExec.Cancel;
begin
  FCancelled := True;
end;

constructor TSshExec.Create(Session: ISshSession);
begin
  inherited Create;
  FSession := Session;
  FBufferSize := 8 * 1024 - 1;
end;

function ReadStringFromChannel(Session: ISshSession; Channel: PLIBSSH2_CHANNEL;
  Buf: PAnsiChar; BufLen: size_t; StreamId: Integer; Cancelled: PBoolean): string;
Var
  MemoryStream : TMemoryStream;
  BytesRead: ssize_t;
begin
  Result := '';
  if Cancelled^ then Exit;
  MemoryStream := TMemoryStream.Create;
  try
    Repeat
      BytesRead :=  libssh2_channel_read_ex(Channel, StreamId, Buf, BufLen);
      CheckLibSsh2Result(BytesRead, Session, 'libssh2_channel_read_ex');
      if BytesRead > 0 then
        MemoryStream.Write(Buf^, BytesRead);
    Until (BytesRead = 0) or Cancelled^;

    if MemoryStream.Size > 0 then
      Result := AnsiToUnicode(PAnsiChar(MemoryStream.Memory),
        MemoryStream.Size, Session.CodePage);
  finally
    MemoryStream.Free;
  end;
end;

procedure TSshExec.Exec(const Command: string; var Output, ErrOutput: string;
  var ExitCode: Integer);
var
  Channel: PLIBSSH2_CHANNEL;
  M: TMarshaller;
  Buffer: TBytes;
  TimeVal: TTimeVal;
  ReadFds: TFdSet;
  ReturnCode: integer;
begin
  if FSession.SessionState <>  session_Authorized then
    raise ESshError.CreateRes(@Err_SessionAuth);
  
  FCancelled := False;
  Channel := libssh2_channel_open_session(FSession.Addr);
  if Channel = nil then
    CheckLibSsh2Result(libssh2_session_last_errno(FSession.Addr), FSession,
     'libssh2_channel_open_session');

  try
    CheckLibSsh2Result(libssh2_channel_exec(Channel,
      M.AsAnsi(Command, FSession.CodePage).ToPointer),
      FSession, 'libssh2_channel_exec');

    // Wait until there is something to read on the Channel
    // Stop waiting if cancelled
    TimeVal.tv_sec := 1;  // check for cancel every one second
    TimeVal.tv_usec := 0;
    Repeat
      FD_ZERO(ReadFds);
      _FD_SET(FSession.Socket, ReadFds);
      ReturnCode := select(0, @ReadFds, nil, nil, @TimeVal);
      if ReturnCode < 0 then CheckSocketResult(WSAGetLastError, 'select');
    Until (ReturnCode > 0) or FCancelled;

    if not FCancelled then
    begin
      SetLength(Buffer, FBufferSize);
      Output := ReadStringFromChannel(FSession, Channel, PAnsiChar(Buffer),
        FBufferSize, 0, @FCancelled);
      ErrOutput := ReadStringFromChannel(FSession, Channel, PAnsiChar(Buffer),
        FBufferSize, SSH_EXTENDED_DATA_STDERR, @FCancelled);
    end;

    if FCancelled then
      // Do not wait for response
      // Note that the remote process may still be running after we exit
      FSession.Blocking := False;
    // libssh2_channel_close sends SSH_MSG_CLOSE to the host
    libssh2_channel_close(Channel);
    if FCancelled then
      ExitCode := 130 // ^C on Linux
    else
      Exitcode := libssh2_channel_get_exit_status(Channel);
  finally
    libssh2_channel_free(Channel);
    FSession.Blocking := True;
  end;
end;

procedure TSshExec.SetBufferSize(Size: Int64);
begin
  FBufferSize := Size;
end;

{$endregion}

{$region 'Factory Methods'}
function GetLibSsh2: ILibSsh2;
begin
  Result := TLibSsh2.Create;
end;

function CreateSession(Host: string; Port: Word): ISshSession;
begin
  Result := TSshSession.Create(Host, Port);
end;

function CreateScp(Session: ISshSession): IScp;
begin
  Result := TScp.Create(Session);
end;


function CreateSshExec(Session: ISshSession): ISshExec;
begin
    Result := TSshExec.Create(Session);
end;


{$endregion}


end.
