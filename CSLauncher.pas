unit CSLauncher;

interface
var
dllDirFullPath: string;
procedure InjectToGw(); { include / }

implementation

uses
  SysUtils, GWCAMemory, CharSelector,Logger;

type
  NTSTATUS = Integer;
  PLUID = ^TLUID;

  _LUID = record
    LowPart: Cardinal;
    HighPart: INT32;
  end;

  TLUID = _LUID;
  LUID = _LUID;
  PLUIDAndAttributes = ^TLUIDAndAttributes;

  _LUID_AND_ATTRIBUTES = packed record
    LUID: Int64;
    Attributes: Cardinal;
  end;

  TLUIDAndAttributes = _LUID_AND_ATTRIBUTES;
  LUID_AND_ATTRIBUTES = _LUID_AND_ATTRIBUTES;

  PTokenPrivileges = ^TTokenPrivileges;

  _TOKEN_PRIVILEGES = record
    PrivilegeCount: Cardinal;
    Privileges: array [0 .. 0] of TLUIDAndAttributes;
  end;

  TTokenPrivileges = _TOKEN_PRIVILEGES;
  TOKEN_PRIVILEGES = _TOKEN_PRIVILEGES;

  TCharSelector = class(TMainForm)
  private
    GwPid: THandle;
    Gwindex: array of Cardinal;
    module: Cardinal;
  private
    procedure Init(sender: TObject);
    procedure Inject(sender: TObject);
    procedure UpGwPid(sender: TObject);
  protected
    constructor Create(); overload;
    destructor destroy;
  end;

const
  TOKEN_ADJUST_PRIVILEGES = $0020;
  SE_PRIVILEGE_ENABLED = $00000002;

var
  mGWHandle: Cardinal = 0; // get from winlist
  mGWThreadHandle: THandle = 0; // for openprocess to open
  mOpenedGWHandle: THandle = 0; // returned from openedprocess
  GWProcessList: TGWProcessesList;
{$REGION 'DllCall'}
function GetWindowThreadProcessId(hWnd: THandle;
  lpdwProcessId: PCardinal): Cardinal; stdcall;
external 'User32.dll' name 'GetWindowThreadProcessId';

function NtOpenProcessToken(ProcessHandle: THandle; DesiredAccess: Cardinal;
  TokenHandle: PCardinal): NTSTATUS; stdcall;
external 'ntdll.dll' name 'NtOpenProcessToken';

function GetCurrentProcess(
): THandle; stdcall;
external 'Kernel32.dll' name 'GetCurrentProcess';

function LookupPrivilegeValueW(lpSystemName: PWideChar; lpName: PWideChar;
  lpLuid: PLUID): LongBool; stdcall;
external 'Advapi32.dll' name 'LookupPrivilegeValueW';

function AdjustTokenPrivileges(TokenHandle: THandle;
  DisableAllPrivileges: LongBool; NewState: PTokenPrivileges;
  BufferLength: Cardinal; PreviousState: PTokenPrivileges;
  ReturnLength: PCardinal): LongBool; stdcall;
external 'Advapi32.dll' name 'AdjustTokenPrivileges';
{$ENDREGION}

function EnableDebug(out hToken: THandle): Boolean;
Const
  SE_DEBUG_NAME = 'SeDebugPrivilege';
var
  _Luit: LUID;
  TP: TOKEN_PRIVILEGES;
  RetLen: Cardinal;
begin
  Result := False;
  hToken := 0;
  if NtOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, @hToken)
    <> 0 then
    Exit;
  if not LookupPrivilegeValueW(nil, SE_DEBUG_NAME, @_Luit) then
  begin
    Exit;
  end;
  TP.PrivilegeCount := 1;
  TP.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
  TP.Privileges[0].LUID := Int64(_Luit);
  RetLen := 0;
  Result := AdjustTokenPrivileges(hToken, False, @TP, SizeOf(TP), nil, @RetLen);
end;

{ TCharSelector }

constructor TCharSelector.Create();
begin
  inherited Create(nil);
  Self.OnCreate := Self.Init;
  Self.RzBitBtn2.OnClick := Self.Inject;
  Self.RzComboBox1.OnSelect := UpGwPid;
end;

destructor TCharSelector.destroy;
begin
  SetLength(Gwindex, 0);
  inherited destroy;
end;

procedure TCharSelector.Init(sender: TObject);
var
  I: Cardinal;
begin

  with Self.RzComboBox1 do
  begin
    Clear;
    if GWProcessList.count = 0 then
      Exit;
    GwPid := GWProcessList.items[0].handle;
   // SetLength(Gwindex, GWProcessList.count);
    for I := 0 to GWProcessList.count - 1 do
    begin
   // Gwindex[I]:=GWProcessList.items[I].handle;
    items.Add(GWProcessList.items[I].Name);
    end;
    ItemIndex:=0;
    Self.GroupBox1.Caption:=Self.GroupBox1.Caption  + ' ' + IntToStr(GWProcessList.count) + ' 个';
   // ReadOnly:=True;
  end;

end;

procedure TCharSelector.Inject(sender: TObject);
begin
  if GWCAMemory.Inject(Self.GwPid, dllDirFullPath + 'GWTOOLBOX.DLL',
    Self.module,True) <> SUCCESSFUL_LOADMODULE then
    ExceptClass.Create('注入失败了！')
  else
    Self.Close;
end;

procedure TCharSelector.UpGwPid(sender: TObject);
begin
  GwPid := GWProcessList.items[Self.RzComboBox1.ItemIndex].handle;
end;

procedure InjectToGw();
var
  module: Cardinal;
  CharSelector: TCharSelector;
  mDebugedHandle: THandle;
  status:TLOADMODULERESULT;
begin
   mDebugedHandle := 0;
  if Not EnableDebug(mDebugedHandle) then
    Exit;
  if not GWInjectList(GWProcessList) then
    Exit;
  try
    if dllDirFullPath = '' then
      dllDirFullPath := Extractfilepath(ParamStr(0));

    if GWProcessList.count > 1 then
    begin
      CharSelector := TCharSelector.Create;
      try
        CharSelector.ShowModal;
      finally
        CharSelector.Free;
      end;
    end
    else
    begin
      status:= Inject(GWProcessList.items[0].handle,
        dllDirFullPath + 'GWTOOLBOX.DLL', module,True);
        if status <> SUCCESSFUL_LOADMODULE then
        begin
        Logger.Initialize;
        Writeln('注入失败，错误代码:' + IntToStr(ord(status)));
        Writeln('按任意键退出');
        Logger.Terminate;
        Exit;
        end;
    end;
  finally
    if mDebugedHandle <> 0 then
      NtClose(mDebugedHandle);
  end;
end;

initialization

end.
