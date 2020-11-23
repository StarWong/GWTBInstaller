unit GWCAMemory;

interface

type

    TCharNameOp = record
    op: array [0 .. 11] of Byte;
    offset: Integer;
    function GetCharName(const buffer: Pointer): LongBool;
  end;

  TLOADMODULERESULT = (SUCCESSFUL_LOADMODULE, MODULE_NONEXISTANT,
    KERNEL32_NOT_FOUND, LOADLIBRARY_NOT_FOUND, MEMORY_NOT_ALLOCATED,
    PATH_NOT_WRITTEN, PATH_WRITTEN_INVID_CONTEXT, MEMORY_READ_FAILURE,
    REMOTE_THREAD_NOT_SPAWNED, REMOTE_THREAD_DID_NOT_FINISH,
    MEMORY_NOT_DEALLOCATED, PROCESS_NOT_OPENED);

  TGWProcess = record
    handle: THandle;
    Name: string;
    charName: array [0 .. 14] of WideChar end;

    TGWProcessesList = record count: Cardinal;
    items: array [0 .. 10] of TGWProcess // index:=0,count of items
      end;
    TInject = function(const GwPid: THandle; const GWToolBoxPath: string;
      Out module: Cardinal; DoOpen: LongBool = False): TLOADMODULERESULT;
  var
    GWDESCRIPTION: string = 'Guild Wars Game Client';
    InjectModuleName: string = 'GWTOOLBOX.DLL';
    charNameOp: TCharNameOp;
    { = (op: ($8B, $F8, $6A, $03, $68, $0F, $00, $00, $C0,
      $8B, $CF, $E8); offset: - $42); }
    Inject: TInject;
{$REGION 'Forward declarations'}
    function GWInjectList(var processesList: TGWProcessesList): LongBool;
{$ENDREGION}
    function CloseHandle(hObject: THandle): LongBool;
    stdcall;external 'Kernel32.dll' name 'CloseHandle';
    function NtClose(Handle:THandle):Integer;
    stdcall;external 'ntdll.dll' name 'NtClose';

implementation
 {$IFDEF DEBUG} {$ENDIF}
uses
  TlHelp32, SysUtils,Logger;

type
     _CLIENT_ID = record
       UniqueProcess: tHANDLE;
       UniqueThread: tHANDLE;
     end;
     CLIENT_ID = _CLIENT_ID;
     PCLIENT_ID = ^CLIENT_ID;
     TClientID = CLIENT_ID;
     PClientID = ^TClientID;

  PUNICODE_STRING = ^UNICODE_STRING;

  UNICODE_STRING = record
    Length: Word;
    MaximumLength: Word;
    Buffer: pwidechar;
  end;
  {$MINENUMSIZE 4}
  TSecurityImpersonationLevel = (SecurityAnonymous,
  SecurityIdentification, SecurityImpersonation, SecurityDelegation);
  {$MINENUMSIZE 1}
  PSecurityQualityOfService = ^TSecurityQualityOfService;
  SECURITY_CONTEXT_TRACKING_MODE = Boolean;
  _SECURITY_QUALITY_OF_SERVICE = record
    Length: Cardinal;
    ImpersonationLevel: TSecurityImpersonationLevel;
    ContextTrackingMode: SECURITY_CONTEXT_TRACKING_MODE;
    EffectiveOnly: Boolean;
  end;

  TSecurityQualityOfService = _SECURITY_QUALITY_OF_SERVICE;
  SECURITY_QUALITY_OF_SERVICE = _SECURITY_QUALITY_OF_SERVICE;
  PSecurityDescriptor = Pointer;

    _OBJECT_ATTRIBUTES = record
    Length: Cardinal;
    RootDirectory: THandle;
    ObjectName: PUNICODE_STRING;
    Attributes: Cardinal;
    SecurityDescriptor: PSecurityDescriptor;
    SecurityQualityOfService: PSecurityQualityOfService;
  end;

  OBJECT_ATTRIBUTES = _OBJECT_ATTRIBUTES;
  POBJECT_ATTRIBUTES = ^OBJECT_ATTRIBUTES;

  TEXEVersionData = record
    CompanyName, FileDescription, FileVersion, InternalName, LegalCopyright,
      LegalTrademarks, OriginalFileName, ProductName, ProductVersion, Comments,
      PrivateBuild, SpecialBuild: string;
  end;

  TQUERYFILEINFORESULT = (SUCCESSFULL_QUERYFILEINFOR,
    ERROR_GetFileVersionInfoSizeW, ERROR_GetFileVersionInfoW,
    ERROR_VerQueryValueW,ERROR_UNKNOW);

  TProcess = tagPROCESSENTRY32;
  PProcess = ^TProcess;
  TModule = tagMODULEENTRY32;

  GWCAMemoryX32 = class
  strict private
    //class var scan_Start: Pointer;
    //class var scan_Size: Cardinal;
    //class var memory_Dump: array of Byte;
    class var process: PProcess;
    class var imageBase: Pointer;
    class var imageSize: Cardinal;
    class var processName: string;
    class var OpenedHandle:THandle;
  strict private
    class function HaveModule(const name: string): LongBool; static;
    class function WriteBytes(const handleOpened: THandle; startaddr: Pointer;
      pBuffer: Pointer; bufferSize: Cardinal): LongBool; static;
  public
    class procedure InitScanner(var process: TProcess); static;
    class function ReadBytes(startaddr: Pointer; bufferSize: Cardinal;
      var pBuffer: array of Byte): LongBool; static;
    class function OfflineScan(signature: array of Byte; offset: Int64;
      readptr: LongBool = False): Pointer; static;
    class function LoadModule(const Pid: THandle; const moduleFullPath: string;
      out module: Cardinal; DoOpen: LongBool = False): TLOADMODULERESULT; static;
    class function IsSpecialProcess: LongBool;static;
    class function IsSpecialDescription(const fullFilePath:string): LongBool;static;
    class function EnableProcessOpened(handleToOpen:Cardinal = 0):LongBool;static;
    class procedure DisableProcessOpened;static;
  end;

  SIZE_T = Cardinal;
  PSIZE_T = ^SIZE_T;
  NTSTATUS = Integer;
  PHANDLE = ^THandle;



const
  NT_SUCC: Integer = 0;

{$REGION 'DllCall'}
function GetModuleHandleW(lpModuleName: PWideChar): THandle; stdcall;
external 'kernel32.dll' name 'GetModuleHandleW';

function PathFileExistsW(pszPath: PWideChar): LongBool; stdcall;
external 'Shlwapi.dll' name 'PathFileExistsW';

function GetProcAddress(HMODULE: THandle; lpProcName: PAnsiChar): Pointer;
  stdcall; external 'Kernel32.dll' name 'GetProcAddress';

function VirtualAllocEx(hProcess: THandle; lpAddress: Pointer; dwSize: SIZE_T;
  flAllocationType: Cardinal; flProtect: Cardinal): Pointer; stdcall;
external 'Kernel32.dll' name 'VirtualAllocEx';

function NtOpenProcess(ProcessHandle: PHANDLE; DesiredAccess: Cardinal;
  ObjectAttributes: Pointer; { vista++,win2008++,must be nil pointer }
  ClientId: Pointer { vista++,win2008++,must be nil pointer }
): NTSTATUS; stdcall; external 'ntdll.dll' name 'NtOpenProcess';

function NtAllocateVirtualMemory(ProcessHandle: THandle; BaseAddress: PPointer;
  ZeroBits: PCardinal; RegionSize: PSIZE_T; AllocationType: Cardinal;
  Protect: Cardinal): NTSTATUS; stdcall;
external 'ntdll.dll' name 'NtAllocateVirtualMemory';

function NtFreeVirtualMemory(ProcessHandle: THandle; BaseAddress: PPointer;
  RegionSize: PSIZE_T; FreeType: Cardinal): NTSTATUS; stdcall;
external 'ntdll.dll' name 'NtFreeVirtualMemory';

function NtWriteVirtualMemory(ProcessHandle: THandle; BaseAddress: Pointer;
  buffer: Pointer; bufferSize: SIZE_T;
  NumberOfBytesWritten: PSIZE_T): NTSTATUS; stdcall;
external 'ntdll.dll' name 'NtWriteVirtualMemory';

function NtReadVirtualMemory(ProcessHandle: THandle; BaseAddress: Pointer;
  buffer: Pointer; bufferSize: SIZE_T;var NumberOfBytesRead: SIZE_T): NTSTATUS;
  stdcall; external 'ntdll.dll' name 'NtReadVirtualMemory';

function CreateRemoteThread(hProcess: THandle; lpThreadAttributes: Pointer;
  dwStackSize: SIZE_T; lpStartAddress: Pointer; lpParameter: Pointer;
  dwCreationFlags: Cardinal; lpThreadId: PCardinal): THandle; stdcall;
external 'Kernel32.dll' name 'CreateRemoteThread';

function WaitForSingleObject(hHandle: THandle;
  dwMilliseconds: Cardinal): Cardinal; stdcall;
external 'Kernel32.dll' name 'WaitForSingleObject';

function GetExitCodeThread(hThread: THandle; lpExitCode: PCardinal): LongBool;
  stdcall; external 'Kernel32.dll' name 'GetExitCodeThread';

function GetFileVersionInfoSizeW(lptstrFilename: string;
  lpdwHandle: PCardinal): Cardinal; stdcall;
external 'version.dll' name 'GetFileVersionInfoSizeW';

function VerQueryValueW(pBlock: Pointer; lpSubBlock: PWideChar;
  var lplpBuffer: Pointer;var  puLen: Cardinal): LongBool; stdcall;
external 'version.dll' name 'VerQueryValueW';

function GetFileVersionInfoW(lptstrFilename: string; dwHandle: Cardinal;
  dwLen: Cardinal; lpData: Pointer): LongBool; stdcall;
external 'version.dll' name 'GetFileVersionInfoW';

function IsBadReadPtr(lp: Pointer; ucb: SIZE_T): LongBool;
external 'Kernel32.dll' name 'IsBadReadPtr';

function GetCurrentProcessId:Cardinal;
external 'Kernel32.dll' name 'GetCurrentProcessId';

{$ENDREGION}
{$REGION 'CompareMem'}

function CompareMem(P1, P2: Pointer; Length: Integer): Boolean;
assembler;
asm
   add   eax, ecx
   add   edx, ecx
   xor   ecx, -1
   add   eax, -8
   add   edx, -8
   add   ecx, 9
   push  ebx
   jg    @Dword
   mov   ebx, [eax+ecx]
   cmp   ebx, [edx+ecx]
   jne   @Ret0
   lea   ebx, [eax+ecx]
   add   ecx, 4
   and   ebx, 3
   sub   ecx, ebx
   jg    @Dword
@DwordLoop:
   mov   ebx, [eax+ecx]
   cmp   ebx, [edx+ecx]
   jne   @Ret0
   mov   ebx, [eax+ecx+4]
   cmp   ebx, [edx+ecx+4]
   jne   @Ret0
   add   ecx, 8
   jg    @Dword
   mov   ebx, [eax+ecx]
   cmp   ebx, [edx+ecx]
   jne   @Ret0
   mov   ebx, [eax+ecx+4]
   cmp   ebx, [edx+ecx+4]
   jne   @Ret0
   add   ecx, 8
   jle   @DwordLoop
@Dword:
   cmp   ecx, 4
   jg    @Word
   mov   ebx, [eax+ecx]
   cmp   ebx, [edx+ecx]
   jne   @Ret0
   add   ecx, 4
@Word:
   cmp   ecx, 6
   jg    @Byte
   movzx ebx, word ptr [eax+ecx]
   cmp   bx, [edx+ecx]
   jne   @Ret0
   add   ecx, 2
@Byte:
   cmp   ecx, 7
   jg    @Ret1
   movzx ebx, byte ptr [eax+7]
   cmp   bl, [edx+7]
   jne   @Ret0
@Ret1:
   mov   eax, 1
   pop   ebx
   ret
@Ret0:
   xor   eax, eax
   pop   ebx
end;
{$ENDREGION}
{$REGION 'CompareText'}
  function CompareText(const S1, S2: string): Integer;
{$IFNDEF UNICODE}
asm
        TEST   EAX, EAX
        JNZ    @@CheckS2
        TEST   EDX, EDX
        JZ     @@Ret
        MOV    EAX, [EDX-4]
        NEG    EAX
@@Ret:
        RET
@@CheckS2:
        TEST   EDX, EDX
        JNZ    @@Compare
        MOV    EAX, [EAX-4]
        RET
@@Compare:
        PUSH   EBX
        PUSH   EBP
        PUSH   ESI
        PUSH   0
        PUSH   0
        CMP    WORD PTR [EAX-10],1
        JE     @@S1IsAnsi

        PUSH   EDX
        MOV    EDX,EAX
        LEA    EAX,[ESP+4]
        CALL   System.@LStrFromUStr
        POP    EDX
        MOV    EAX,[ESP]

@@S1IsAnsi:
        CMP    WORD PTR [EDX-10],1
        JE     @@S2IsAnsi

        PUSH   EAX
        LEA    EAX,[ESP+8]
        CALL   System.@LStrFromUStr
        POP    EAX
        MOV    EDX,[ESP+4]

@@S2IsAnsi:
        MOV    EBP, [EAX-4]     // length(S1)
        MOV    EBX, [EDX-4]     // length(S2)
        SUB    EBP, EBX         // Result if All Compared Characters Match
        SBB    ECX, ECX
        AND    ECX, EBP
        ADD    ECX, EBX         // min(length(S1),length(S2)) = Compare Length
        LEA    ESI, [EAX+ECX]   // Last Compare Position in S1
        ADD    EDX, ECX         // Last Compare Position in S2
        NEG    ECX
        JZ     @@SetResult      // Exit if Smallest Length = 0
@@Loop:                         // Load Next 2 Chars from S1 and S2
                                // May Include Null Terminator}
        MOVZX  EAX, WORD PTR [ESI+ECX]
        MOVZX  EBX, WORD PTR [EDX+ECX]
        CMP    EAX, EBX
        JE     @@Next           // Next 2 Chars Match
        CMP    AL, BL
        JE     @@SecondPair     // First Char Matches
        MOV    AH, 0
        MOV    BH, 0
        CMP    AL, 'a'
        JL     @@UC1
        CMP    AL, 'z'
        JG     @@UC1
        SUB    EAX, 'a'-'A'
@@UC1:
        CMP    BL, 'a'
        JL     @@UC2
        CMP    BL, 'z'
        JG     @@UC2
        SUB    EBX, 'a'-'A'
@@UC2:
        SUB    EAX, EBX         // Compare Both Uppercase Chars
        JNE    @@Done           // Exit with Result in EAX if Not Equal
        MOVZX  EAX, WORD PTR [ESI+ECX] // Reload Same 2 Chars from S1
        MOVZX  EBX, WORD PTR [EDX+ECX] // Reload Same 2 Chars from S2
        CMP    AH, BH
        JE     @@Next           // Second Char Matches
@@SecondPair:
        SHR    EAX, 8
        SHR    EBX, 8
        CMP    AL, 'a'
        JL     @@UC3
        CMP    AL, 'z'
        JG     @@UC3
        SUB    EAX, 'a'-'A'
@@UC3:
        CMP    BL, 'a'
        JL     @@UC4
        CMP    BL, 'z'
        JG     @@UC4
        SUB    EBX, 'a'-'A'
@@UC4:
        SUB    EAX, EBX         // Compare Both Uppercase Chars
        JNE    @@Done           // Exit with Result in EAX if Not Equal
@@Next:
        ADD    ECX, 2
        JL     @@Loop           // Loop until All required Chars Compared
@@SetResult:
        MOV    EAX, EBP         // All Matched, Set Result from Lengths
@@Done:
        MOV    ECX,ESP
        MOV    EDX,[ECX]
        OR     EDX,[ECX + 4]
        JZ     @@NoClear
        PUSH   EAX
        MOV    EAX,ECX
        MOV    EDX,2
        CALL   System.@LStrArrayClr
        POP    EAX
@@NoClear:
        ADD    ESP,8
        POP    ESI
        POP    EBP
        POP    EBX
end;
{$ELSE}
  (* ***** BEGIN LICENSE BLOCK *****
    *
    * The function CompareText is licensed under the CodeGear license terms.
    *
    * The initial developer of the original code is Fastcode
    *
    * Portions created by the initial developer are Copyright (C) 2002-2004
    * the initial developer. All Rights Reserved.
    *
    * Contributor(s): John O'Harrow
    *
    * ***** END LICENSE BLOCK ***** *)
asm
        TEST   EAX, EAX
        JNZ    @@CheckS2
        TEST   EDX, EDX
        JZ     @@Ret
        MOV    EAX, [EDX-4]
        NEG    EAX
@@Ret:
        RET
@@CheckS2:
        TEST   EDX, EDX
        JNZ    @@Compare
        MOV    EAX, [EAX-4]
        RET
@@Compare:
        PUSH   EBX
        PUSH   EBP
        PUSH   ESI
        PUSH   0
        PUSH   0
        CMP    WORD PTR [EAX-10],2
        JE     @@S1IsUnicode

        PUSH   EDX
        MOV    EDX,EAX
        LEA    EAX,[ESP+4]
        CALL   System.@UStrFromLStr
        POP    EDX
        MOV    EAX,[ESP]

@@S1IsUnicode:
        CMP    WORD PTR [EDX-10],2
        JE     @@S2IsUnicode

        PUSH   EAX
        LEA    EAX,[ESP+8]
        CALL   System.@UStrFromLStr
        POP    EAX
        MOV    EDX,[ESP+4]

@@S2IsUnicode:
        MOV    EBP, [EAX-4]     // length(S1)
        MOV    EBX, [EDX-4]     // length(S2)
        SUB    EBP, EBX         // Result if All Compared Characters Match
        SBB    ECX, ECX
        AND    ECX, EBP
        ADD    ECX, EBX         // min(length(S1),length(S2)) = Compare Length
        LEA    ESI, [EAX+ECX*2] // Last Compare Position in S1
        ADD    EDX, ECX         // Last Compare Position in S2
        ADD    EDX, ECX         // Last Compare Position in S2
        NEG    ECX
        JZ     @@SetResult      // Exit if Smallest Length = 0
@@Loop:                         // Load Next 2 Chars from S1 and S2
                                // May Include Null Terminator}
        MOV    EAX, [ESI+ECX*2]
        MOV    EBX, [EDX+ECX*2]
        CMP    EAX,EBX
        JE     @@Next           // Next 2 Chars Match
        CMP    AX,BX
        JE     @@SecondPair     // First Char Matches
        AND    EAX,$0000FFFF
        AND    EBX,$0000FFFF
        CMP    EAX, 'a'
        JL     @@UC1
        CMP    EAX, 'z'
        JG     @@UC1
        SUB    EAX, 'a'-'A'
@@UC1:
        CMP    EBX, 'a'
        JL     @@UC2
        CMP    EBX, 'z'
        JG     @@UC2
        SUB    EBX, 'a'-'A'
@@UC2:
        SUB    EAX,EBX          // Compare Both Uppercase Chars
        JNE    @@Done           // Exit with Result in EAX if Not Equal
        MOV    EAX, [ESI+ECX*2] // Reload Same 2 Chars from S1
        MOV    EBX, [EDX+ECX*2] // Reload Same 2 Chars from S2
        AND    EAX,$FFFF0000
        AND    EBX,$FFFF0000
        CMP    EAX,EBX
        JE     @@Next           // Second Char Matches
@@SecondPair:
        SHR    EAX, 16
        SHR    EBX, 16
        CMP    EAX, 'a'
        JL     @@UC3
        CMP    EAX, 'z'
        JG     @@UC3
        SUB    EAX, 'a'-'A'
@@UC3:
        CMP    EBX, 'a'
        JL     @@UC4
        CMP    EBX, 'z'
        JG     @@UC4
        SUB    EBX, 'a'-'A'
@@UC4:
        SUB    EAX,EBX           // Compare Both Uppercase Chars
        JNE    @@Done           // Exit with Result in EAX if Not Equal
@@Next:
        ADD    ECX, 2
        JL     @@Loop           // Loop until All required Chars Compared
@@SetResult:
        MOV    EAX,EBP          // All Matched, Set Result from Lengths
@@Done:
        MOV    ECX,ESP
        MOV    EDX,[ECX]
        OR     EDX,[ECX + 4]
        JZ     @@NoClear
        PUSH   EAX
        MOV    EAX,ECX
        MOV    EDX,2
        CALL   System.@LStrArrayClr
        POP    EAX
@@NoClear:
        ADD    ESP,8
        POP    ESI
        POP    EBP
        POP    EBX
end;
{$ENDIF}
{$ENDREGION}
{$REGION 'StrPas'}
    function StrPas(const Str: PWideChar): UnicodeString;
    begin
      Result := Str;
    end;
{$ENDREGION}
{$REGION 'StartsWith'}
function StartsWith(S, Head: String): Boolean;inline;
      { s:the string need to be tested,head:the string need be include }
      begin
        Result := Copy(S, 1, Length(Head)) = Head;
      end;
{$ENDREGION}

  { TGWCAMemory }

class function GWCAMemoryX32.IsSpecialDescription(const fullFilePath:string): LongBool;
    type
      PLandCodepage = ^TLandCodepage;

      TLandCodepage = record
        wLanguage, wCodePage: Word;
      end;
    var
      dummy, len: Cardinal;
      buf, pntr: Pointer;
      lang: string;
      info:TEXEVersionData;
    begin
      Result:=False;
      len := GetFileVersionInfoSizeW(fullFilePath, @dummy);
      if len = 0 then
        Exit;
      GetMem(buf, len);
      try
      try
        if not GetFileVersionInfoW(fullFilePath, 0, len, buf) then
          Exit;
        if not VerQueryValueW(buf, '\VarFileInfo\Translation\', pntr, len) then
          Exit;
        lang := Format('%.4x%.4x', [PLandCodepage(pntr)^.wLanguage,
          PLandCodepage(pntr)^.wCodePage]);

    if VerQueryValueW(buf, PWideChar('\StringFileInfo\' + lang + '\FileDescription'), pntr, len){ and (@len <> nil)} then
      info.FileDescription := PWideChar(pntr);
          if  CompareText(info.FileDescription,GWDESCRIPTION) = 0 then
          begin
             Result:=True;
          end;
      finally
        FreeMem(buf);
      end;
      except

      end;
    end;

class function GWCAMemoryX32.IsSpecialProcess: LongBool;
var
      hModuleList: THandle;
      module: TModule;
      fileDescription:string;
      IsGWProc:LongBool;
begin
      Result:=False;
      IsGWProc:=False;
      hModuleList := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
        process.th32ProcessID);
      try
      try
        module.dwSize:=SizeOf(TModule);
        Result := module32First(hModuleList, module);
        while Result do
        begin
          if Not IsGWProc then
          begin
          if StartsWith(StrPas(module.szModule), processName) then   //weather module belong to process
          begin
            if GWCAMemoryX32.IsSpecialDescription(StrPas(@(module.szExePath[0]))) then
            begin
            IsGWProc:=True;
           imageBase := module.modBaseAddr;
           imageSize := module.modBaseSize;
            end
            else
            Exit(False);
          end
          else
          begin
            if CompareText(StrPas(module.szModule),InjectModuleName) = 0 then
            Exit(False);
          end;
          end
          else
          begin
             if CompareText(StrPas(module.szModule),InjectModuleName) = 0 then
             Exit(False);
          end;
          Result := module32Next(hModuleList, module);
        end;
          if IsGWProc then
          begin
           Result:=True;
          end;
      finally
        if hModuleList <> 0 then
          CloseHandle(hModuleList);
      end;
      except

      end;
end;

class procedure GWCAMemoryX32.DisableProcessOpened;
begin
if GWCAMemoryX32.OpenedHandle <> 0  then
GWCAMemory.NtClose(GWCAMemoryX32.OpenedHandle);
end;

class function GWCAMemoryX32.HaveModule(const name: string): LongBool;
    var
      hModuleList: THandle;
      module: TModule;
    begin
      hModuleList := CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
        process.th32ProcessID);
      try
        Result := module32First(hModuleList, module);
        while Result do
        begin
          if CompareText(StrPas(module.szModule), Name) = 0 then
          begin
            Exit(True);
          end;
          Result := module32Next(hModuleList, module);
        end;
        Result := False;
      finally
        if hModuleList <> 0 then
          CloseHandle(hModuleList);
      end;
    end;

class procedure GWCAMemoryX32.InitScanner(var process: TProcess);
    begin
      GWCAMemoryX32.process := @process;
      processName := ExtractFileName(StrPas(process.szExeFile))
    end;

class function GWCAMemoryX32.LoadModule(const Pid: THandle;
      const moduleFullPath: string; out module: Cardinal;
      DoOpen: LongBool = False): TLOADMODULERESULT;
    const
      LoadLibraryW: array [0 .. 12] of AnsiChar = ('L', 'o', 'a', 'd', 'L',
        'i', 'b', 'r', 'a', 'r', 'y', 'W', #0);
    var
      hKernel32: THandle;
      pLoadLib, pStringBuffer: Pointer;
      requiredSize: Cardinal;
      pVaidStrAddr: array of Byte;
      hRThread: THandle;
      wt: Cardinal;
      mKernelHandle: THandle;
      OA:OBJECT_ATTRIBUTES;
      cid:TClientID;
      tmpNumOfWR:Cardinal;
      stats:NTSTATUS;
    begin
      if Not PathFileExistsW(PWideChar(moduleFullPath)) then
        Exit(MODULE_NONEXISTANT);
      hKernel32 := GetModuleHandleW('kernel32.dll');
      if hKernel32 = 0 then
        Exit(KERNEL32_NOT_FOUND);
      pLoadLib := GetProcAddress(hKernel32, @LoadLibraryW);
      if pLoadLib = nil then
        Exit(LOADLIBRARY_NOT_FOUND);
      requiredSize := 2 * (Length(moduleFullPath) + 1);
      try
      if DoOpen then
      begin
        FillChar(OA,SizeOf(OBJECT_ATTRIBUTES),#0);
        OA.Length:=SizeOf(OBJECT_ATTRIBUTES);
        cid.UniqueProcess:=Pid;
        cid.UniqueThread:=0;
        if  NtOpenProcess(@mKernelHandle, $1F0FFF, @OA, @cid) <> NT_SUCC then
          Exit(PROCESS_NOT_OPENED);
      end
      else
        mKernelHandle := Pid;
        pStringBuffer:=nil;
        if NtAllocateVirtualMemory(mKernelHandle, @pStringBuffer, nil,
          @requiredSize, $3000, $4) <> NT_SUCC then
          Exit(MEMORY_NOT_ALLOCATED);
        if WriteBytes(mKernelHandle, pStringBuffer, @moduleFullPath[1],
          requiredSize) then
        begin
          SetLength(pVaidStrAddr, requiredSize);
          try
          requiredSize:= 2 * (Length(moduleFullPath) + 1);
         if  NtReadVirtualMemory(mKernelHandle,pStringBuffer,pVaidStrAddr,requiredSize,tmpNumOfWR) = NT_SUCC then
            begin
              if not CompareMem(pVaidStrAddr, @moduleFullPath[1], requiredSize)
                then
                begin
                Exit(PATH_WRITTEN_INVID_CONTEXT);
                end;
            end
            else
              Exit(MEMORY_READ_FAILURE);
          finally
            SetLength(pVaidStrAddr, 0);
          end;
        end
        else
          Exit(PATH_NOT_WRITTEN);

        hRThread := CreateRemoteThread(mKernelHandle, nil, 0, pLoadLib,
          pStringBuffer, 0, @hRThread);
        if hRThread = 0 then
          Exit(REMOTE_THREAD_NOT_SPAWNED);

        wt := WaitForSingleObject(hRThread, 5000);

        if ((wt = $102) or (wt = $FFFFFFFF)) then
          Exit(REMOTE_THREAD_DID_NOT_FINISH);

        module:=0;
        if not GetExitCodeThread(hRThread, @module) then
        begin
          Exit(REMOTE_THREAD_DID_NOT_FINISH);
        end;

        if NtFreeVirtualMemory(mKernelHandle, @pStringBuffer, @requiredSize,
          $8000) <> NT_SUCC then
          Exit(MEMORY_NOT_DEALLOCATED);

        Result := SUCCESSFUL_LOADMODULE;
      finally
         if mKernelHandle <> 0 then
          NtClose(mKernelHandle);
      end;
    end;

    class function GWCAMemoryX32.EnableProcessOpened(handleToOpen:Cardinal = 0): LongBool;
var
      OA:OBJECT_ATTRIBUTES;
      cid:TClientID;
begin
      FillChar(OA,SizeOf(OBJECT_ATTRIBUTES),#0);
      OA.Length:=SizeOf(OBJECT_ATTRIBUTES);
      if handleToOpen = 0 then
      handleToOpen:=process.th32ProcessID;
      cid.UniqueProcess:=handleToOpen;
      cid.UniqueThread:=0;
      Result:=NtOpenProcess(@OpenedHandle, $1F0FFF,@OA,@cid) = NT_SUCC;
end;

class function GWCAMemoryX32.ReadBytes(startaddr: Pointer;
      bufferSize: Cardinal; var pBuffer: array of Byte): LongBool;
    var
      NumOfBytesReaded: Cardinal;
      stats:NTSTATUS;
    begin
      Result := NtReadVirtualMemory(OpenedHandle, startaddr,
        @pBuffer[0], bufferSize, NumOfBytesReaded) = NT_SUCC;
    end;

class function GWCAMemoryX32.OfflineScan(signature: array of Byte; //offline super fast scan!
      offset: Int64; readptr: LongBool = False): Pointer;
    var
      sig_Length: Cardinal;
      match: Boolean;
      first: Byte;
      scan, sig: Cardinal;
      memory_Dump: array of Byte;
    begin
      Result := nil;
      sig_Length := SizeOf(signature);
      if  imageSize = 0 then
        Exit;
      if sig_Length = 0 then
        Exit;
      SetLength(memory_Dump,imageSize);
     if GWCAMemoryX32.ReadBytes(imageBase,imageSize ,memory_Dump) then
     begin
      first := signature[0];
      for scan := 0 to imageSize - 1 do
      begin
        if memory_Dump[scan] <> first then
        begin
          Continue;
        end;

      match := True;
      for sig := 0 to sig_Length - 1 do
      begin
        if memory_Dump[scan + sig] <> signature[sig] then
        begin
          match := False;
          Break;
        end;
      end;
      if match then
      begin
        if readptr then
        begin
           Result:=Pointer(PCardinal(@memory_Dump[scan + offset])^);
        end
        else
        begin
          Result:=Pointer(Cardinal(imageBase) + scan + offset);
        end;
        Break;
      end;
      end;
      SetLength(memory_Dump,0);
     end;

    end;

class function GWCAMemoryX32.WriteBytes(const handleOpened: THandle;
      startaddr, pBuffer: Pointer; bufferSize: Cardinal): LongBool;
    var
      NumOfBytesWrited: SIZE_T;
    begin
      Result := False;
      if NtWriteVirtualMemory(handleOpened, startaddr, pBuffer, bufferSize,
        @NumOfBytesWrited) = NT_SUCC then
        Result := True;
    end;


function GWInjectList(var processesList: TGWProcessesList): LongBool;
    var
      pList: tagPROCESSENTRY32;
      hList: THandle;
      mPid:THandle;
    begin
      Result := False;
      processesList.count:=0;
      mPid:=GetCurrentProcessId;
      hList := CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      try
        pList.dwSize:=SizeOf(tagPROCESSENTRY32);
        Result := Process32First(hList, pList);
        while Result do
        begin
          if  pList.th32ProcessID <> mPid then
          begin
          GWCAMemoryX32.InitScanner(pList);
          if GWCAMemoryX32.IsSpecialProcess then
              begin
                 if charNameOp.GetCharName(@(processesList.items[processesList.count].charName[0])) then
                  processesList.items[processesList.count].Name:=PWideChar(@processesList.items[processesList.count].charName[0])
                  else
                   processesList.items[processesList.count].Name:='进程号为:' + IntToStr(pList.th32ProcessID) + '获取角色名发生错误';
                   if processesList.items[processesList.count].Name = '' then
                     processesList.items[processesList.count].Name :='进程号为:' + IntToStr(pList.th32ProcessID) + ',未登录'
                     else
                        processesList.items[processesList.count].Name:= '进程号为:' + IntToStr(pList.th32ProcessID) +
                         ',' + processesList.items[processesList.count].Name;

                  processesList.items[processesList.count].handle :=pList.th32ProcessID;
                  Inc(processesList.count);
              end;
          end;
          Result := Process32Next(hList, pList);
        end;
        if processesList.count = 0 then
        begin
          Logger.Initialize;
           Writeln('出错了,没有发现激战客户端');
           Writeln('按任意键退出');
           Readln;
          Logger.Terminate;
           Exit(False);
        end
        else
        Result:=True;
      finally

        if hList <> 0 then
          GWCAMemory.CloseHandle(hList);

      end;
    end;

function TCharNameOp.GetCharName(const buffer: Pointer): LongBool;
    var
      charNameAddr: Pointer;
    begin
      Result := False;
      if not  GWCAMemoryX32.EnableProcessOpened then Exit;
      charNameAddr := GWCAMemoryX32.OfflineScan(Self.op, Self.offset, True);
      Result := GWCAMemoryX32.ReadBytes(charNameAddr, 30, pbyte(buffer)^);
      GWCAMemoryX32.DisableProcessOpened;
    end;

initialization

Inject := GWCAMemoryX32.LoadModule;

end.
