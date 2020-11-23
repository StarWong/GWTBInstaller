program Launcher;

uses
  Forms,
  CharSelector in 'CharSelector.pas' {MainForm},
  GWCAMemory in 'GWCAMemory.pas',
  CSLauncher in 'CSLauncher.pas';

{$R *.res}

const
opCode:array[0..11] of Byte =($8B, $F8, $6A, $03, $68, $0F, $00, $00, $C0,$8B, $CF, $E8);
offset:Integer = - $42;
workDir:string ='';
GWDESCRIPTION: string = 'Guild Wars Game Client';
InjectModuleName: string = 'GWTOOLBOX.DLL';
begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  CSLauncher.dllDirFullPath:=workDir;
  Move(opCode[0],charNameOp.op[0],12);
  charNameOp.offset:=offset;
  GWCAMemory.GWDESCRIPTION:= GWDESCRIPTION;
  GWCAMemory.InjectModuleName:=InjectModuleName;
  CSLauncher.InjectToGw;
  Application.Run;
end.
