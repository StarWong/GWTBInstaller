unit Logger;


{$DEFINE Log}
interface
procedure Initialize;
procedure Terminate;
{$IFDEF SaveLog}
procedure Log(const Str: string;Date_lOG:Boolean=False);overload
procedure Log(const Data: Cardinal;Date_lOG:Boolean=False);overload
procedure Log(const Key: string;const Value: Cardinal;Date_lOG:Boolean=False);overload
procedure Log(const Key: string;const Value: Cardinal;BaseData:Cardinal = 0;Date_lOG:Boolean=False);overload
procedure SetLogger(const DirectoryPath_:string;const logFileName_:string;const RetSetLogFile_:Boolean);
{$ENDIF}
{$IFDEF  Log}
procedure Log(const msg:string;const Args: array of const);overload;
procedure Log(const msg:string);overload;
procedure Log(pAddr:PByte;Len:Cardinal);overload;
{$ENDIF}
implementation
uses
Windows,SysUtils;
{$IFDEF  Log}
type
  CONSOLE_FONT_INFOEX = record
    cbSize      : ULONG;
    nFont       : DWORD;
    dwFontSizeX : SHORT;
    dwFontSizeY : SHORT;
    FontFamily  : UINT;
    FontWeight  : UINT; // range from 100 to 1000, in multiples of 100
    FaceName    : array [0..LF_FACESIZE-1] of WCHAR;
  end;
const
CP_UTF8:Cardinal = 65001;
var
HConsole:Cardinal;
FontInfo:CONSOLE_FONT_INFOEX;
ScreenInfo:_CONSOLE_SCREEN_BUFFER_INFO;
{$ENDIF}
{$IFDEF SaveLog}
var
DirectoryPath:string = '';
logFileName:string = 'Logger.log';
RetSetLogFile:Boolean = True;
{$ENDIF}
IsLoggerEnabled:LongBool;
{$REGION 'Debug & Logs'}
{$IFDEF SaveLog}
procedure AppendTxt(const filePath, Str: string); // 主进程函数
var
  F: Textfile;
begin
  AssignFile(F, filePath);
  Append(F);
  Writeln(F, Str);
  Closefile(F);
end;

// 新建文件                                                //主进程函数

procedure NewTxt(const filePath: string);
var
  F: Textfile;
begin
  AssignFile(F, filePath);
  ReWrite(F);
  Closefile(F);
end;
procedure Log(const Str: string;Date_lOG:Boolean=False);
begin
    if Date_lOG then
    AppendTxt(DirectoryPath + logFileName, Str)
    else
    AppendTxt(DirectoryPath + logFileName,
    FormatDateTime('YYYY-MM-DD HH:NN:SS ZZZ: ',Now) + Str);
end;

procedure Log(const Data: Cardinal;Date_lOG:Boolean=False);
begin
  Log(IntToStr(Data),Date_lOG);
end;

procedure Log(const Key: string;const Value: Cardinal;Date_lOG:Boolean=False);
begin
  Log(Key + ':' + IntToStr(Value),Date_lOG);
end;

procedure Log(const Key: string;const Value: Cardinal;BaseData:Cardinal = 0;Date_lOG:Boolean=False);
begin
  Log(Key,Value - BaseData,Date_lOG );
end;

procedure SetLogger(const DirectoryPath_:string;const logFileName_:string;const RetSetLogFile_:Boolean);
begin
    DirectoryPath:=DirectoryPath_;
    logFileName:=logFileName_;
    RetSetLogFile:=RetSetLogFile_;
end;
{$ENDIF}
{$IFDEF Log}
function SetCurrentConsoleFontEx(hConsoleOutput: Cardinal; bMaximumWindow: BOOL; var CONSOLE_FONT_INFOEX): BOOL;
   stdcall; external 'kernel32.dll' name 'SetCurrentConsoleFontEx';
function GetCurrentConsoleFontEx(hConsoleOutput:Cardinal;bMaximumWindow:BOOL;var ConsoleCurrentFontEx):BOOL;
stdcall;external 'kernel32.dll' name 'GetCurrentConsoleFontEx';
//function AllocConsole: LongBool;stdcall; external 'Kernel32.dll';
//function FreeConsole: LongBool;stdcall; external 'Kernel32.dll';
//function SetConsoleTitle(lpConsoleTitle:PWideChar):LongBool;stdcall; external 'Kernel32.dll' name 'SetConsoleTitleW';
//function wsprintf(Output: PChar; Format: PChar): Integer; cdecl; varargs;
//  external 'user32.dll' name {$IFDEF UNICODE}'wsprintfW'{$ELSE}'wsprintfA'{$ENDIF};

function PByteToString(P:PByte):string;
begin
  case P^ of
  {$REGION '0..255'}
0:Exit('0');
1:Exit('1');
2:Exit('2');
3:Exit('3');
4:Exit('4');
5:Exit('5');
6:Exit('6');
7:Exit('7');
8:Exit('8');
9:Exit('9');
10:Exit('10');
11:Exit('11');
12:Exit('12');
13:Exit('13');
14:Exit('14');
15:Exit('15');
16:Exit('16');
17:Exit('17');
18:Exit('18');
19:Exit('19');
20:Exit('20');
21:Exit('21');
22:Exit('22');
23:Exit('23');
24:Exit('24');
25:Exit('25');
26:Exit('26');
27:Exit('27');
28:Exit('28');
29:Exit('29');
30:Exit('30');
31:Exit('31');
32:Exit('32');
33:Exit('33');
34:Exit('34');
35:Exit('35');
36:Exit('36');
37:Exit('37');
38:Exit('38');
39:Exit('39');
40:Exit('40');
41:Exit('41');
42:Exit('42');
43:Exit('43');
44:Exit('44');
45:Exit('45');
46:Exit('46');
47:Exit('47');
48:Exit('48');
49:Exit('49');
50:Exit('50');
51:Exit('51');
52:Exit('52');
53:Exit('53');
54:Exit('54');
55:Exit('55');
56:Exit('56');
57:Exit('57');
58:Exit('58');
59:Exit('59');
60:Exit('60');
61:Exit('61');
62:Exit('62');
63:Exit('63');
64:Exit('64');
65:Exit('65');
66:Exit('66');
67:Exit('67');
68:Exit('68');
69:Exit('69');
70:Exit('70');
71:Exit('71');
72:Exit('72');
73:Exit('73');
74:Exit('74');
75:Exit('75');
76:Exit('76');
77:Exit('77');
78:Exit('78');
79:Exit('79');
80:Exit('80');
81:Exit('81');
82:Exit('82');
83:Exit('83');
84:Exit('84');
85:Exit('85');
86:Exit('86');
87:Exit('87');
88:Exit('88');
89:Exit('89');
90:Exit('90');
91:Exit('91');
92:Exit('92');
93:Exit('93');
94:Exit('94');
95:Exit('95');
96:Exit('96');
97:Exit('97');
98:Exit('98');
99:Exit('99');
100:Exit('100');
101:Exit('101');
102:Exit('102');
103:Exit('103');
104:Exit('104');
105:Exit('105');
106:Exit('106');
107:Exit('107');
108:Exit('108');
109:Exit('109');
110:Exit('110');
111:Exit('111');
112:Exit('112');
113:Exit('113');
114:Exit('114');
115:Exit('115');
116:Exit('116');
117:Exit('117');
118:Exit('118');
119:Exit('119');
120:Exit('120');
121:Exit('121');
122:Exit('122');
123:Exit('123');
124:Exit('124');
125:Exit('125');
126:Exit('126');
127:Exit('127');
128:Exit('128');
129:Exit('129');
130:Exit('130');
131:Exit('131');
132:Exit('132');
133:Exit('133');
134:Exit('134');
135:Exit('135');
136:Exit('136');
137:Exit('137');
138:Exit('138');
139:Exit('139');
140:Exit('140');
141:Exit('141');
142:Exit('142');
143:Exit('143');
144:Exit('144');
145:Exit('145');
146:Exit('146');
147:Exit('147');
148:Exit('148');
149:Exit('149');
150:Exit('150');
151:Exit('151');
152:Exit('152');
153:Exit('153');
154:Exit('154');
155:Exit('155');
156:Exit('156');
157:Exit('157');
158:Exit('158');
159:Exit('159');
160:Exit('160');
161:Exit('161');
162:Exit('162');
163:Exit('163');
164:Exit('164');
165:Exit('165');
166:Exit('166');
167:Exit('167');
168:Exit('168');
169:Exit('169');
170:Exit('170');
171:Exit('171');
172:Exit('172');
173:Exit('173');
174:Exit('174');
175:Exit('175');
176:Exit('176');
177:Exit('177');
178:Exit('178');
179:Exit('179');
180:Exit('180');
181:Exit('181');
182:Exit('182');
183:Exit('183');
184:Exit('184');
185:Exit('185');
186:Exit('186');
187:Exit('187');
188:Exit('188');
189:Exit('189');
190:Exit('190');
191:Exit('191');
192:Exit('192');
193:Exit('193');
194:Exit('194');
195:Exit('195');
196:Exit('196');
197:Exit('197');
198:Exit('198');
199:Exit('199');
200:Exit('200');
201:Exit('201');
202:Exit('202');
203:Exit('203');
204:Exit('204');
205:Exit('205');
206:Exit('206');
207:Exit('207');
208:Exit('208');
209:Exit('209');
210:Exit('210');
211:Exit('211');
212:Exit('212');
213:Exit('213');
214:Exit('214');
215:Exit('215');
216:Exit('216');
217:Exit('217');
218:Exit('218');
219:Exit('219');
220:Exit('220');
221:Exit('221');
222:Exit('222');
223:Exit('223');
224:Exit('224');
225:Exit('225');
226:Exit('226');
227:Exit('227');
228:Exit('228');
229:Exit('229');
230:Exit('230');
231:Exit('231');
232:Exit('232');
233:Exit('233');
234:Exit('234');
235:Exit('235');
236:Exit('236');
237:Exit('237');
238:Exit('238');
239:Exit('239');
240:Exit('240');
241:Exit('241');
242:Exit('242');
243:Exit('243');
244:Exit('244');
245:Exit('245');
246:Exit('246');
247:Exit('247');
248:Exit('248');
249:Exit('249');
250:Exit('250');
251:Exit('251');
252:Exit('252');
253:Exit('253');
254:Exit('254');
255:Exit('255');
  {$ENDREGION}
  end;
end;

function PByteToHex(P:PByte):string;
begin
  case P^ of
  {$REGION '0..255'}
0:Exit('00');
1:Exit('01');
2:Exit('02');
3:Exit('03');
4:Exit('04');
5:Exit('05');
6:Exit('06');
7:Exit('07');
8:Exit('08');
9:Exit('09');
10:Exit('0A');
11:Exit('0B');
12:Exit('0C');
13:Exit('0D');
14:Exit('0E');
15:Exit('0F');
16:Exit('10');
17:Exit('11');
18:Exit('12');
19:Exit('13');
20:Exit('14');
21:Exit('15');
22:Exit('16');
23:Exit('17');
24:Exit('18');
25:Exit('19');
26:Exit('1A');
27:Exit('1B');
28:Exit('1C');
29:Exit('1D');
30:Exit('1E');
31:Exit('1F');
32:Exit('20');
33:Exit('21');
34:Exit('22');
35:Exit('23');
36:Exit('24');
37:Exit('25');
38:Exit('26');
39:Exit('27');
40:Exit('28');
41:Exit('29');
42:Exit('2A');
43:Exit('2B');
44:Exit('2C');
45:Exit('2D');
46:Exit('2E');
47:Exit('2F');
48:Exit('30');
49:Exit('31');
50:Exit('32');
51:Exit('33');
52:Exit('34');
53:Exit('35');
54:Exit('36');
55:Exit('37');
56:Exit('38');
57:Exit('39');
58:Exit('3A');
59:Exit('3B');
60:Exit('3C');
61:Exit('3D');
62:Exit('3E');
63:Exit('3F');
64:Exit('40');
65:Exit('41');
66:Exit('42');
67:Exit('43');
68:Exit('44');
69:Exit('45');
70:Exit('46');
71:Exit('47');
72:Exit('48');
73:Exit('49');
74:Exit('4A');
75:Exit('4B');
76:Exit('4C');
77:Exit('4D');
78:Exit('4E');
79:Exit('4F');
80:Exit('50');
81:Exit('51');
82:Exit('52');
83:Exit('53');
84:Exit('54');
85:Exit('55');
86:Exit('56');
87:Exit('57');
88:Exit('58');
89:Exit('59');
90:Exit('5A');
91:Exit('5B');
92:Exit('5C');
93:Exit('5D');
94:Exit('5E');
95:Exit('5F');
96:Exit('60');
97:Exit('61');
98:Exit('62');
99:Exit('63');
100:Exit('64');
101:Exit('65');
102:Exit('66');
103:Exit('67');
104:Exit('68');
105:Exit('69');
106:Exit('6A');
107:Exit('6B');
108:Exit('6C');
109:Exit('6D');
110:Exit('6E');
111:Exit('6F');
112:Exit('70');
113:Exit('71');
114:Exit('72');
115:Exit('73');
116:Exit('74');
117:Exit('75');
118:Exit('76');
119:Exit('77');
120:Exit('78');
121:Exit('79');
122:Exit('7A');
123:Exit('7B');
124:Exit('7C');
125:Exit('7D');
126:Exit('7E');
127:Exit('7F');
128:Exit('80');
129:Exit('81');
130:Exit('82');
131:Exit('83');
132:Exit('84');
133:Exit('85');
134:Exit('86');
135:Exit('87');
136:Exit('88');
137:Exit('89');
138:Exit('8A');
139:Exit('8B');
140:Exit('8C');
141:Exit('8D');
142:Exit('8E');
143:Exit('8F');
144:Exit('90');
145:Exit('91');
146:Exit('92');
147:Exit('93');
148:Exit('94');
149:Exit('95');
150:Exit('96');
151:Exit('97');
152:Exit('98');
153:Exit('99');
154:Exit('9A');
155:Exit('9B');
156:Exit('9C');
157:Exit('9D');
158:Exit('9E');
159:Exit('9F');
160:Exit('A0');
161:Exit('A1');
162:Exit('A2');
163:Exit('A3');
164:Exit('A4');
165:Exit('A5');
166:Exit('A6');
167:Exit('A7');
168:Exit('A8');
169:Exit('A9');
170:Exit('AA');
171:Exit('AB');
172:Exit('AC');
173:Exit('AD');
174:Exit('AE');
175:Exit('AF');
176:Exit('B0');
177:Exit('B1');
178:Exit('B2');
179:Exit('B3');
180:Exit('B4');
181:Exit('B5');
182:Exit('B6');
183:Exit('B7');
184:Exit('B8');
185:Exit('B9');
186:Exit('BA');
187:Exit('BB');
188:Exit('BC');
189:Exit('BD');
190:Exit('BE');
191:Exit('BF');
192:Exit('C0');
193:Exit('C1');
194:Exit('C2');
195:Exit('C3');
196:Exit('C4');
197:Exit('C5');
198:Exit('C6');
199:Exit('C7');
200:Exit('C8');
201:Exit('C9');
202:Exit('CA');
203:Exit('CB');
204:Exit('CC');
205:Exit('CD');
206:Exit('CE');
207:Exit('CF');
208:Exit('D0');
209:Exit('D1');
210:Exit('D2');
211:Exit('D3');
212:Exit('D4');
213:Exit('D5');
214:Exit('D6');
215:Exit('D7');
216:Exit('D8');
217:Exit('D9');
218:Exit('DA');
219:Exit('DB');
220:Exit('DC');
221:Exit('DD');
222:Exit('DE');
223:Exit('DF');
224:Exit('E0');
225:Exit('E1');
226:Exit('E2');
227:Exit('E3');
228:Exit('E4');
229:Exit('E5');
230:Exit('E6');
231:Exit('E7');
232:Exit('E8');
233:Exit('E9');
234:Exit('EA');
235:Exit('EB');
236:Exit('EC');
237:Exit('ED');
238:Exit('EE');
239:Exit('EF');
240:Exit('F0');
241:Exit('F1');
242:Exit('F2');
243:Exit('F3');
244:Exit('F4');
245:Exit('F5');
246:Exit('F6');
247:Exit('F7');
248:Exit('F8');
249:Exit('F9');
250:Exit('FA');
251:Exit('FB');
252:Exit('FC');
253:Exit('FD');
254:Exit('FE');
255:Exit('FF');

  {$ENDREGION}
  end;
end;

procedure Log(const msg:string;const Args: array of const);
var
dw:DWORD;
buff:string;
begin
try
    buff:=Format(msg,Args);
    WriteConsoleW(HConsole,@buff[1],Length(buff),dw,nil);
    WriteConsoleA(HConsole,PAnsiChar(#13#10),2,dw,nil);
except
      MessageBox(0,'WriteConsoleW failed','error',MB_ICONERROR);
end;
end;

procedure Log(const msg:string);
var
dw:DWORD;
begin
try
    WriteConsoleW(HConsole,@msg[1],Length(msg),dw,nil);
    WriteConsoleA(HConsole,PAnsiChar(#13#10),2,dw,nil);
except
      MessageBox(0,'WriteConsoleW failed','error',MB_ICONERROR);
end;
end;

procedure Log(pAddr:PByte;Len:Cardinal);
var
I:Cardinal;
begin

      for I := 0 to Len -1 do
      begin
            if I > 0 then
            Inc(pAddr);
            if I< Len -1 then
            Write(PByteToHex(pAddr)+' ')
            else
            Writeln(PByteToHex(pAddr));
      end;

end;

{$ENDIF}

{$ENDREGION}

procedure Initialize;
begin
if IsLoggerEnabled then Exit;
  {$IFDEF SaveLog}
DirectoryPath := ExtractFilePath(paramstr(0));
if  not fileExists(DirectoryPath + logFileName) then
    NewTxt(DirectoryPath + logFileName)
    else
    begin
      if RetSetLogFile then
      begin
        DeleteFile(DirectoryPath + logFileName);
        NewTxt(DirectoryPath + logFileName);
      end;
    end;
{$ENDIF}
{$IFDEF Log}
AllocConsole;
SetConsoleTitle('Debug Console');
//SetConsoleOutputCP(CP_UTF8);
HConsole:=GetStdHandle(STD_OUTPUT_HANDLE);
//FillChar(ScreenInfo,SizeOf(ScreenInfo),#0);
//GetConsoleScreenBufferInfo(HConsole,ScreenInfo);
//Inc(ScreenInfo.srWindow.Left,100);
//Inc(ScreenInfo.srWindow.Right,100);
//Inc(ScreenInfo.srWindow.Top,100);
//Inc(ScreenInfo.srWindow.Bottom,100);
//SetConsoleWindowInfo(HConsole,True,ScreenInfo.srWindow);
//FillChar(FontInfo,SizeOf(CONSOLE_FONT_INFOEX),#0);
//FontInfo.cbSize:=SizeOf(CONSOLE_FONT_INFOEX);
//FontInfo.dwFontSizeX:=8;
//FontInfo.dwFontSizeY:=12;
//GetCurrentConsoleFontEx(HConsole,False,FontInfo);
//MessageBox(0,PWideChar('x:' + IntToStr(FontInfo.dwFontSizeX)),PWideChar('y:' + IntToStr(FontInfo.dwFontSizeY)),0);
//SetCurrentConsoleFontEx(HConsole,False,FontInfo);
{$ENDIF}
IsLoggerEnabled:=True;
end;

procedure Terminate;
begin
if Not IsLoggerEnabled then  Exit;

{$IFDEF Log}
if HConsole <> 0 then
CloseHandle(HConsole);
//FreeConsole;
{$ENDIF}
 IsLoggerEnabled:=False;
end;

initialization
{$IFDEF DEBUG}
Initialize;
{$ENDIF}
finalization
{$IFDEF DEBUG}
Terminate;
{$ENDIF}
end.
