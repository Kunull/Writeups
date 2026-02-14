We are provided with a ZIP file called `cryptpad_handout.zip` which has the following content:

```
Kunal.walavalkar@CY-IND-L2200 Documents % ls -la cryptpad_handout
total 32
drwxr-xr-x   4 Kunal.walavalkar  staff    128 14 Feb 14:07 .
drwx------+ 29 Kunal.walavalkar  staff    928 14 Feb 14:06 ..
-rwxr-xr-x@  1 Kunal.walavalkar  staff  11776 14 Feb 14:07 cryptpad.exe
-rw-r--r--@  1 Kunal.walavalkar  staff     64 14 Feb 14:07 flag.enc
```

It seems that `cryptpad.exe` was used to encrypt the flag, giving us `flag.enc`.

## Binary Analysis

```c title="cryptpad.exe :: start() :: Pseudocode" showLineNumbers
void __noreturn start()
{
  int v0; // eax
  HWND Window; // eax
  BOOL MessageA; // eax

  dword_403565 = (int)GetModuleHandleA(nullptr);
  hInstance = (HINSTANCE)dword_403565;
  stru_40242D.pvReserved = (void *)48;
  stru_40242D.FlagsEx = (DWORD)sub_4011A0;
  stru_40242D.dwReserved = 3;
  dword_402491 = (int)LoadIconA((HINSTANCE)dword_403565, (LPCSTR)0x7F00);
  dword_4024A5 = dword_402491;
  dword_402495 = (int)LoadCursorA(nullptr, (LPCSTR)'\x7F\0');
  dword_402499 = 16;
  dword_4024A1 = (int)ClassName;
  dword_402485 = 0;
  dword_402489 = 0;
  dword_40249D = 0;
  dword_402495 = (int)LoadCursorA(nullptr, (LPCSTR)0x7F00);
  stru_40242D.dwReserved = 3;
  LOWORD(v0) = RegisterClassExA((const WNDCLASSEXA *)&stru_40242D.pvReserved);
  if ( v0
    && (sub_401713(),
        hMenu = LoadMenuA(hInstance, (LPCSTR)1),
        (Window = CreateWindowExA(
                    0,
                    ClassName,
                    Caption,
                    0xCF0000u,
                    0x80000000,
                    0x80000000,
                    700,
                    500,
                    nullptr,
                    hMenu,
                    hInstance,
                    nullptr)) != nullptr) )
  {
    hWnd = Window;
    ShowWindow(Window, 1);
    UpdateWindow(hWnd);
    while ( 1 )
    {
      MessageA = GetMessageA(&Msg, nullptr, 0, 0);
      if ( !MessageA )
        break;
      if ( MessageA )
      {
        TranslateMessage(&Msg);
        DispatchMessageA(&Msg);
      }
    }
  }
  else
  {
    MessageBoxA(nullptr, Text, Caption, 0x10u);
  }
  ExitProcess(Msg.wParam);
}
```

