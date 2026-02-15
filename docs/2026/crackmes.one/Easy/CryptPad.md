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

### Windown setup

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

#### `GetModuleHandleA`

We can see that the program calls the `GetModuleHandleA`

```c title="cryptpad.exe :: start() :: Pseudocode" showLineNumbers
# ---- snip ----

  dword_403565 = GetModuleHandleA(nullptr);
  hInstance = dword_403565;

# ---- snip ----
```

```C title="GetModuleHandleA"
HMODULE GetModuleHandleA(
  [in, optional] LPCSTR lpModuleName
);
```

This function returns the module handle, i.e. the unique, system-generated identifier (often a 32-bit or 64-bit integer)  for the specified module. 

A module handle (`HMODULE`) in Windows is a unique identifier (specifically, the base memory address) for an executable (`.exe`) or dynamic-link library (`.dll`) loaded into a process's address space.
It allows applications to reference specific loaded code modules to retrieve resources, function pointers, or module information. 

Since the `nullptr` argument is passed, the handle of the current process’s main module is returned.

#### `LoadIconA`

Then it uses the `LoadIconA` function to load an icon resource from the executable (.exe) file associated with an application instance.

```c title="cryptpad.exe :: start() :: Pseudocode" showLineNumbers
# ---- snip ----

dword_402491 = (int)LoadIconA(dword_403565, (LPCSTR)0x7F00);

# ---- snip ----
```

```c title="LoadIconA"
HICON LoadIconA(
  [in, optional] HINSTANCE hInstance,
  [in]           LPCSTR    lpIconName
);
```

Parameters:
- `(HINSTANCE) hInstance`: A handle to the module of either a DLL or executable (.exe) file that contains the icon to be loaded.
- `(LPCSTR) lpIconName`: If `hInstance` is non-NULL, `lpIconName` specifies the icon resource either by name or ordinal.

Return Value: 
- `(HICON)`: If the function succeeds, the return value is a handle to the newly loaded icon.

#### [`LoadCursorA`](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-loadcursora)

Then the `LoadCursorA` function is used to load an cursor resource from the executable (.exe) file associated with an application instance.

```c title="cryptpad.exe" showLineNumbers
# ---- snip ----

dword_402495 = (int)LoadCursorA(nullptr, (LPCSTR)0x7F00);

# ---- snip ----
```

```c title="LoadCursorA" 
HCURSOR LoadCursorA(
  [in, optional] HINSTANCE hInstance,
  [in]           LPCSTR    lpCursorName
);
```

#### `RegisterClassExA`

Using `RegisterClassExA`, it registers the `open_file_name.pvReserved` 

```c title="cryptpad.exe" showLineNumbers
# ---- snip ----

LOWORD(v0) = RegisterClassExA((const WNDCLASSEXA *)&open_file_name.pvReserved);

# ---- snip ----
```

```c title="RegisterClassExA"
ATOM RegisterClassExA(
  [in] const WNDCLASSEXA *unnamedParam1
);
```

