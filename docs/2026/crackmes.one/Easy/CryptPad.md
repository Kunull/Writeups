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
  ATOM v0; // ax
  HWND Window; // eax
  BOOL MessageA; // eax

  hInstance = GetModuleHandleA(nullptr);
  hInstance_0 = hInstance;
  open_file_name.pvReserved = (void *)48;
  open_file_name.FlagsEx = (DWORD)sub_4011A0;
  open_file_name.dwReserved = 3;
  hIcon = LoadIconA(hInstance, (LPCSTR)0x7F00);
  hIcon_0 = hIcon;
  dword_402495 = LoadCursorA(nullptr, (LPCSTR)0x7F00);
  dword_402499 = 16;
  dword_4024A1 = "CryptPAD";
  dword_402485 = 0;
  dword_402489 = 0;
  dword_40249D = 0;
  dword_402495 = LoadCursorA(nullptr, (LPCSTR)0x7F00);
  open_file_name.dwReserved = 3;
  v0 = RegisterClassExA((const WNDCLASSEXA *)&open_file_name.pvReserved);
  if ( *(_DWORD *)&v0
    && (sub_401713(),
        hMenu = LoadMenuA(hInstance_0, (LPCSTR)1),
        (Window = CreateWindowExA(
                    0,
                    "CryptPAD",
                    "CryptPad",
                    0xCF0000u,
                    0x80000000,
                    0x80000000,
                    700,
                    500,
                    nullptr,
                    hMenu,
                    hInstance_0,
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
    MessageBoxA(nullptr, "Startup failed.", "CryptPad", 0x10u);
  }
  ExitProcess(Msg.wParam);
}
```

We can see that the program calls the `GetModuleHandleA`

```c title="cryptpad.exe :: start() :: Pseudocode" showLineNumbers
# ---- snip ----

  dword_403565 = GetModuleHandleA(nullptr);
  hInstance = dword_403565;

# ---- snip ----
```

The `GetModuleHandleA` function returns the module handle, i.e. the unique, system-generated identifier (often a 32-bit or 64-bit integer)  for the specified module. 

A module handle (`HMODULE`) in Windows is a unique identifier (specifically, the base memory address) for an executable (`.exe`) or dynamic-link library (`.dll`) loaded into a process's address space.
It allows applications to reference specific loaded code modules to retrieve resources, function pointers, or module information. 

Since the `nullptr` argument is passed, `GetModuleHandle` returns a handle to the file used to create the calling process (.exe file).

Then it uses the `LoadIconA` function to load an icon resource from the executable (.exe) file associated with an application instance.

```c title="cryptpad.exe :: start() :: Pseudocode" showLineNumbers
# ---- snip ----

  dword_402491 = (int)LoadIconA(dword_403565, (LPCSTR)0x7F00);

# ---- snip ----
```

Then the `LoadCursorA` function is used to load an cursor resource from the executable (.exe) file associated with an application instance.

```c title="cryptpad.exe" showLineNumbers
# ---- snip ----

  dword_402495 = (int)LoadCursorA(nullptr, (LPCSTR)0x7F00);

# ---- snip ----
```

Using `RegisterClassExA`, it registers the `open_file_name.pvReserved` window, and if that operation fails, it outputs and fail message and exits.

```c title="cryptpad.exe" showLineNumbers
# ---- snip ----

  v0 = RegisterClassExA((const WNDCLASSEXA *)&open_file_name.pvReserved);  else
  
# ---- snip ----  
  
  else
  {
    MessageBoxA(nullptr, "Startup failed.", "CryptPad", 0x10u);
  }
  ExitProcess(Msg.wParam);

# ---- snip ----
```

If the window registration succeeds, it performs some more checks:
- It loads the specified menu resource from the `hInstance` file associated with an application instance. using the `LoadMenuA` function.
- It creates an overlapped, pop-up, or child window with an extended window style a window using the `CreateWindowExA` function.

```c title="cryptpad.exe" showLineNumbers
# ---- snip ----

  v0 = RegisterClassExA((const WNDCLASSEXA *)&open_file_name.pvReserved);
  if ( *(_DWORD *)&v0
    && (sub_401713(),
        hMenu = LoadMenuA(hInstance_0, (LPCSTR)1),
        (Window = CreateWindowExA(
                    0,
                    "CryptPAD",
                    "CryptPad",
                    0xCF0000u,
                    0x80000000,
                    0x80000000,
                    700,
                    500,
                    nullptr,
                    hMenu,
                    hInstance_0,
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

# ---- snip ----
```

