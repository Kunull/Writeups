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

Let's decompile this program using IDA.

### Window setup

```c title="cryptpad.exe :: start() :: Pseudocode" showLineNumbers
void __noreturn start()
{
  ATOM v0; // ax
  HWND Window; // eax
  BOOL MessageA; // eax

  hInstance = GetModuleHandleA(nullptr);
  wnd_class.hInstance = hInstance;
  wnd_class.cbSize = 48;
  wnd_class.lpfnWndProc = sub_4011A0;
  wnd_class.style = 3;
  wnd_class.hIcon = LoadIconA(hInstance, (LPCSTR)0x7F00);
  wnd_class.hIconSm = wnd_class.hIcon;
  wnd_class.hCursor = LoadCursorA(nullptr, (LPCSTR)0x7F00);
  wnd_class.hbrBackground = (HBRUSH)16;
  wnd_class.lpszClassName = "CryptPAD";
  wnd_class.cbClsExtra = 0;
  wnd_class.cbWndExtra = 0;
  wnd_class.lpszMenuName = nullptr;
  wnd_class.hCursor = LoadCursorA(nullptr, (LPCSTR)0x7F00);
  wnd_class.style = 3;
  v0 = RegisterClassExA(&wnd_class);
  if ( *(_DWORD *)&v0
    && (sub_401713(),
        hMenu = LoadMenuA(wnd_class.hInstance, (LPCSTR)1),
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
                    wnd_class.hInstance,
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

We can see that the program calls the `GetModuleHandleA`.

```c title="cryptpad.exe :: start() :: Pseudocode" showLineNumbers
# ---- snip ----

  hInstance = GetModuleHandleA(nullptr);
  wnd_class.hInstance = hInstance;

# ---- snip ----
```

The `GetModuleHandleA` function returns the module handle, i.e. the unique, system-generated identifier (often a 32-bit or 64-bit integer)  for the specified module. 

A module handle (`HMODULE`) in Windows is a unique identifier (specifically, the base memory address) for an executable (`.exe`) or dynamic-link library (`.dll`) loaded into a process's address space.
It allows applications to reference specific loaded code modules to retrieve resources, function pointers, or module information. 

Since the `nullptr` argument is passed, `GetModuleHandle` returns a handle to the file used to create the calling process (.exe file).

Then it uses the `LoadIconA` function to load an icon resource from the executable (.exe) file associated with an application instance.

```c title="cryptpad.exe :: start() :: Pseudocode" showLineNumbers
# ---- snip ----

  wnd_class.hIcon = LoadIconA(hInstance, (LPCSTR)0x7F00);

# ---- snip ----
```

Then the `LoadCursorA` function is used to load an cursor resource from the executable (.exe) file associated with an application instance.

```c title="cryptpad.exe" showLineNumbers
# ---- snip ----

  wnd_class.hCursor = LoadCursorA(nullptr, (LPCSTR)0x7F00);

# ---- snip ----
```

Using `RegisterClassExA`, it registers the `open_file_name.pvReserved` window, and if that operation fails, it outputs and fail message and exits.

```c title="cryptpad.exe" showLineNumbers
# ---- snip ----

  v0 = RegisterClassExA(&wnd_class);
  
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

  v0 = RegisterClassExA(&wnd_class);
  if ( *(_DWORD *)&v0
    && (sub_401713(),
        hMenu = LoadMenuA(wnd_class.hInstance, (LPCSTR)1),
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
                    wnd_class.hInstance,
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

The program then uses `GetMessageA` retrieves a message from the thread’s message queue.

If the `GetMessageA` function succeeds, it uses the `TranslateMessage` function to translate a message, and then uses `DispatchMessageA` to dispatch the message.

There are two function calls which are made in the `start()` function: `sub_401713()` within the conditional statement and `sub_4011A0()` outside of that.

### Going down the rabbit hole

If we try to go into `sub_401713()`, it takes us down a rabbit hole.

```c title="cryptpad.exe :: sub_401713() :: Pseudocode" showLineNumbers
// attributes: thunk
void sub_401713(void)
{
  sub_40139D();
}
```

```c title="cryptpad.exe :: sub_40139D() :: Pseudocode" showLineNumbers
// attributes: thunk
void sub_40139D()
{
  sub_40119D();
}
```

```c title="cryptpad.exe :: sub_40119D() :: Pseudocode" showLineNumbers
// positive sp value has been detected, the output may be wrong!
void sub_40119D()
{
  ;
}
```

Let's look at the other function which is called: `sub_4011A0()`.

```c title="cryptpad.exe :: start() :: Pseudocode" showLineNumbers
# ---- snip ----

  wnd_class.lpfnWndProc = sub_4011A0;

# ---- snip ----
```

Looking at this function decomp, we can tell that it is the `WNDPROC` function, because it takes the same amount of arguments, and it's return value is stored in the `lpfnWndProc` field of the `WNDCLASSEXA` struct.

```c title="WNDCLASSEXA structure" showLineNumbers
typedef struct tagWNDCLASSEXA {
  UINT      cbSize;
  UINT      style;
  WNDPROC   lpfnWndProc;
  int       cbClsExtra;
  int       cbWndExtra;
  HINSTANCE hInstance;
  HICON     hIcon;
  HCURSOR   hCursor;
  HBRUSH    hbrBackground;
  LPCSTR    lpszMenuName;
  LPCSTR    lpszClassName;
  HICON     hIconSm;
} WNDCLASSEXA, *PWNDCLASSEXA, *NPWNDCLASSEXA, *LPWNDCLASSEXA;
```

```c title="cryptpad.exe :: sub_4011A0() :: Pseudocode" showLineNumbers
LRESULT __stdcall sub_4011A0(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)

# ---- snip ----
```

Knowing this, we can rename `sub_4011A0` to `WNDPROC`.

```c title="cryptpad.exe :: sub_4011A0() :: Pseudocode" showLineNumbers
LRESULT __stdcall WNDPROC(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  LRESULT result; // eax
  LRESULT result_1; // [esp-4h] [ebp-10h]
  int v6; // [esp+0h] [ebp-Ch]
  int v7; // [esp+4h] [ebp-8h]

  // WM_DESTROY
  if ( uMsg == 2 )
    goto POST_QUIT_MSG_AND_RETURN;

  // WM_COMMAND
  if ( uMsg == 273 )
  {
    switch ( (unsigned __int16)wParam )
    {
      case 'e':
        SendMessageA(dword_4024D1, 0xCu, (WPARAM)"CryptPad", 0);
        nullsub_1();
        SetWindowTextA((HWND)wnd_class.hInstance, "CryptPad");
        String[0] = 0;
        return 0;
      case 'p':
        return MessageBoxA(::hWnd, aCryptpad10IsAn, "CryptPad", 0);
      case 'o':
        return MessageBoxA(::hWnd, aToRegisterSend, "CryptPad", 0);
      case 'f':
        return sub_4013A2(v6, v7);
      case 'g':
        result = sub_401718(::hWnd);
        if ( result )
        {
          SetWindowTextA(::hWnd, String);
          sub_4013BD();
          return 0;
        }
        return result;
    }
    if ( (unsigned __int16)wParam != 105 )
      return DefWindowProcA(hWnd, uMsg, wParam, lParam);
POST_QUIT_MSG_AND_RETURN:
    PostQuitMessage(0);
    return 0;
  }

  // !WM_CREATE
  if ( uMsg != 1 )
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
  result = (LRESULT)CreateWindowExA(
                      0x200u,
                      aEdit,
                      nullptr,
                      0x50200044u,
                      0,
                      0,
                      700,
                      500,
                      hWnd,
                      nullptr,
                      wnd_class.hInstance,
                      nullptr);
  if ( result )
  {
    dword_4024D1 = (HWND)result;
    result_1 = result;
    ::wParam = CreateFontA(18, 0, 0, 0, 400, 0, 0, 0, 0, 5u, 0, 2u, 1u, pszFaceName);
    if ( result_1 == 140989193 )
    {
      return 140989194;
    }
    else
    {
      dword_403569 = SendMessageA(dword_4024D1, 0x30u, ::wParam, 0);
      dword_40356D = dword_403569;
      return 0;
    }
  }
  return result;
}
```

This function lets the user decide which action to perform, and if the user `g`, it calls the `sub_401718()` function, and if it returns a `True` response, it calls the `sub_4013BD()` function.

```c title="cryptpad.exe :: sub_4011A0() :: Pseudocode" showLineNumbers
# ---- snip ----

      case 'g':
        result = sub_401718(::hWnd);
        if ( result )
        {
          SetWindowTextA(::hWnd, String);
          sub_4013BD();
          return 0;
        }
        return result;

# ---- snip ----
```

### Opening a file

Let's look at the `sub_401718()` function.

```c title="cryptpad.exe :: sub_401718() :: Pseudocode" showLineNumbers
BOOL __stdcall sub_401718(HWND a1)
{
  memset(&open_file_name, 0, 0x4Cu);
  open_file_name.lStructSize = 76;
  open_file_name.hwndOwner = a1;
  open_file_name.lpstrFilter = aEncryptedFiles;
  open_file_name.lpstrFile = String;
  open_file_name.nMaxFile = 260;
  open_file_name.Flags = 526342;
  open_file_name.lpstrDefExt = aTxt;
  return GetSaveFileNameA(&open_file_name);
}
```

This function calls `GetSaveFileNameA`, which basically shows a Save File dialog and stores the chosen path in `String`.

### Save file dialog

Let's look at the `sub_4013BD()` function which is called after the user provides a file.

```c title="cryptpad.exe :: sub_4013BD() :: Pseuocode" showLineNumbers
BOOL sub_4013BD()
{
  HANDLE ProcessHeap; // eax
  CHAR *v1; // eax
  HANDLE FileA; // eax
  DWORD v3; // eax

  ProcessHeap = GetProcessHeap();
  if ( ProcessHeap
    && (hHeap = ProcessHeap,
        NumberOfBytesWritten = GetWindowTextLengthA(dword_4024D1) + 1,
        RandomBufferLength = 64 - NumberOfBytesWritten % 0x40,
        (v1 = HeapAlloc(hHeap, 0, NumberOfBytesWritten + RandomBufferLength)) != nullptr)
    && (lpMem = v1, (FileA = CreateFileA(String, 0x40000000u, 0, nullptr, 2u, 0x80u, nullptr)) != nullptr) )
  {
    hObject = FileA;
    GetWindowTextA(dword_4024D1, lpMem, NumberOfBytesWritten);
    sub_40166B(&lpMem[NumberOfBytesWritten], RandomBufferLength);
    sub_40166B(byte_4024C5, 8u);
    LOBYTE(v3) = sub_4014EB(lpMem, NumberOfBytesWritten, 1);
    WriteFile(hObject, lpMem, v3, &NumberOfBytesWritten, nullptr);
    CloseHandle(hObject);
  }
  else
  {
    MessageBoxA(nullptr, aErrorProcessin, Caption, 0x10u);
  }
  return HeapFree(hHeap, 0, lpMem);
}
```

This function uses `GetProcessHeap` to retrieve a handle to the default heap of the calling process. This handle can then be used in subsequent calls to the heap functions.
After obtaining a handle to the process heap, the function proceeds to prepare the data that will be written to disk.

```c title="cryptpad.exe :: sub_4013BD() :: Pseuocode" showLineNumbers
# ---- snip ----

        NumberOfBytesWritten = GetWindowTextLengthA(dword_4024D1) + 1;
        RandomBufferLength = 64 - NumberOfBytesWritten % 0x40;
        (v1 = HeapAlloc(hHeap, 0, NumberOfBytesWritten + RandomBufferLength)) != nullptr

# ---- snip ----
```

First, the program queries the length of the text currently present in the EDIT control using `GetWindowTextLengthA`. It adds 1 to account for the NULL terminator. Then it computes a padding length so that the total size becomes a multiple of `0x40` (64) bytes:

```c title="cryptpad.exe :: sub_4013BD() :: Pseuocode" showLineNumbers
# ---- snip ----

        RandomBufferLength = 64 - NumberOfBytesWritten % 0x40,

# ---- snip ----
```

This indicates that the program wants to align the plaintext size to 64-byte boundaries before encryption. 

A buffer of size `NumberOfBytesWritten + RandomBufferLength` is then allocated from the process heap using HeapAlloc.

```c title="cryptpad.exe :: sub_4013BD() :: Pseuocode" showLineNumbers
# ---- snip -----

        (v1 = HeapAlloc(hHeap, 0, NumberOfBytesWritten + RandomBufferLength)) != nullptr)

# ---- snip ----
```

Next, the program creates the output file using the path previously selected in the Save File dialog:

```c title="cryptpad.exe :: sub_4013BD() :: Pseuocode" showLineNumbers
# ---- snip ----

    FileA = CreateFileA(String, 0x40000000u, 0, nullptr, 2u, 0x80u, nullptr)) != nullptr) )

# ---- snip ----
```

Here:
- String contains the user-chosen file path
- `0x40000000` corresponds to `GENERIC_WRITE`
- `2` corresponds to `CREATE_ALWAYS`, meaning the file is created or overwritten.

If all of these steps succeed, the function proceeds with the actual data processing.

### Preparing the plaintext buffer

```c title="cryptpad.exe :: sub_4013BD() :: Pseuocode" showLineNumbers
# ---- snip ----

    GetWindowTextA(dword_4024D1, lpMem, NumberOfBytesWritten);

# ---- snip ----
```

The text from the `EDIT` control is copied into the allocated buffer `lpMem`.

Then, two calls are made to `sub_40166B`:

```c title="cryptpad.exe :: sub_4013BD() :: Pseuocode" showLineNumbers
# ---- snip ----

    sub_40166B(&lpMem[NumberOfBytesWritten], RandomBufferLength);
    sub_40166B(byte_4024C5, 8u);

# ---- snip ----
```

From earlier analysis of `sub_4013BD()`, we know that it calls `SystemFunction036` which is Windows API name for `RtlGenRandom`, a cryptographically secure random number generator. Therefore:
- The first call fills the padding region (after the plaintext) with random bytes.
- The second call fills an 8-byte global buffer (`byte_4024C5`) with random bytes. This 8-byte value acts as a key (or key material) for the encryption routine.

At this point, the buffer layout looks like:

```
[ plaintext (including null) ][ random padding ... ]
```

### Encrypting the buffer

Next, the function calls:

```c title="cryptpad.exe :: sub_4013BD() :: Pseuocode" showLineNumbers
# ---- snip ----

    LOBYTE(v3) = sub_4014EB(lpMem, NumberOfBytesWritten, 1);

# ---- snip ----
```

The third argument (`1`) indicates that this function is being called in “encryption mode”. This function performs the actual encryption in place on `lpMem` and returns the final number of bytes to write.

### RC4

```c title="cryptpad.exe :: sub_4014EB() :: Pseudocode" showLineNumbers
DWORD __stdcall sub_4014EB(_BYTE *buf, DWORD len, int mode)
{
  unsigned int v3; // ecx
  _BYTE *v4; // esi
  DWORD v5; // eax
  DWORD result; // eax
  BYTE *v8; // edi
  DWORD v9; // ecx
  int v10; // edx
  int v11; // ecx
  BYTE *v12; // esi
  int v13; // ecx
  int v14; // ebx
  int v15; // ebx
  BYTE *v16; // esi
  int v17; // eax
  int v18; // ecx
  BYTE v19; // dl
  int v21; // ebx
  int v23; // ecx
  BYTE v24; // dh
  BYTE v25; // dl
  BYTE *v27; // edi
  DWORD v28; // ecx
  int v29; // edx
  _BYTE *v30; // edi

  if ( mode )
  {
    if ( mode != 1 )
      return MessageBoxA(nullptr, nullptr, nullptr, 0);
  }
  else
  {
    v3 = *&buf[len - 1];
    v4 = &buf[len - 1 - v3];
    qmemcpy(byte_4024C5, v4, v3);
    v5 = *(v4 - 1);
    *(v4 - 1) = 0;
    len = v5;
  }
  v8 = byte_4024C5;
  v9 = NumberOfBytesWritten;
LABEL_6:
  v10 = 0;
  do
  {
    *buf++ ^= *v8++;
    if ( ++v10 == 8 )
      goto LABEL_6;
    --v9;
  }
  while ( v9 );

  // ```
  // for (i = 0; i < 256; i++)
  //     S[i] = i;
  // ```
  v11 = 256;
  do
  {
    byte_403795[-v11] = -v11;
    --v11;
  }
  while ( v11 );

  // ```
  // for i in range(256):
  //     K[i] = key[i % keylen]
  // ```
  v12 = byte_403695;
  v13 = 256;
  v14 = 0;
  do
  {
    if ( v14 >= 8 )
      v14 = 0;
    *v12++ = byte_4024C5[v14++];
    --v13;
  }
  while ( v13 );

  // ```
  // j = 0;
  // for i in range(256):
  //     j = (j + S[i] + K[i]) & 0xFF
  //     swap(S[i], S[j])
  // ```
  v15 = 0;
  v16 = v12 - 256;
  v17 = 0;
  v18 = 256;
  do
  {
    LOBYTE(v15) = byte_403795[v17] + v16[v17] + v15;
    v19 = byte_403795[v17];
    byte_403795[v17] = byte_403795[v15];
    byte_403795[v15] = v19;
    ++v17;
    --v18;
  }
  while ( v18 );
  result = 0;

  // ```
  // i = 0;
  // j = 0;
  // for n in range(len):
  //     i = (i + 1) & 0xFF
  //     j = (j + S[i]) & 0xFF
  //     swap(S[i], S[j])
  //     K = S[(S[i] + S[j]) & 0xFF]
  //     buf[n] ^= K
  // ```
  v21 = 0;
  do
  {
    v23 = (result + 1);
    v24 = byte_403795[v23];
    LOBYTE(v21) = v24 + v21;
    v25 = byte_403795[v21];
    byte_403795[v23] = v25;
    byte_403795[v21] = v24;
    LOBYTE(v23) = byte_403795[(v24 + v25)] ^ buf[result];
    buf[result++] = v23;
    --len;
  }
  while ( len != 1 );
  v27 = byte_4024C5;
  v28 = NumberOfBytesWritten;
LABEL_20:
  v29 = 0;
  do
  {
    LOBYTE(result) = *v27 ^ *buf;
    *buf++ = result;
    ++v27;
    if ( ++v29 == 8 )
      goto LABEL_20;
    --v28;
  }
  while ( v28 );
  if ( mode == 1 )
  {
    v30 = &buf[len - 13 + RandomBufferLength];
    *v30 = len;
    v30 += 4;
    qmemcpy(v30, byte_4024C5, 8u);
    v30[8] = 8;
    return RandomBufferLength + len;
  }
  return result;
}
```

The function initializes a 256-byte array.

```c title="cryptpad.exe :: sub_4014EB() :: Pseudocode" showLineNumbers
# ---- snip ----

  // ```
  // for (i = 0; i < 256; i++)
  //     S[i] = i;
  // ```
  v11 = 256;
  do
  {
    byte_403795[-v11] = -v11;
    --v11;
  }
  while ( v11 );

# ---- snip ----
```

#### Key Scheduling Algorithm (KSA)

Another 256-byte buffer is filled by repeating the 8-byte key, and then the code runs:

```c title="cryptpad.exe :: sub_4014EB() :: Pseudocode" showLineNumbers
# ---- snip ----

  // ```
  // j = 0;
  // for i in range(256):
  //     j = (j + S[i] + K[i]) & 0xFF
  //     swap(S[i], S[j])
  // ```
  v15 = 0;
  v16 = v12 - 256;
  v17 = 0;
  v18 = 256;
  do
  {
    LOBYTE(v15) = byte_403795[v17] + v16[v17] + v15;
    v19 = byte_403795[v17];
    byte_403795[v17] = byte_403795[v15];
    byte_403795[v15] = v19;
    ++v17;
    --v18;
  }
  while ( v18 );
  result = 0;

# ---- snip ----
```

This matches RC4’s Key Scheduling Algorithm exactly.

#### Pseudo-Random Generation Algorithm (PRGA)

The main loop follows the classic RC4 PRGA pattern:

```c title="cryptpad.exe :: sub_4014EB() :: Pseudocode" showLineNumbers
# ---- snip ----

  // ```
  // i = 0;
  // j = 0;
  // for n in range(len):
  //     i = (i + 1) & 0xFF
  //     j = (j + S[i]) & 0xFF
  //     swap(S[i], S[j])
  //     K = S[(S[i] + S[j]) & 0xFF]
  //     buf[n] ^= K
  // ```
  v21 = 0;
  do
  {
    v23 = (result + 1);
    v24 = byte_403795[v23];
    LOBYTE(v21) = v24 + v21;
    v25 = byte_403795[v21];
    byte_403795[v23] = v25;
    byte_403795[v21] = v24;
    LOBYTE(v23) = byte_403795[(v24 + v25)] ^ buf[result];
    buf[result++] = v23;
    --len;
  }

# ---- snip ----
```

This is the defining RC4 keystream generation and XOR step.

#### Symmetric XOR-based encryption

The buffer is XORed with the generated keystream, which is characteristic of RC4 (same operation for encryption and decryption).

## Solution

```py title="script.py" showLineNumbers
#!/usr/bin/env python3
import struct

def rc4_crypt(data: bytearray, key: bytes):
    # Build S-box
    S = list(range(256))
    T = [key[i % len(key)] for i in range(256)]

    # KSA
    j = 0
    for i in range(256):
        j = (j + S[i] + T[i]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # PRGA
    i = 0
    j = 0
    out = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out[k] = data[k] ^ K

    return out

def xor_with_key(buf: bytearray, key: bytes):
    out = bytearray(len(buf))
    for i in range(len(buf)):
        out[i] = buf[i] ^ key[i % len(key)]
    return out

def decrypt_file(path):
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < 13:
        raise ValueError("File too small to be valid")

    # Layout at end:
    # [ ... ciphertext ... ][ orig_len (4 bytes LE) ][ key (8 bytes) ][ 0x08 ]
    marker = data[-1]
    if marker != 0x08:
        print(f"[!] Warning: marker is {marker:#x}, expected 0x08")

    key = data[-9:-1]              # 8 bytes
    orig_len = struct.unpack("<I", data[-13:-9])[0]

    cipher = bytearray(data[:-13])  # everything before trailer

    # Reverse operations:
    # encryption was: XOR(key) -> RC4(key) -> XOR(key)
    # so decryption is the same in reverse order:

    step1 = xor_with_key(cipher, key)
    step2 = rc4_crypt(step1, key)
    plain = xor_with_key(step2, key)

    # Trim to original length
    plain = plain[:orig_len]

    return plain, key, orig_len

if __name__ == "__main__":
    plaintext, key, orig_len = decrypt_file("flag.enc")
    print(f"[+] Key: {key.hex()}")
    print(f"[+] Original length: {orig_len}")
    print("[+] Decrypted data:\n")
    try:
        print(plaintext.decode("utf-8", errors="replace"))
    except Exception:
        print(plaintext)

    # Also write to file
    with open("flag.dec", "wb") as f:
        f.write(plaintext)

    print("\n[+] Written output to flag.dec")
```

```
$ python3 solver.py
[+] Key: e8171bf4503f3d70
[+] Original length: 28
[+] Decrypted data:

CMO{r0ll_y0ur_0wn_b4d_c0d3}

[+] Written output to flag.dec
```