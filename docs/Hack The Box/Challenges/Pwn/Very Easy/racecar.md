> Spying time. Check what all users have been up to with this Challenge recently.

&nbsp;

Let's check the files properties first.

```
┌─[us-dedivip-1]─[10.10.14.129]─[kunull@htb-w0a6ami5sw]─[~/Downloads]
└──╼ [★]$ file racecar
racecar: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c5631a370f7704c44312f6692e1da56c25c1863c, not stripped
```

As we can see, the file a 32 bit ELF executable.

Let's run `checksec` to obtain information about the file's system configurations.

```
┌─[us-dedivip-1]─[10.10.14.129]─[kunull@htb-w0a6ami5sw]─[~/Downloads]
└──╼ [★]$ checksec racecar
[*] '/home/kunull/Downloads/racecar'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

Now that we know the basic details about the file, let't execute it.

```
┌─[us-dedivip-1]─[10.10.14.129]─[kunull@htb-w0a6ami5sw]─[~/Downloads]
└──╼ [★]$ ./racecar 

# --- snip ---

Insert your data:

Name: Kunal
Nickname: Kunull

[+] Welcome [Kunal]!

[*] Your name is [Kunal] but everybody calls you.. [Kunull]!
[*] Current coins: [69]

1. Car info
2. Car selection
> 2  


Select car:
1. 🚗
2. 🏎️
> 2


Select race:
1. Highway battle
2. Circuit
> 1  

[*] Waiting for the race to finish...

[+] You won the race!! You get 100 coins!
[+] Current coins: [169]

[!] Do you have anything to say to the press after your big victory?
> [-] Could not open flag.txt. Please contact the creator.
```

So if we choose the the second car and race on the highawy, we win, but we do not get the flog.
BTW, we win even if we choose the first car and race on teh circuit.

Since playing nice does not get us the flag, we must move on to debugging the executable.

## Debugging

```
┌─[us-dedivip-1]─[10.10.14.129]─[kunull@htb-w0a6ami5sw]─[~/Downloads]
└──╼ [★]$ gdb racecar

# --- snip ---

(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
   0x000013e1 <+0>:	lea    ecx,[esp+0x4]
   0x000013e5 <+4>:	and    esp,0xfffffff0
   0x000013e8 <+7>:	push   DWORD PTR [ecx-0x4]
   0x000013eb <+10>:	push   ebp
   0x000013ec <+11>:	mov    ebp,esp
   0x000013ee <+13>:	push   ebx
   0x000013ef <+14>:	push   ecx
   0x000013f0 <+15>:	sub    esp,0x10
   0x000013f3 <+18>:	call   0x7d0 <__x86.get_pc_thunk.bx>
   0x000013f8 <+23>:	add    ebx,0x2b94
   0x000013fe <+29>:	mov    eax,gs:0x14
   0x00001404 <+35>:	mov    DWORD PTR [ebp-0xc],eax
   0x00001407 <+38>:	xor    eax,eax
   0x00001409 <+40>:	call   0xb93 <setup>
   0x0000140e <+45>:	call   0x929 <banner>
   0x00001413 <+50>:	call   0x1082 <info>
   0x00001418 <+55>:	jmp    0x1463 <main+130>
   0x0000141a <+57>:	call   0x1352 <menu>
   0x0000141f <+62>:	cmp    eax,0x1
   0x00001422 <+65>:	je     0x142b <main+74>
   0x00001424 <+67>:	cmp    eax,0x2
   0x00001427 <+70>:	je     0x1432 <main+81>
   0x00001429 <+72>:	jmp    0x1443 <main+98>
   0x0000142b <+74>:	call   0x11d2 <car_info>
   0x00001430 <+79>:	jmp    0x1463 <main+130>
--Type <RET> for more, q to quit, c to continue without paging--c
   0x00001432 <+81>:	mov    DWORD PTR [ebx+0x80],0x0
   0x0000143c <+91>:	call   0xc91 <car_menu>
   0x00001441 <+96>:	jmp    0x1463 <main+130>
   0x00001443 <+98>:	sub    esp,0x4
   0x00001446 <+101>:	lea    eax,[ebx-0x2a54]
   0x0000144c <+107>:	push   eax
   0x0000144d <+108>:	lea    eax,[ebx-0x2a44]
   0x00001453 <+114>:	push   eax
   0x00001454 <+115>:	lea    eax,[ebx-0x2661]
   0x0000145a <+121>:	push   eax
   0x0000145b <+122>:	call   0x670 <printf@plt>
   0x00001460 <+127>:	add    esp,0x10
   0x00001463 <+130>:	mov    eax,DWORD PTR [ebx+0x80]
   0x00001469 <+136>:	test   eax,eax
   0x0000146b <+138>:	jne    0x141a <main+57>
   0x0000146d <+140>:	nop
   0x0000146e <+141>:	mov    eax,DWORD PTR [ebp-0xc]
   0x00001471 <+144>:	xor    eax,DWORD PTR gs:0x14
   0x00001478 <+151>:	je     0x147f <main+158>
   0x0000147a <+153>:	call   0x1500 <__stack_chk_fail_local>
   0x0000147f <+158>:	lea    esp,[ebp-0x8]
   0x00001482 <+161>:	pop    ecx
   0x00001483 <+162>:	pop    ebx
   0x00001484 <+163>:	pop    ebp
   0x00001485 <+164>:	lea    esp,[ecx-0x4]
   0x00001488 <+167>:	ret
End of assembler dump.

```
