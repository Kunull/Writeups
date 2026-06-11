---
custom_edit_url: null
sidebar_position: 3
slug: /pwn-college/system-security/kernel-security
---

## level1.0

### Binary analysis

We start by disassembling the kernel module.

```text
hacker@vm_kernel-security~level1-0:~$ objdump -d /challenge/babykernel_level1.0.ko | tail -200
 845:   90                      nop
 846:   90                      nop
 847:   90                      nop
 848:   90                      nop
 849:   90                      nop
 84a:   90                      nop
 84b:   90                      nop
 84c:   90                      nop
 84d:   90                      nop
 84e:   90                      nop
 84f:   90                      nop
 850:   90                      nop
 851:   90                      nop
 852:   90                      nop
 853:   90                      nop
 854:   90                      nop
 855:   90                      nop
 856:   90                      nop
 857:   90                      nop
 858:   90                      nop
 859:   90                      nop
 85a:   90                      nop
 85b:   90                      nop
 85c:   90                      nop
 85d:   90                      nop
 85e:   90                      nop
 85f:   90                      nop
 860:   90                      nop
 861:   90                      nop
 862:   90                      nop
 863:   90                      nop
 864:   90                      nop
 865:   90                      nop
 866:   90                      nop
 867:   90                      nop
 868:   90                      nop
 869:   90                      nop
 86a:   90                      nop
 86b:   90                      nop
 86c:   90                      nop
 86d:   c3                      ret
 86e:   66 90                   xchg   %ax,%ax

0000000000000870 <init_module>:
 870:   55                      push   %rbp
 871:   31 d2                   xor    %edx,%edx
 873:   31 f6                   xor    %esi,%esi
 875:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 87c:   e8 00 00 00 00          call   881 <init_module+0x11>
 881:   48 c7 c2 00 00 00 00    mov    $0x0,%rdx
 888:   b9 10 00 00 00          mov    $0x10,%ecx
 88d:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
 894:   48 89 c5                mov    %rax,%rbp
 897:   48 89 d7                mov    %rdx,%rdi
 89a:   31 c0                   xor    %eax,%eax
 89c:   ba 80 00 00 00          mov    $0x80,%edx
 8a1:   f3 48 ab                rep stos %rax,%es:(%rdi)
 8a4:   48 8d 4d 68             lea    0x68(%rbp),%rcx
 8a8:   48 89 ef                mov    %rbp,%rdi
 8ab:   e8 00 00 00 00          call   8b0 <init_module+0x40>
 8b0:   48 89 ef                mov    %rbp,%rdi
 8b3:   31 f6                   xor    %esi,%esi
 8b5:   e8 00 00 00 00          call   8ba <init_module+0x4a>
 8ba:   48 c7 c1 00 00 00 00    mov    $0x0,%rcx
 8c1:   31 d2                   xor    %edx,%edx
 8c3:   be b6 01 00 00          mov    $0x1b6,%esi
 8c8:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 8cf:   e8 00 00 00 00          call   8d4 <init_module+0x64>
 8d4:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 8db:   48 89 05 00 00 00 00    mov    %rax,0x0(%rip)        # 8e2 <init_module+0x72>
 8e2:   e8 00 00 00 00          call   8e7 <init_module+0x77>
 8e7:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 8ee:   e8 00 00 00 00          call   8f3 <init_module+0x83>
 8f3:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 8fa:   e8 00 00 00 00          call   8ff <init_module+0x8f>
 8ff:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 906:   e8 00 00 00 00          call   90b <init_module+0x9b>
 90b:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 912:   e8 00 00 00 00          call   917 <init_module+0xa7>
 917:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 91e:   e8 00 00 00 00          call   923 <init_module+0xb3>
 923:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 92a:   e8 00 00 00 00          call   92f <init_module+0xbf>
 92f:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 936:   e8 00 00 00 00          call   93b <init_module+0xcb>
 93b:   31 c0                   xor    %eax,%eax
 93d:   5d                      pop    %rbp
 93e:   c3                      ret
 93f:   90                      nop

0000000000000940 <cleanup_module>:
 940:   48 8b 3d 00 00 00 00    mov    0x0(%rip),%rdi        # 947 <cleanup_module+0x7>
 947:   48 85 ff                test   %rdi,%rdi
 94a:   74 05                   je     951 <cleanup_module+0x11>
 94c:   e9 00 00 00 00          jmp    951 <cleanup_module+0x11>
 951:   c3                      ret

Disassembly of section .text.unlikely:

0000000000000000 <device_release>:
   0:   48 89 f2                mov    %rsi,%rdx
   3:   48 89 fe                mov    %rdi,%rsi
   6:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
   d:   e8 00 00 00 00          call   12 <device_release+0x12>
  12:   31 c0                   xor    %eax,%eax
  14:   c3                      ret

0000000000000015 <device_open>:
  15:   48 89 f2                mov    %rsi,%rdx
  18:   48 89 fe                mov    %rdi,%rsi
  1b:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  22:   e8 00 00 00 00          call   27 <device_open+0x12>
  27:   31 c0                   xor    %eax,%eax
  29:   c3                      ret

000000000000002a <device_write>:
  2a:   41 54                   push   %r12
  2c:   49 89 c8                mov    %rcx,%r8
  2f:   49 89 d4                mov    %rdx,%r12
  32:   48 89 d1                mov    %rdx,%rcx
  35:   55                      push   %rbp
  36:   48 89 f2                mov    %rsi,%rdx
  39:   48 89 f5                mov    %rsi,%rbp
  3c:   48 89 fe                mov    %rdi,%rsi
  3f:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  46:   48 83 ec 18             sub    $0x18,%rsp
  4a:   65 48 8b 04 25 28 00    mov    %gs:0x28,%rax
  51:   00 00 
  53:   48 89 44 24 10          mov    %rax,0x10(%rsp)
  58:   31 c0                   xor    %eax,%eax
  5a:   e8 00 00 00 00          call   5f <device_write+0x35>
  5f:   49 83 fc 10             cmp    $0x10,%r12
  63:   ba 10 00 00 00          mov    $0x10,%edx
  68:   48 89 ee                mov    %rbp,%rsi
  6b:   49 0f 46 d4             cmovbe %r12,%rdx
  6f:   48 89 e7                mov    %rsp,%rdi
  72:   e8 00 00 00 00          call   77 <device_write+0x4d>
  77:   ba 10 00 00 00          mov    $0x10,%edx
  7c:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
  83:   48 89 e7                mov    %rsp,%rdi
  86:   e8 00 00 00 00          call   8b <device_write+0x61>
  8b:   85 c0                   test   %eax,%eax
  8d:   0f 94 c0                sete   %al
  90:   ff c0                   inc    %eax
  92:   88 05 00 00 00 00       mov    %al,0x0(%rip)        # 98 <device_write+0x6e>
  98:   48 8b 44 24 10          mov    0x10(%rsp),%rax
  9d:   65 48 33 04 25 28 00    xor    %gs:0x28,%rax
  a4:   00 00 
  a6:   74 05                   je     ad <device_write+0x83>
  a8:   e8 00 00 00 00          call   ad <device_write+0x83>
  ad:   48 83 c4 18             add    $0x18,%rsp
  b1:   4c 89 e0                mov    %r12,%rax
  b4:   5d                      pop    %rbp
  b5:   41 5c                   pop    %r12
  b7:   c3                      ret

00000000000000b8 <device_read>:
  b8:   41 54                   push   %r12
  ba:   49 89 c8                mov    %rcx,%r8
  bd:   49 89 f4                mov    %rsi,%r12
  c0:   48 89 d1                mov    %rdx,%rcx
  c3:   55                      push   %rbp
  c4:   48 89 d5                mov    %rdx,%rbp
  c7:   48 89 f2                mov    %rsi,%rdx
  ca:   48 89 fe                mov    %rdi,%rsi
  cd:   53                      push   %rbx
  ce:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  d5:   e8 00 00 00 00          call   da <device_read+0x22>
  da:   8a 05 00 00 00 00       mov    0x0(%rip),%al        # e0 <device_read+0x28>
  e0:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
  e7:   3c 02                   cmp    $0x2,%al
  e9:   74 2d                   je     118 <device_read+0x60>
  eb:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
  f2:   7f 24                   jg     118 <device_read+0x60>
  f4:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
  fb:   84 c0                   test   %al,%al
  fd:   74 19                   je     118 <device_read+0x60>
  ff:   fe c8                   dec    %al
 101:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
 108:   75 0e                   jne    118 <device_read+0x60>
 10a:   c6 05 00 00 00 00 00    movb   $0x0,0x0(%rip)        # 111 <device_read+0x59>
 111:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
 118:   31 c0                   xor    %eax,%eax
 11a:   48 89 f7                mov    %rsi,%rdi
 11d:   48 83 c9 ff             or     $0xffffffffffffffff,%rcx
 121:   48 89 ea                mov    %rbp,%rdx
 124:   f2 ae                   repnz scas %es:(%rdi),%al
 126:   4c 89 e7                mov    %r12,%rdi
 129:   48 89 c8                mov    %rcx,%rax
 12c:   48 f7 d0                not    %rax
 12f:   48 8d 58 ff             lea    -0x1(%rax),%rbx
 133:   48 39 eb                cmp    %rbp,%rbx
 136:   48 0f 46 d3             cmovbe %rbx,%rdx
 13a:   e8 00 00 00 00          call   13f <device_read+0x87>
 13f:   48 29 c3                sub    %rax,%rbx
 142:   48 89 d8                mov    %rbx,%rax
 145:   5b                      pop    %rbx
 146:   5d                      pop    %rbp
 147:   41 5c                   pop    %r12
 149:   c3                      ret
```

Looking at the relevant sections:

**`device_write`** copies up to 16 bytes from userspace onto the stack, then calls `strncmp` against a global password string. Depending on the result, it sets a flag byte to `2` if the password matched, `1` otherwise.

**`device_read`** checks that flag byte. If it equals `2`, it reads from `/flag` and copies the contents back to userspace. If it equals `1`, it resets the flag to `0` and returns nothing useful.

We load the module into IDA to inspect the `.rodata` section.

<figure style={{ textAlign: 'center' }}>
 <img alt="image" src="https://github.com/user-attachments/assets/7a9ad384-2ec6-42ab-be7d-a6600d71affd" />
</figure>

```c title="/challenge/babykernel_level1.0.ko :: .rodata"
odata.str1.1:0000000000000D43 aDeviceErrorUnk db 'device error: unknown state',0Ah,0
.rodata.str1.1:0000000000000D43                                         ; DATA XREF: device_read+33↑o
.rodata.str1.1:0000000000000D43                                         ; device_read+49↑o
.rodata.str1.1:0000000000000D60 aFlag           db '/flag',0            ; DATA XREF: init_module+5↑o
.rodata.str1.1:0000000000000D66 aPwncollege     db 'pwncollege',0       ; DATA XREF: init_module+58↑o
.rodata.str1.1:0000000000000D71 unk_D71         db    1                 ; DATA XREF: init_module+64↑o
.rodata.str1.1:0000000000000D71                                         ; init_module+83↑o
.rodata.str1.1:0000000000000D72                 db  36h ; 6
.rodata.str1.1:0000000000000D73                 db  23h ; #
.rodata.str1.1:0000000000000D74                 db  23h ; #
.rodata.str1.1:0000000000000D75                 db  23h ; #
.rodata.str1.1:0000000000000D76                 db  0Ah
.rodata.str1.1:0000000000000D77                 db    0
.rodata.str1.1:0000000000000D78 unk_D78         db    1                 ; DATA XREF: init_module+BF↑o
.rodata.str1.1:0000000000000D79                 db  36h ; 6
.rodata.str1.1:0000000000000D7A                 db  47h ; G
.rodata.str1.1:0000000000000D7B                 db  6Fh ; o
.rodata.str1.1:0000000000000D7C                 db  6Fh ; o
.rodata.str1.1:0000000000000D7D                 db  64h ; d
.rodata.str1.1:0000000000000D7E                 db  20h
.rodata.str1.1:0000000000000D7F                 db  6Ch ; l
.rodata.str1.1:0000000000000D80                 db  75h ; u
.rodata.str1.1:0000000000000D81                 db  63h ; c
.rodata.str1.1:0000000000000D82                 db  6Bh ; k
.rodata.str1.1:0000000000000D83                 db  21h ; !
.rodata.str1.1:0000000000000D84                 db  0Ah
.rodata.str1.1:0000000000000D85                 db    0
.rodata.str1.1:0000000000000D85 _rodata_str1_1  ends
.rodata.str1.1:0000000000000D85
```

The password is `qqypfbyywqmzhfcn`.

We can also see:

- `aFlag` -> `/flag`: the file the module reads from
- `aPwncollege` -> `pwncollege`: the module name, which tells us where to find the proc entry

## Finding the device

The module isn't registered as a character device, so `/dev/pwncollege` doesn't exist. 
We can check `lsmod` to confirm the module name.

```text
hacker@vm_kernel-security~level1-0:~$ lsmod
Module                  Size  Used by
challenge              16384  0
```

We then look for the proc entry it registered.

```text
hacker@vm_kernel-security~level1-0:~$ find /proc -maxdepth 1 -type f 2>/dev/null
/proc/fb
/proc/dma
/proc/keys
/proc/kmsg
/proc/misc
/proc/mtrr
/proc/stat
/proc/iomem
/proc/kcore
/proc/locks
/proc/swaps
/proc/crypto
/proc/mdstat
/proc/uptime
/proc/vmstat
/proc/cgroups
/proc/cmdline
/proc/cpuinfo
/proc/devices
/proc/ioports
/proc/loadavg
/proc/meminfo
/proc/modules
/proc/version
/proc/consoles
/proc/kallsyms
/proc/slabinfo
/proc/softirqs
/proc/zoneinfo
/proc/buddyinfo
/proc/config.gz
/proc/diskstats
/proc/key-users
/proc/schedstat
/proc/interrupts
/proc/kpagecount
/proc/kpageflags
/proc/partitions
/proc/pwncollege
/proc/timer_list
/proc/execdomains
/proc/filesystems
/proc/vmallocinfo
/proc/pagetypeinfo
/proc/sysrq-trigger
```

There it is: `/proc/pwncollege`.

## Exploit

```text
hacker@vm_kernel-security~level1-0:~$ python3 -c "
import os
fd = os.open('/proc/pwncollege', os.O_RDWR)
os.write(fd, b'qqypfbyywqmzhfcn')
print(os.read(fd, 256))
"
```

The write triggers the `strncmp` check against `qqypfbyywqmzhfcn`, which passes and sets the flag byte to `2`. The subsequent read sees the flag byte is `2`, reads `/flag`, and returns the contents.
