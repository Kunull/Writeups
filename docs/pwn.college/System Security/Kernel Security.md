---
custom_edit_url: null
sidebar_position: 3
slug: /pwn-college/system-security/kernel-security
---

## level1.0

> Ease into kernel exploitation with this simple crackme level!

We have to first start and connect to the custom VM.

```
hacker@kernel-security~level1-0:~$ vm start
hacker@kernel-security~level1-0:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
hacker@vm_kernel-security~level1-0:~$ 
```

### Binary analysis

We start by disassembling the kernel module.

```
0040098a    int64_t device_write(int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4)

0040098a    {
0040098a        void* gsbase;
004009aa        int64_t rax = *(uint64_t*)((char*)gsbase + 0x28);
004009ba        printk(0x400b00, arg1, arg2, arg3, arg4);
004009c3        int64_t rdx_1 = 0x10;
004009c3        
004009cb        if (arg3 <= 0x10)
004009cb            rdx_1 = arg3;
004009cb        
004009d2        void var_28;
004009d2        _copy_from_user(&var_28, arg2, rdx_1);
004009ed        int32_t rax_2;
004009ed        (uint8_t)rax_2 = !strncmp(&var_28, "qqypfbyywqmzhfcn", 0x10);
004009f2        device_state = (uint8_t)rax_2 + 1;
004009f2        
00400a06        if (rax != *(uint64_t*)((char*)gsbase + 0x28))
00400a08            __stack_chk_fail();
00400a08        
00400a17        return arg3;
0040098a    }
```

```
int init_module(void)

{
  long lVar1;
  long lVar2;
  char *pcVar3;
  byte bVar4;
  
  bVar4 = 0;
  lVar1 = filp_open("/flag",0,0);
  pcVar3 = flag;
  for (lVar2 = 0x10; lVar2 != 0; lVar2 = lVar2 + -1) {
    pcVar3[0] = '\0';
    pcVar3[1] = '\0';
    pcVar3[2] = '\0';
    pcVar3[3] = '\0';
    pcVar3[4] = '\0';
    pcVar3[5] = '\0';
    pcVar3[6] = '\0';
    pcVar3[7] = '\0';
    pcVar3 = pcVar3 + ((ulong)bVar4 * -2 + 1) * 8;
  }
  kernel_read(lVar1,flag,0x80,lVar1 + 0x68);
  filp_close(lVar1,0);
  proc_entry = (proc_dir_entry *)proc_create("pwncollege",0x1b6,0,&fops);
  printk(&DAT_00100db1);
  printk(&DAT_00100bb0);
  printk(&DAT_00100db1);
  printk(&DAT_00100be0);
  printk(&DAT_00100c48);
  printk(&DAT_00100ca8);
  printk(&DAT_00100cf8);
  printk(&DAT_00100db8);
  return 0;
```

Looking at the relevant sections:

**`device_write`** copies up to 16 bytes from userspace onto the stack, then calls `strncmp` against a global password string. Depending on the result, it sets a flag byte to `2` if the password matched, `1` otherwise.

**`device_read`** checks that flag byte. If it equals `2`, it reads from `/flag` and copies the contents back to userspace. If it equals `1`, it resets the flag to `0` and returns nothing useful.

We load the module into IDA to inspect the `.rodata` section.

<figure style={{ textAlign: 'center' }}>
 <img alt="image" src="https://github.com/user-attachments/assets/7a9ad384-2ec6-42ab-be7d-a6600d71affd" />
</figure>

```c title="/challenge/babykernel_level1.0.ko :: .rodata"
.rodata.str1.1:0000000000000D43 aDeviceErrorUnk db 'device error: unknown state',0Ah,0
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

### Exploit

In another terminal craft the `~/exploit.c` file, and compile it.

```c title="~/exploit.c" showLineNumbers
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    write(fd, "qqypfbyywqmzhfcn", 16);

    char buf[256] = {0};
    int n = read(fd, buf, sizeof(buf));
    printf("%.*s\n", n, buf);

    close(fd);
    return 0;
}
```

```
hacker@kernel-security~level1-0:~$ gcc -o exploit exploit.c
```

Back in the VM terminal, execute the `~/exploit` binary.

```
hacker@vm_kernel-security~level1-0:~$ ./exploit 
pwn.college{07BVixbx15euU8bhJUNxxTetCwn.01MyQDL4ITM0EzW}
```

The write triggers the `strncmp` check against `qqypfbyywqmzhfcn`, which passes and sets the flag byte to `2`. The subsequent read sees the flag byte is `2`, reads `/flag`, and returns the contents.

Alternatively, we can just use a python script.

```text
hacker@vm_kernel-security~level1-0:~$ python3 -c "
> import os
> fd = os.open('/proc/pwncollege', os.O_RDWR)
> os.write(fd, b'qqypfbyywqmzhfcn')
> print(os.read(fd, 256))
> "
b'pwn.college{07BVixbx15euU8bhJUNxxTetCwn.01MyQDL4ITM0EzW}\n'
```

&nbsp;

## level1.1

> Ease into kernel exploitation with this simple crackme level!

We have to first start and connect to the custom VM.

```
hacker@kernel-security~level1-1:~$ vm start
hacker@kernel-security~level1-1:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
hacker@vm_kernel-security~level1-1:~$ 
```

### Binary analysis

We start by disassembling the kernel module.

```text
hacker@vm_kernel-security~level1-1:~$ objdump -d /challenge/babykernel_level1.1.ko | tail -75
 d3b:   90                      nop
 d3c:   90                      nop
 d3d:   90                      nop
 d3e:   90                      nop
 d3f:   90                      nop
 d40:   90                      nop
 d41:   90                      nop
 d42:   90                      nop
 d43:   90                      nop
 d44:   90                      nop
 d45:   90                      nop
 d46:   90                      nop
 d47:   90                      nop
 d48:   90                      nop
 d49:   90                      nop
 d4a:   90                      nop
 d4b:   90                      nop
 d4c:   90                      nop
 d4d:   90                      nop
 d4e:   90                      nop
 d4f:   90                      nop
 d50:   90                      nop
 d51:   90                      nop
 d52:   90                      nop
 d53:   90                      nop
 d54:   90                      nop
 d55:   c3                      ret
 d56:   66 2e 0f 1f 84 00 00    cs nopw 0x0(%rax,%rax,1)
 d5d:   00 00 00
0000000000000d60 <init_module>:
 d60:   55                      push   %rbp
 d61:   31 d2                   xor    %edx,%edx
 d63:   31 f6                   xor    %esi,%esi
 d65:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 d6c:   e8 00 00 00 00          call   d71 <init_module+0x11>
 d71:   48 c7 c2 00 00 00 00    mov    $0x0,%rdx
 d78:   b9 10 00 00 00          mov    $0x10,%ecx
 d7d:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
 d84:   48 89 c5                mov    %rax,%rbp
 d87:   48 89 d7                mov    %rdx,%rdi
 d8a:   31 c0                   xor    %eax,%eax
 d8c:   ba 80 00 00 00          mov    $0x80,%edx
 d91:   f3 48 ab                rep stos %rax,%es:(%rdi)
 d94:   48 8d 4d 68             lea    0x68(%rbp),%rcx
 d98:   48 89 ef                mov    %rbp,%rdi
 d9b:   e8 00 00 00 00          call   da0 <init_module+0x40>
 da0:   48 89 ef                mov    %rbp,%rdi
 da3:   31 f6                   xor    %esi,%esi
 da5:   e8 00 00 00 00          call   daa <init_module+0x4a>
 daa:   48 c7 c1 00 00 00 00    mov    $0x0,%rcx
 db1:   31 d2                   xor    %edx,%edx
 db3:   be b6 01 00 00          mov    $0x1b6,%esi
 db8:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 dbf:   e8 00 00 00 00          call   dc4 <init_module+0x64>
 dc4:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 dcb:   48 89 05 00 00 00 00    mov    %rax,0x0(%rip)        # dd2 <init_module+0x72>
 dd2:   e8 00 00 00 00          call   dd7 <init_module+0x77>
 dd7:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 dde:   e8 00 00 00 00          call   de3 <init_module+0x83>
 de3:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 dea:   e8 00 00 00 00          call   def <init_module+0x8f>
 def:   31 c0                   xor    %eax,%eax
 df1:   5d                      pop    %rbp
 df2:   c3                      ret
 df3:   66 66 2e 0f 1f 84 00    data16 cs nopw 0x0(%rax,%rax,1)
 dfa:   00 00 00 00
 dfe:   66 90                   xchg   %ax,%ax
0000000000000e00 <cleanup_module>:
 e00:   48 8b 3d 00 00 00 00    mov    0x0(%rip),%rdi        # e07 <cleanup_module+0x7>
 e07:   48 85 ff                test   %rdi,%rdi
 e0a:   74 05                   je     e11 <cleanup_module+0x11>
 e0c:   e9 00 00 00 00          jmp    e11 <cleanup_module+0x11>
 e11:   c3                      ret
```

The structure is identical to level1.0 — same `init_module`, same `device_write`/`device_read` pattern. We load the module into IDA to inspect the `.rodata` section and find the password.

```c title="/challenge/babykernel_level1.1.ko :: .rodata"
.rodata.str1.1:0000000000000E12 aFuxzvzdurndqgq db 'fuxzvzdurndqgqsv',0 ; DATA XREF: device_write+36↑o
.rodata.str1.1:0000000000000E23 aPassword       db 'password:',0Ah,0    ; DATA XREF: device_read+5A↑o
.rodata.str1.1:0000000000000E2E aInvalidPasswor db 'invalid password',0Ah,0
.rodata.str1.1:0000000000000E2E                                         ; DATA XREF: device_read+43↑o
.rodata.str1.1:0000000000000E40 aDeviceErrorUnk db 'device error: unknown state',0Ah,0
.rodata.str1.1:0000000000000E40                                         ; DATA XREF: device_read+1C↑o
.rodata.str1.1:0000000000000E5D aFlag           db '/flag',0            ; DATA XREF: init_module+5↑o
.rodata.str1.1:0000000000000E63 aPwncollege     db 'pwncollege',0       ; DATA XREF: init_module+58↑o
```

The password is `fuxzvzdurndqgqsv`.

We can also see:

- `aFlag` -> `/flag`: the file the module reads from
- `aPwncollege` -> `pwncollege`: the module name, which tells us where to find the proc entry

The module isn't registered as a character device, so `/dev/pwncollege` doesn't exist.
We can confirm the module name with `lsmod`.

```text
hacker@vm_kernel-security~level1-1:~$ lsmod
Module                  Size  Used by
challenge              16384  0
```

We then look for the proc entry it registered.

```text
hacker@vm_kernel-security~level1-1:~$ find /proc -maxdepth 1 -type f 2>/dev/null
...
/proc/pwncollege
...
```

There it is: `/proc/pwncollege`.

### Exploit

In another terminal craft the `~/exploit.c` file, and compile it.

```c title="~/exploit.c" showLineNumbers
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    write(fd, "fuxzvzdurndqgqsv", 16);

    char buf[256] = {0};
    int n = read(fd, buf, sizeof(buf));
    printf("%.*s\n", n, buf);

    close(fd);
    return 0;
}
```

```
hacker@kernel-security~level1-1:~$ gcc -o exploit exploit.c
```

Back in the VM terminal, execute the `~/exploit` binary.

```
hacker@vm_kernel-security~level1-1:~$ ./exploit
pwn.college{<flag>}
```

The write triggers the `strncmp` check against `fuxzvzdurndqgqsv`, which passes and sets the flag byte to `2`. The subsequent read sees the flag byte is `2`, reads `/flag`, and returns the contents.

&nbsp;

## level2.0

> Ease into kernel exploitation with another crackme level.

We have to first start and connect to the custom VM.

```
hacker@kernel-security~level2-0:~$ vm start
hacker@kernel-security~level2-0:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
hacker@vm_kernel-security~level2-0:~$ 
```

### Binary analysis

We start by disassembling the kernel module.

```text
hacker@vm_kernel-security~level2-0:~$ objdump -d /challenge/babykernel_level2.0.ko | tail -200

# ---- snip ----

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
  8d:   75 13                   jne    a2 <device_write+0x78>
  8f:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
  96:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  9d:   e8 00 00 00 00          call   a2 <device_write+0x78>
  a2:   48 8b 44 24 10          mov    0x10(%rsp),%rax

# ---- snip ----

```

This level differs from level1 — `device_write` no longer sets a flag byte for `device_read` to check. Instead, on a correct password it directly calls a function with two string arguments:

```asm
8d:   jne    a2              ← skip if password wrong
8f:   mov    rsi,0x0         ← format string argument
96:   mov    rdi,0x0         ← format string argument
9d:   call   a2              ← logs the flag to the kernel ring buffer
```

We load the module into IDA to inspect the `.rodata` section.

```c title="/challenge/babykernel_level2.0.ko :: .rodata"
.rodata.str1.1:0000000000000B67 ; const char s2[]
.rodata.str1.1:0000000000000B67 s2              db 'zvcjxwvydfmyjyhl',0 ; DATA XREF: device_write+52↑o
.rodata.str1.1:0000000000000B78 unk_B78         db    1                 ; DATA XREF: device_write+6C↑o
.rodata.str1.1:0000000000000B79                 db  36h ; 6
.rodata.str1.1:0000000000000B7A                 db  54h ; T

# ---- snip ----

.rodata.str1.1:0000000000000B7E                 db  66h ; f
.rodata.str1.1:0000000000000B7F                 db  6Ch ; l
.rodata.str1.1:0000000000000B80                 db  61h ; a
.rodata.str1.1:0000000000000B81                 db  67h ; g
.rodata.str1.1:0000000000000B82                 db  20h
.rodata.str1.1:0000000000000B83                 db  69h ; i
.rodata.str1.1:0000000000000B84                 db  73h ; s
.rodata.str1.1:0000000000000B85                 db  3Ah ; :
.rodata.str1.1:0000000000000B86                 db  20h
.rodata.str1.1:0000000000000B87                 db  25h ; %
.rodata.str1.1:0000000000000B88                 db  73h ; s  ← "The flag is: %s"
.rodata.str1.1:0000000000000B8B aFlag           db '/flag',0            ; DATA XREF: init_module+5↑o
.rodata.str1.1:0000000000000B91 aPwncollege     db 'pwncollege',0       ; DATA XREF: init_module+58↑o
```

The password is `zvcjxwvydfmyjyhl`. On a correct password match, `device_write` calls `printk` with the format string `"The flag is: %s"` and the contents of `/flag`, logging it to the kernel ring buffer instead of returning it via `device_read`.

### Exploit

In another terminal craft the `~/exploit.c` file, and compile it. Since the flag is no longer returned via `read`, we drop that part.

```c title="~/exploit.c" showLineNumbers
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    write(fd, "zvcjxwvydfmyjyhl", 16);

    close(fd);
    return 0;
}
```

```
hacker@kernel-security~level2-0:~$ gcc -o exploit exploit.c
```

Back in the VM terminal, execute the `~/exploit` binary, then check the kernel ring buffer.

```
hacker@vm_kernel-security~level2-0:~$ ./exploit
hacker@vm_kernel-security~level2-0:~$ dmesg | tail
[   34.858035] [device_open] inode=ffff88807cab5448, file=ffff88807d6d7c00
[   34.859952] [device_write] file=ffff88807d6d7c00, buffer=0000565415d6501a, length=16, offset=ffffc90000157f08
[   34.862507] The flag is: pwn.college{kvGaeMALSoqkJpMltIq3vLw_vPd.0VNyQDL4ITM0EzW}
[   34.867074] [device_release] inode=ffff88807cab5448, file=ffff88807d6d7c00
```

The write triggers the `strncmp` check against `zvcjxwvydfmyjyhl`, which passes. On success `device_write` calls `printk` with the flag contents, which logs it to the kernel ring buffer. We retrieve it with `dmesg`.

&nbsp;

## level2.1

> Ease into kernel exploitation with another crackme level.
 
We have to first start and connect to the custom VM.

```
hacker@kernel-security~level2-1:~$ vm start
hacker@kernel-security~level2-1:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
hacker@vm_kernel-security~level2-1:~$ 
```

### Binary analysis

We start by disassembling the kernel module.

```text
hacker@vm_kernel-security~level2-1:~$ objdump -d /challenge/babykernel_level2.1.ko | tail -75
 32b:   90                      nop
 32c:   90                      nop
...
 33f:   c3                      ret
0000000000000340 <init_module>:
 340:   55                      push   %rbp
 341:   31 d2                   xor    %edx,%edx
...
00000000000003e0 <cleanup_module>:
 3e0:   48 8b 3d 00 00 00 00    mov    0x0(%rip),%rdi
...
 3f1:   c3                      ret

Disassembly of section .text.unlikely:

0000000000000000 <device_write.cold>:
   0:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
   7:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
   e:   e8 00 00 00 00          call   13 <device_write.cold+0x13>
  13:   e9 00 00 00 00          jmp    18 <device_write+0x8>
```

The structure is identical to level2.0 — same `printk` on correct password pattern. We load the module into IDA to inspect the `.rodata` section and find the password.

```c title="/challenge/babykernel_level2.1.ko :: .rodata"
.rodata.str1.1:000000000000040A aLmutfodocxaogx db 'lmutfodocxaogxuk',0 ; DATA XREF: device_write+36↑o
.rodata.str1.1:000000000000041B unk_41B         db    1                 ; DATA XREF: device_write_cold+7↑o
.rodata.str1.1:000000000000041C                 db  36h ; 6
.rodata.str1.1:000000000000041D                 db  54h ; T
...
.rodata.str1.1:0000000000000421                 db  66h ; f
.rodata.str1.1:0000000000000422                 db  6Ch ; l
.rodata.str1.1:0000000000000423                 db  61h ; a
.rodata.str1.1:0000000000000424                 db  67h ; g
.rodata.str1.1:0000000000000425                 db  20h
.rodata.str1.1:0000000000000426                 db  69h ; i
.rodata.str1.1:0000000000000427                 db  73h ; s
.rodata.str1.1:0000000000000428                 db  3Ah ; :
.rodata.str1.1:0000000000000429                 db  20h
.rodata.str1.1:000000000000042A                 db  25h ; %
.rodata.str1.1:000000000000042B                 db  73h ; s  ← "The flag is: %s"
```

The password is `lmutfodocxaogxuk`.

### Exploit

In another terminal craft the `~/exploit.c` file, and compile it.

```c title="~/exploit.c" showLineNumbers
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    write(fd, "lmutfodocxaogxuk", 16);

    close(fd);
    return 0;
}
```

```
hacker@kernel-security~level2-1:~$ gcc -o exploit exploit.c
```

Back in the VM terminal, execute the `~/exploit` binary, then check the kernel ring buffer.

```
hacker@vm_kernel-security~level2-1:~$ ./exploit
hacker@vm_kernel-security~level2-1:~$ dmesg | tail
[    ...] [device_open] ...
[    ...] [device_write] ...
[    ...] The flag is: pwn.college{<flag>}
[    ...] [device_release] ...
```

The write triggers the `strncmp` check against `lmutfodocxaogxuk`, which passes. On success `device_write` calls `printk` with the flag contents, logging it to the kernel ring buffer. We retrieve it with `dmesg`.

&nbsp;

## level3.0

> Ease into kernel exploitation with another crackme level, this time with some privilege escalation (whoami?).

We have to first start and connect to the custom VM.

```
hacker@kernel-security~level3-0:~$ vm start
hacker@kernel-security~level3-0:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
hacker@vm_kernel-security~level3-0:~$ 
```

### Binary analysis

We start by disassembling the kernel module.

```text
hacker@vm_kernel-security~level3-0:~$ objdump -d /challenge/babykernel_level3.0.ko | tail -200

# ---- snip ----

0000000000000720 <init_module>:
 720:   48 c7 c1 00 00 00 00    mov    $0x0,%rcx
 727:   31 d2                   xor    %edx,%edx
 729:   be b6 01 00 00          mov    $0x1b6,%esi
 72e:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 735:   e8 00 00 00 00          call   73a <init_module+0x1a>
 73a:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 741:   48 89 05 00 00 00 00    mov    %rax,0x0(%rip)        # 748 <init_module+0x28>
 748:   e8 00 00 00 00          call   74d <init_module+0x2d>
 74d:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 754:   e8 00 00 00 00          call   759 <init_module+0x39>
 759:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 760:   e8 00 00 00 00          call   765 <init_module+0x45>
 765:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 76c:   e8 00 00 00 00          call   771 <init_module+0x51>
 771:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 778:   e8 00 00 00 00          call   77d <init_module+0x5d>
 77d:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 784:   e8 00 00 00 00          call   789 <init_module+0x69>
 789:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 790:   e8 00 00 00 00          call   795 <init_module+0x75>
 795:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 79c:   e8 00 00 00 00          call   7a1 <init_module+0x81>
 7a1:   31 c0                   xor    %eax,%eax
 7a3:   c3                      ret
 7a4:   66 66 2e 0f 1f 84 00    data16 cs nopw 0x0(%rax,%rax,1)
 7ab:   00 00 00 00
 7af:   90                      nop

00000000000007b0 <cleanup_module>:
 7b0:   48 8b 3d 00 00 00 00    mov    0x0(%rip),%rdi        # 7b7 <cleanup_module+0x7>
 7b7:   48 85 ff                test   %rdi,%rdi
 7ba:   74 05                   je     7c1 <cleanup_module+0x11>
 7bc:   e9 00 00 00 00          jmp    7c1 <cleanup_module+0x11>
 7c1:   c3                      ret

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

000000000000002a <win>:
  2a:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  31:   e8 00 00 00 00          call   36 <win+0xc>
  36:   31 ff                   xor    %edi,%edi
  38:   e8 00 00 00 00          call   3d <win+0x13>
  3d:   48 89 c7                mov    %rax,%rdi
  40:   e9 00 00 00 00          jmp    45 <device_write>

0000000000000045 <device_write>:
  45:   41 54                   push   %r12
  47:   49 89 c8                mov    %rcx,%r8
  4a:   49 89 d4                mov    %rdx,%r12
  4d:   48 89 d1                mov    %rdx,%rcx
  50:   55                      push   %rbp
  51:   48 89 f2                mov    %rsi,%rdx
  54:   48 89 f5                mov    %rsi,%rbp
  57:   48 89 fe                mov    %rdi,%rsi
  5a:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  61:   48 83 ec 18             sub    $0x18,%rsp
  65:   65 48 8b 04 25 28 00    mov    %gs:0x28,%rax
  6c:   00 00
  6e:   48 89 44 24 10          mov    %rax,0x10(%rsp)
  73:   31 c0                   xor    %eax,%eax
  75:   e8 00 00 00 00          call   7a <device_write+0x35>
  7a:   49 83 fc 10             cmp    $0x10,%r12
  7e:   ba 10 00 00 00          mov    $0x10,%edx
  83:   48 89 ee                mov    %rbp,%rsi
  86:   49 0f 46 d4             cmovbe %r12,%rdx
  8a:   48 89 e7                mov    %rsp,%rdi
  8d:   e8 00 00 00 00          call   92 <device_write+0x4d>
  92:   ba 10 00 00 00          mov    $0x10,%edx
  97:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
  9e:   48 89 e7                mov    %rsp,%rdi
  a1:   e8 00 00 00 00          call   a6 <device_write+0x61>
  a6:   85 c0                   test   %eax,%eax
  a8:   75 05                   jne    af <device_write+0x6a>
  aa:   e8 7b ff ff ff          call   2a <win>
  af:   48 8b 44 24 10          mov    0x10(%rsp),%rax
  b4:   65 48 33 04 25 28 00    xor    %gs:0x28,%rax
  bb:   00 00
  bd:   74 05                   je     c4 <device_write+0x7f>
  bf:   e8 00 00 00 00          call   c4 <device_write+0x7f>
  c4:   48 83 c4 18             add    $0x18,%rsp
  c8:   4c 89 e0                mov    %r12,%rax
  cb:   5d                      pop    %rbp
  cc:   41 5c                   pop    %r12
  ce:   c3                      ret
```

This level introduces a new concept. Rather than logging the flag or returning it via `device_read`, a dedicated `win` function is now called on a correct password match.

Looking at `win`:

- It calls `prepare_kernel_cred(0)` to create root credentials
- It then calls `commit_creds()` with the result, elevating the calling process to root

`device_write` calls `win` directly when the `strncmp` succeeds:

```asm
a6:   test   eax,eax
a8:   jne    af         ← skip if wrong password
aa:   call   2a <win>   ← escalate to root if correct
```

We load the module into IDA to find the password in `.rodata`.

```c title="/challenge/babykernel_level3.0.ko :: .rodata"
.rodata.str1.1:0000000000000B15 ; const char s2[]
.rodata.str1.1:0000000000000B15 s2              db 'mmtilqnbfhgnhthd',0 ; DATA XREF: device_write+52↑o
.rodata.str1.1:0000000000000B26 aPwncollege     db 'pwncollege',0       ; DATA XREF: init_module+E↑o
```

We also see in `.rodata.str1.8`:

```c
.rodata.str1.8:00000000000008E8 unk_8E8  db  1   ; DATA XREF: win↑o
; "You win! Your current process has been elevated to root!"
```

The password is `mmtilqnbfhgnhthd`. Since writing the correct password elevates us to root, we can spawn a shell immediately after and read the flag directly.

### Exploit

In another terminal craft the `~/exploit.c` file, and compile it.

```c title="~/exploit.c" showLineNumbers
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    write(fd, "mmtilqnbfhgnhthd", 16);
    close(fd);

    // We are now root
    execl("/bin/sh", "sh", NULL);
    return 0;
}
```

```
hacker@kernel-security~level3-0:~$ gcc -o exploit exploit.c
```

Back in the VM terminal, execute the `~/exploit` binary. Since `win` elevates the process to root, we get a root shell and can read the flag directly.

```
hacker@vm_kernel-security~level3-0:~$ ./exploit
# cat /flag
pwn.college{IvvJ-wZjG1cr6EBAfHi6ZORHXcT.01NyQDL4ITM0EzW}
```

The write triggers the `strncmp` check against `mmtilqnbfhgnhthd`, which passes. On success `device_write` calls `win`, which calls `prepare_kernel_cred(0)` and `commit_creds()` to escalate the process to root. We then spawn a shell and read `/flag`.

&nbsp;

## level3.1

> Ease into kernel exploitation with another crackme level, this time with some privilege escalation (whoami?).

We have to first start and connect to the custom VM.

```
hacker@kernel-security~level3-1:~$ vm start
hacker@kernel-security~level3-1:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
hacker@vm_kernel-security~level3-1:~$ 
```

### Binary analysis

We start by disassembling the kernel module.

```text
hacker@vm_kernel-security~level3-1:~$ objdump -d /challenge/babykernel_level3.1.ko | tail -100

# ---- snip ----

0000000000000850 <device_write>:
 850:   41 54                   push   %r12
 852:   49 89 d4                mov    %rdx,%r12
 855:   55                      push   %rbp
 856:   53                      push   %rbx
 857:   bb 10 00 00 00          mov    $0x10,%ebx
 85c:   48 83 ec 18             sub    $0x18,%rsp
 860:   65 48 8b 04 25 28 00    mov    %gs:0x28,%rax
 867:   00 00
 869:   48 89 44 24 10          mov    %rax,0x10(%rsp)
 86e:   31 c0                   xor    %eax,%eax
 870:   48 83 fa 10             cmp    $0x10,%rdx
 874:   48 89 da                mov    %rbx,%rdx
 877:   48 89 e5                mov    %rsp,%rbp
 87a:   49 0f 46 d4             cmovbe %r12,%rdx
 87e:   48 89 ef                mov    %rbp,%rdi
 881:   e8 00 00 00 00          call   886 <device_write+0x36>
 886:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 88d:   48 89 ee                mov    %rbp,%rsi
 890:   48 89 d9                mov    %rbx,%rcx
 893:   f3 a6                   repz cmpsb %es:(%rdi),%ds:(%rsi)
 895:   0f 97 c0                seta   %al
 898:   1c 00                   sbb    $0x0,%al
 89a:   84 c0                   test   %al,%al
 89c:   0f 84 00 00 00 00       je     8a2 <device_write+0x52>
 8a2:   48 8b 44 24 10          mov    0x10(%rsp),%rax
 8a7:   65 48 33 04 25 28 00    xor    %gs:0x28,%rax
 8ae:   00 00
 8b0:   75 0c                   jne    8be <device_write+0x6e>
 8b2:   48 83 c4 18             add    $0x18,%rsp
 8b6:   4c 89 e0                mov    %r12,%rax
 8b9:   5b                      pop    %rbx
 8ba:   5d                      pop    %rbp
 8bb:   41 5c                   pop    %r12
 8bd:   c3                      ret
 8be:   e8 00 00 00 00          call   8c3 <device_write+0x73>
 8c3:   66 66 2e 0f 1f 84 00    data16 cs nopw 0x0(%rax,%rax,1)
 8ca:   00 00 00 00
 8ce:   66 90                   xchg   %ax,%ax

00000000000008d0 <init_module>:
 8d0:   48 c7 c1 00 00 00 00    mov    $0x0,%rcx
 8d7:   31 d2                   xor    %edx,%edx
 8d9:   be b6 01 00 00          mov    $0x1b6,%esi
 8de:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 8e5:   e8 00 00 00 00          call   8ea <init_module+0x1a>
 8ea:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 8f1:   48 89 05 00 00 00 00    mov    %rax,0x0(%rip)        # 8f8 <init_module+0x28>
 8f8:   e8 00 00 00 00          call   8fd <init_module+0x2d>
 8fd:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 904:   e8 00 00 00 00          call   909 <init_module+0x39>
 909:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 910:   e8 00 00 00 00          call   915 <init_module+0x45>
 915:   31 c0                   xor    %eax,%eax
 917:   c3                      ret
 918:   0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)
 91f:   00

0000000000000920 <cleanup_module>:
 920:   48 8b 3d 00 00 00 00    mov    0x0(%rip),%rdi        # 927 <cleanup_module+0x7>
 927:   48 85 ff                test   %rdi,%rdi
 92a:   74 05                   je     931 <cleanup_module+0x11>
 92c:   e9 00 00 00 00          jmp    931 <cleanup_module+0x11>
 931:   c3                      ret

Disassembly of section .text.unlikely:

0000000000000000 <win>:
   0:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
   7:   e8 00 00 00 00          call   c <win+0xc>
   c:   31 ff                   xor    %edi,%edi
   e:   e8 00 00 00 00          call   13 <win+0x13>
  13:   48 89 c7                mov    %rax,%rdi
  16:   e9 00 00 00 00          jmp    1b <device_write.cold>

000000000000001b <device_write.cold>:
  1b:   e8 e0 ff ff ff          call   0 <win>
  20:   e9 00 00 00 00          jmp    25 <bin_padding+0x5>
```

The structure is identical to level3.0 — same `win` function calling `prepare_kernel_cred(0)` and `commit_creds()` to elevate the process to root. We load the module into IDA to find the password in `.rodata`.

```c title="/challenge/babykernel_level3.1.ko :: .rodata"
.rodata.str1.1:00000000000009C1 aLimtlgzgaygsln db 'limtlgzgaygslnew',0 ; DATA XREF: device_write+36↑o
.rodata.str1.1:00000000000009D2 aPwncollege     db 'pwncollege',0       ; DATA XREF: init_module+E↑o
```

We also see in `.rodata.str1.8`:

```c
.rodata.str1.8:0000000000000958 unk_958  db  1   ; DATA XREF: win↑o
; "You win! Your current process has been elevated to root!"
```

The password is `limtlgzgaygslnew`.

### Exploit

In another terminal craft the `~/exploit.c` file, and compile it.

```c title="~/exploit.c" showLineNumbers
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    write(fd, "limtlgzgaygslnew", 16);
    close(fd);

    // We are now root
    execl("/bin/sh", "sh", NULL);
    return 0;
}
```

```
hacker@kernel-security~level3-1:~$ gcc -o exploit exploit.c
```

Back in the VM terminal, execute the `~/exploit` binary. Since `win` elevates the process to root, we get a root shell and can read the flag directly.

```
hacker@vm_kernel-security~level3-1:~$ ./exploit
# cat /flag
pwn.college{oNavJdiPACQZl0IXl7WH4m9j6Qj.0FOyQDL4ITM0EzW}
```

The write triggers the `strncmp` check against `limtlgzgaygslnew`, which passes. On success `device_write` calls `win`, which calls `prepare_kernel_cred(0)` and `commit_creds()` to escalate the process to root. We then spawn a shell and read `/flag`.

&nbsp;

## level4.0

> Ease into kernel exploitation with another crackme level and learn how kernel devices communicate.

We have to first start and connect to the custom VM.

```
hacker@kernel-security~level4-0:~$ vm start
hacker@kernel-security~level4-0:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
hacker@vm_kernel-security~level4-0:~$
```

### Binary analysis

We start by disassembling the kernel module.

```text
hacker@vm_kernel-security~level4-0:~$ objdump -d /challenge/babykernel_level4.0.ko | tail -200

# ---- snip ----

0000000000000b70 <init_module>:
 b70:   48 c7 c1 00 00 00 00    mov    $0x0,%rcx
 b77:   31 d2                   xor    %edx,%edx
 b79:   be b6 01 00 00          mov    $0x1b6,%esi
 b7e:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 b85:   e8 00 00 00 00          call   b8a <init_module+0x1a>
 b8a:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 b91:   48 89 05 00 00 00 00    mov    %rax,0x0(%rip)        # b98 <init_module+0x28>
 b98:   e8 00 00 00 00          call   b9d <init_module+0x2d>
 b9d:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 ba4:   e8 00 00 00 00          call   ba9 <init_module+0x39>
 ba9:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 bb0:   e8 00 00 00 00          call   bb5 <init_module+0x45>
 bb5:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 bbc:   e8 00 00 00 00          call   bc1 <init_module+0x51>
 bc1:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 bc8:   e8 00 00 00 00          call   bcd <init_module+0x5d>
 bcd:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 bd4:   e8 00 00 00 00          call   bd9 <init_module+0x69>
 bd9:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 be0:   e8 00 00 00 00          call   be5 <init_module+0x75>
 be5:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 bec:   e8 00 00 00 00          call   bf1 <init_module+0x81>
 bf1:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 bf8:   e8 00 00 00 00          call   bfd <init_module+0x8d>
 bfd:   31 c0                   xor    %eax,%eax
 bff:   c3                      ret

0000000000000c00 <cleanup_module>:
 c00:   48 8b 3d 00 00 00 00    mov    0x0(%rip),%rdi        # c07 <cleanup_module+0x7>
 c07:   48 85 ff                test   %rdi,%rdi
 c0a:   74 05                   je     c11 <cleanup_module+0x11>
 c0c:   e9 00 00 00 00          jmp    c11 <cleanup_module+0x11>
 c11:   c3                      ret

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

000000000000002a <win>:
  2a:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  31:   e8 00 00 00 00          call   36 <win+0xc>
  36:   31 ff                   xor    %edi,%edi
  38:   e8 00 00 00 00          call   3d <win+0x13>
  3d:   48 89 c7                mov    %rax,%rdi
  40:   e9 00 00 00 00          jmp    45 <device_ioctl>

0000000000000045 <device_ioctl>:
  45:   55                      push   %rbp
  46:   48 89 d1                mov    %rdx,%rcx
  49:   48 89 d5                mov    %rdx,%rbp
  4c:   89 f2                   mov    %esi,%edx
  4e:   53                      push   %rbx
  4f:   89 f3                   mov    %esi,%ebx
  51:   48 89 fe                mov    %rdi,%rsi
  54:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  5b:   48 83 ec 18             sub    $0x18,%rsp
  5f:   65 48 8b 04 25 28 00    mov    %gs:0x28,%rax
  66:   00 00
  68:   48 89 44 24 10          mov    %rax,0x10(%rsp)
  6d:   31 c0                   xor    %eax,%eax
  6f:   e8 00 00 00 00          call   74 <device_ioctl+0x2f>
  74:   48 83 c8 ff             or     $0xffffffffffffffff,%rax
  78:   81 fb 39 05 00 00       cmp    $0x539,%ebx
  7e:   75 35                   jne    b5 <device_ioctl+0x70>
  80:   ba 10 00 00 00          mov    $0x10,%edx
  85:   48 89 ee                mov    %rbp,%rsi
  88:   48 89 e7                mov    %rsp,%rdi
  8b:   e8 00 00 00 00          call   90 <device_ioctl+0x4b>
  90:   ba 10 00 00 00          mov    $0x10,%edx
  95:   48 c7 c6 00 00 00 00    mov    $0x0,%rsi
  9c:   48 89 e7                mov    %rsp,%rdi
  9f:   e8 00 00 00 00          call   a4 <device_ioctl+0x5f>
  a4:   41 89 c0                mov    %eax,%r8d
  a7:   31 c0                   xor    %eax,%eax
  a9:   45 85 c0                test   %r8d,%r8d
  ac:   75 07                   jne    b5 <device_ioctl+0x70>
  ae:   e8 77 ff ff ff          call   2a <win>
  b3:   31 c0                   xor    %eax,%eax
  b5:   48 8b 4c 24 10          mov    0x10(%rsp),%rcx
  ba:   65 48 33 0c 25 28 00    xor    %gs:0x28,%rcx
  c1:   00 00
  c3:   74 05                   je     ca <device_ioctl+0x85>
  c5:   e8 00 00 00 00          call   ca <device_ioctl+0x85>
  ca:   48 83 c4 18             add    $0x18,%rsp
  ce:   5b                      pop    %rbx
  cf:   5d                      pop    %rbp
  d0:   c3                      ret
```

This level introduces `device_ioctl` as the handler instead of `device_write`. Two conditions must be met to trigger `win`:

**First**, the ioctl command must equal `0x539` (1337 decimal):

```asm
78:   cmp    $0x539,%ebx
7e:   jne    b5          ← bail if wrong command
```

**Second**, the password passed as the ioctl `arg` pointer must match the hardcoded string via `strncmp`:

```asm
90:   mov    $0x10,%edx
95:   mov    $0x0,%rsi    ← password in .rodata
9c:   mov    %rsp,%rdi
9f:   call   strncmp
a9:   test   %r8d,%r8d
ac:   jne    b5           ← skip if wrong password
ae:   call   2a <win>     ← escalate to root
```

On success, `win` calls `prepare_kernel_cred(0)` and `commit_creds()` to elevate the calling process to root — same as level3.

We load the module into IDA to inspect the `.rodata` section.

```c title="/challenge/babykernel_level4.0.ko :: .rodata"
.rodata.str1.1:0000000000000F95 ; const char s2[]
.rodata.str1.1:0000000000000F95 s2              db 'hacvtgrjhlscihpk',0 ; DATA XREF: device_ioctl+50↑o
.rodata.str1.1:0000000000000FA6 aPwncollege     db 'pwncollege',0       ; DATA XREF: init_module+E↑o
```

The password is `hacvtgrjhlscihpk`.

### Exploit

In another terminal craft the `~/exploit.c` file, and compile it. The key change from level3 is using `ioctl` instead of `write`, passing `0x539` as the command and the password string as the third argument.

```c title="~/exploit.c" showLineNumbers
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    ioctl(fd, 0x539, "hacvtgrjhlscihpk");
    close(fd);

    // We are now root
    execl("/bin/sh", "sh", NULL);
    return 0;
}
```

```
hacker@kernel-security~level4-0:~$ gcc -o exploit exploit.c
```

Back in the VM terminal, execute the `~/exploit` binary.

```
hacker@vm_kernel-security~level4-0:~$ ./exploit
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /flag
pwn.college{kPl_5X0Mum6lVH5wMj9FpR8GEt_.0VOyQDL4ITM0EzW}
```

The `ioctl` call passes the command check (`0x539`) and the `strncmp` check against `hacvtgrjhlscihpk`. On success `device_ioctl` calls `win`, which calls `prepare_kernel_cred(0)` and `commit_creds()` to escalate the process to root. We then spawn a shell and read `/flag`.

&nbsp;

## level4.1

> Ease into kernel exploitation with another crackme level and learn how kernel devices communicate.

We have to first start and connect to the custom VM.

```
hacker@kernel-security~level4-1:~$ vm start
hacker@kernel-security~level4-1:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
hacker@vm_kernel-security~level4-1:~$
```

### Binary analysis

We start by disassembling the kernel module.

```text
hacker@vm_kernel-security~level4-1:~$ objdump -d /challenge/babykernel_level4.1.ko | tail -200

# ---- snip ----

0000000000000bf0 <device_ioctl>:
 bf0:   55                      push   %rbp
 bf1:   48 83 ec 18             sub    $0x18,%rsp
 bf5:   65 48 8b 04 25 28 00    mov    %gs:0x28,%rax
 bfc:   00 00
 bfe:   48 89 44 24 10          mov    %rax,0x10(%rsp)
 c03:   31 c0                   xor    %eax,%eax
 c05:   81 fe 39 05 00 00       cmp    $0x539,%esi
 c0b:   75 49                   jne    c56 <device_ioctl+0x66>
 c0d:   48 89 e5                mov    %rsp,%rbp
 c10:   48 89 d6                mov    %rdx,%rsi
 c13:   ba 10 00 00 00          mov    $0x10,%edx
 c18:   48 89 ef                mov    %rbp,%rdi
 c1b:   e8 00 00 00 00          call   c20 <device_ioctl+0x30>
 c20:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 c27:   b9 10 00 00 00          mov    $0x10,%ecx
 c2c:   48 89 ee                mov    %rbp,%rsi
 c2f:   f3 a6                   repz cmpsb %es:(%rdi),%ds:(%rsi)
 c31:   0f 97 c0                seta   %al
 c34:   1c 00                   sbb    $0x0,%al
 c36:   84 c0                   test   %al,%al
 c38:   0f 84 00 00 00 00       je     c3e <device_ioctl+0x4e>
 c3e:   31 c0                   xor    %eax,%eax
 c40:   48 8b 4c 24 10          mov    0x10(%rsp),%rcx
 c45:   65 48 33 0c 25 28 00    xor    %gs:0x28,%rcx
 c4c:   00 00
 c4e:   75 0f                   jne    c5f <device_ioctl+0x6f>
 c50:   48 83 c4 18             add    $0x18,%rsp
 c54:   5d                      pop    %rbp
 c55:   c3                      ret
 c56:   48 c7 c0 ff ff ff ff    mov    $0xffffffffffffffff,%rax
 c5d:   eb e1                   jmp    c40 <device_ioctl+0x50>
 c5f:   e8 00 00 00 00          call   c64 <device_ioctl+0x74>
 c64:   66 66 2e 0f 1f 84 00    data16 cs nopw 0x0(%rax,%rax,1)
 c6b:   00 00 00 00
 c6f:   90                      nop

0000000000000c70 <init_module>:
 c70:   48 c7 c1 00 00 00 00    mov    $0x0,%rcx
 c77:   31 d2                   xor    %edx,%edx
 c79:   be b6 01 00 00          mov    $0x1b6,%esi
 c7e:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 c85:   e8 00 00 00 00          call   c8a <init_module+0x1a>
 c8a:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 c91:   48 89 05 00 00 00 00    mov    %rax,0x0(%rip)        # c98 <init_module+0x28>
 c98:   e8 00 00 00 00          call   c9d <init_module+0x2d>
 c9d:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 ca4:   e8 00 00 00 00          call   ca9 <init_module+0x39>
 ca9:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 cb0:   e8 00 00 00 00          call   cb5 <init_module+0x45>
 cb5:   31 c0                   xor    %eax,%eax
 cb7:   c3                      ret
 cb8:   0f 1f 84 00 00 00 00    nopl   0x0(%rax,%rax,1)
 cbf:   00

0000000000000cc0 <cleanup_module>:
 cc0:   48 8b 3d 00 00 00 00    mov    0x0(%rip),%rdi        # cc7 <cleanup_module+0x7>
 cc7:   48 85 ff                test   %rdi,%rdi
 cca:   74 05                   je     cd1 <cleanup_module+0x11>
 ccc:   e9 00 00 00 00          jmp    cd1 <cleanup_module+0x11>
 cd1:   c3                      ret

Disassembly of section .text.unlikely:

0000000000000000 <win>:
   0:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
   7:   e8 00 00 00 00          call   c <win+0xc>
   c:   31 ff                   xor    %edi,%edi
   e:   e8 00 00 00 00          call   13 <win+0x13>
  13:   48 89 c7                mov    %rax,%rdi
  16:   e9 00 00 00 00          jmp    1b <device_ioctl.cold>

000000000000001b <device_ioctl.cold>:
  1b:   e8 e0 ff ff ff          call   0 <win>
  20:   31 c0                   xor    %eax,%eax
  22:   e9 00 00 00 00          jmp    27 <bin_padding+0x7>
```

The structure is identical to level4.0 — same `device_ioctl` handler with the same two checks. The only difference is `win` is now in `.text.unlikely` as a cold function. We load the module into IDA to inspect the `.rodata` section and find the password.

```c title="/challenge/babykernel_level4.1.ko :: .rodata"
.rodata.str1.1:0000000000000D69 aSrungttywgwxmr db 'srungttywgwxmrht',0 ; DATA XREF: device_ioctl+30↑o
.rodata.str1.1:0000000000000D7A aPwncollege     db 'pwncollege',0       ; DATA XREF: init_module+E↑o
```

We also see in `.rodata.str1.8`:

```c
.rodata.str1.8:0000000000000D00 unk_D00  db  1   ; DATA XREF: win↑o
; "You win! Your current process has been elevated to root!"
```

The password is `srungttywgwxmrht`.

### Exploit

In another terminal craft the `~/exploit.c` file, and compile it.

```c title="~/exploit.c" showLineNumbers
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    ioctl(fd, 0x539, "srungttywgwxmrht");
    close(fd);

    // We are now root
    execl("/bin/sh", "sh", NULL);
    return 0;
}
```

```
hacker@kernel-security~level4-1:~$ gcc -o exploit exploit.c
```

Back in the VM terminal, execute the `~/exploit` binary.

```
hacker@vm_kernel-security~level4-1:~$ ./exploit
# cat /flag
pwn.college{AbzNYx21kQFWjBS4IOPbo5bMUtR.0FMzQDL4ITM0EzW}
```

The `ioctl` call passes the command check (`0x539`) and the `strncmp` check against `srungttywgwxmrht`. On success `device_ioctl` calls `win`, which calls `prepare_kernel_cred(0)` and `commit_creds()` to escalate the process to root. We then spawn a shell and read `/flag`.

&nbsp;

Looking at `device_ioctl`, this level removes the password check entirely — the only requirement is the correct ioctl command:

```asm
49:   cmp    $0x539,%ebp
4f:   jne    58          ← bail if wrong command
51:   call   56 <win>    ← escalate to root immediately
```

No `strncmp`, no password. Just `ioctl(fd, 0x539, anything)` and `win` is called.

## level5.0

We have to first start and connect to the custom VM.

```
hacker@kernel-security~level5-0:~$ vm start
hacker@kernel-security~level5-0:~$ vm connect
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
hacker@vm_kernel-security~level5-0:~$
```

### Binary analysis

We start by disassembling the kernel module.

```text
hacker@vm_kernel-security~level5-0:~$ objdump -d /challenge/babykernel_level5.0.ko | tail -200
 342:   90                      nop
 343:   90                      nop
 344:   90                      nop
 345:   90                      nop
 346:   90                      nop
 347:   90                      nop
 348:   90                      nop
 349:   90                      nop
 34a:   90                      nop
 34b:   90                      nop
 34c:   90                      nop
 34d:   90                      nop
 34e:   90                      nop
 34f:   90                      nop
 350:   90                      nop
 351:   90                      nop
 352:   90                      nop
 353:   90                      nop
 354:   90                      nop
 355:   90                      nop
 356:   90                      nop
 357:   90                      nop
 358:   90                      nop
 359:   90                      nop
 35a:   90                      nop
 35b:   90                      nop
 35c:   90                      nop
 35d:   90                      nop
 35e:   90                      nop
 35f:   90                      nop
 360:   90                      nop
 361:   90                      nop
 362:   90                      nop
 363:   90                      nop
 364:   90                      nop
 365:   90                      nop
 366:   90                      nop
 367:   90                      nop
 368:   90                      nop
 369:   90                      nop
 36a:   90                      nop
 36b:   90                      nop
 36c:   90                      nop
 36d:   90                      nop
 36e:   90                      nop
 36f:   90                      nop
 370:   90                      nop
 371:   90                      nop
 372:   90                      nop
 373:   90                      nop
 374:   90                      nop
 375:   90                      nop
 376:   90                      nop
 377:   90                      nop
 378:   90                      nop
 379:   90                      nop
 37a:   90                      nop
 37b:   90                      nop
 37c:   90                      nop
 37d:   90                      nop
 37e:   90                      nop
 37f:   90                      nop
 380:   90                      nop
 381:   90                      nop
 382:   90                      nop
 383:   90                      nop
 384:   90                      nop
 385:   90                      nop
 386:   90                      nop
 387:   90                      nop
 388:   90                      nop
 389:   90                      nop
 38a:   90                      nop
 38b:   90                      nop
 38c:   90                      nop
 38d:   90                      nop
 38e:   90                      nop
 38f:   90                      nop
 390:   90                      nop
 391:   90                      nop
 392:   90                      nop
 393:   90                      nop
 394:   90                      nop
 395:   90                      nop
 396:   90                      nop
 397:   90                      nop
 398:   90                      nop
 399:   90                      nop
 39a:   90                      nop
 39b:   90                      nop
 39c:   90                      nop
 39d:   90                      nop
 39e:   90                      nop
 39f:   90                      nop
 3a0:   90                      nop
 3a1:   90                      nop
 3a2:   90                      nop
 3a3:   90                      nop
 3a4:   90                      nop
 3a5:   90                      nop
 3a6:   90                      nop
 3a7:   90                      nop
 3a8:   90                      nop
 3a9:   90                      nop
 3aa:   90                      nop
 3ab:   90                      nop
 3ac:   90                      nop
 3ad:   90                      nop
 3ae:   90                      nop
 3af:   90                      nop
 3b0:   90                      nop
 3b1:   90                      nop
 3b2:   90                      nop
 3b3:   90                      nop
 3b4:   c3                      ret
 3b5:   66 66 2e 0f 1f 84 00    data16 cs nopw 0x0(%rax,%rax,1)
 3bc:   00 00 00 00

00000000000003c0 <init_module>:
 3c0:   48 c7 c1 00 00 00 00    mov    $0x0,%rcx
 3c7:   31 d2                   xor    %edx,%edx
 3c9:   be b6 01 00 00          mov    $0x1b6,%esi
 3ce:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 3d5:   e8 00 00 00 00          call   3da <init_module+0x1a>
 3da:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 3e1:   48 89 05 00 00 00 00    mov    %rax,0x0(%rip)        # 3e8 <init_module+0x28>
 3e8:   e8 00 00 00 00          call   3ed <init_module+0x2d>
 3ed:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 3f4:   e8 00 00 00 00          call   3f9 <init_module+0x39>
 3f9:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 400:   e8 00 00 00 00          call   405 <init_module+0x45>
 405:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 40c:   e8 00 00 00 00          call   411 <init_module+0x51>
 411:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 418:   e8 00 00 00 00          call   41d <init_module+0x5d>
 41d:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 424:   e8 00 00 00 00          call   429 <init_module+0x69>
 429:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 430:   e8 00 00 00 00          call   435 <init_module+0x75>
 435:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 43c:   e8 00 00 00 00          call   441 <init_module+0x81>
 441:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 448:   e8 00 00 00 00          call   44d <init_module+0x8d>
 44d:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
 454:   e8 00 00 00 00          call   459 <init_module+0x99>
 459:   31 c0                   xor    %eax,%eax
 45b:   c3                      ret
 45c:   0f 1f 40 00             nopl   0x0(%rax)

0000000000000460 <cleanup_module>:
 460:   48 8b 3d 00 00 00 00    mov    0x0(%rip),%rdi        # 467 <cleanup_module+0x7>
 467:   48 85 ff                test   %rdi,%rdi
 46a:   74 05                   je     471 <cleanup_module+0x11>
 46c:   e9 00 00 00 00          jmp    471 <cleanup_module+0x11>
 471:   c3                      ret

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

000000000000002a <device_ioctl>:
  2a:   55                      push   %rbp
  2b:   48 89 d1                mov    %rdx,%rcx
  2e:   89 f5                   mov    %esi,%ebp
  30:   53                      push   %rbx
  31:   48 89 d3                mov    %rdx,%rbx
  34:   89 f2                   mov    %esi,%edx
  36:   48 89 fe                mov    %rdi,%rsi
  39:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  40:   e8 00 00 00 00          call   45 <device_ioctl+0x1b>
  45:   48 83 c8 ff             or     $0xffffffffffffffff,%rax
  49:   81 fd 39 05 00 00       cmp    $0x539,%ebp
  4f:   75 07                   jne    58 <device_ioctl+0x2e>
  51:   e8 00 00 00 00          call   56 <device_ioctl+0x2c>
  56:   31 c0                   xor    %eax,%eax
  58:   5b                      pop    %rbx
  59:   5d                      pop    %rbp
  5a:   c3                      ret

000000000000005b <win>:
  5b:   48 c7 c7 00 00 00 00    mov    $0x0,%rdi
  62:   e8 00 00 00 00          call   67 <win+0xc>
  67:   31 ff                   xor    %edi,%edi
  69:   e8 00 00 00 00          call   6e <win+0x13>
  6e:   48 89 c7                mov    %rax,%rdi
  71:   e9 00 00 00 00          jmp    76 <__UNIQUE_ID_depends23+0x6>
```

This level removes the password check entirely. `device_ioctl` now only checks the command number — no `strncmp`, no password copy. Sending `ioctl(fd, 0x539, 0)` is sufficient to call `win` and escalate to root.

```asm
49:   cmp    $0x539,%ebp
4f:   jne    58          ← bail if wrong command
51:   call   win         ← escalate to root immediately
```

### Exploit

In another terminal craft the `~/exploit.c` file, and compile it. Since there is no password check, the third argument to `ioctl` is irrelevant.

```c title="~/exploit.c" showLineNumbers
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

int main() {
    int fd = open("/proc/pwncollege", O_RDWR);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    ioctl(fd, 0x539, 0);
    close(fd);

    // We are now root
    execl("/bin/sh", "sh", NULL);
    return 0;
}
```

```
hacker@kernel-security~level5-0:~$ gcc -o exploit exploit.c
```

Back in the VM terminal, execute the `~/exploit` binary.

```
hacker@vm_kernel-security~level5-0:~$ ./exploit
# cat /flag
pwn.college{<flag>}
```

The `ioctl` call passes the command check (`0x539`). With no password check, `device_ioctl` calls `win` immediately, which calls `prepare_kernel_cred(0)` and `commit_creds()` to escalate the process to root. We then spawn a shell and read `/flag`.

&nbsp;

