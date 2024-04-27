---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 1
---

Let's run the program.
```
sh-4.3$ ./level01
Enter the 3 digit passcode to enter:
```
As we can see we need to enter a 3 digit passcode.

We can disassemble the program using `gdb` to get an idea of how the program performs it's checks.
```
(gdb) disassemble main
Dump of assembler code for function main:
   0x08048080 <+0>:     push   $0x8049128
   0x08048085 <+5>:     call   0x804810f
   0x0804808a <+10>:    call   0x804809f
   0x0804808f <+15>:    cmp    $0x10f,%eax
   0x08048094 <+20>:    je     0x80480dc
   0x0804809a <+26>:    call   0x8048103
End of assembler dump.
```
We can see that the value stored in `$eax` is being compared to `0x10f`.
As this is the only comparison, this  should be our input.

`0x10f` in decimal is 271.
We can provide this value as the passcode and solve the level.
