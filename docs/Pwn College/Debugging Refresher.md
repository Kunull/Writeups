---
custom_edit_url: null
sidebar_position: 4
---

## level 1

> Use the command `continue`, or `c` for short, in order to continue program execution.

Before we do anything else we need to open the file in GDB.

```
$ gdb embryogdb_level1
```

This challenge is fairly simple, we just have to run the file.

```
(gdb) run

; -- snip --
Program received signal SIGTRAP, Trace/breakpoint trap.
0x000055e9b5da2be3 in main ()
```

The program will hit a breakpoint at `0x000055e9b5da2be3` in `main` function.

We can continue the execution and get the flag.

```
(gdb) continue
```

&nbsp;

## level 2

> In order to solve this level, you must figure out the current random value of register r12 in hex.

We can find the value of the `r12` register using the `p` command which is a short from of print.

```
(gdb) p/x $r12
$1 = 0x7ffcf408c27db613
```

The `x` option prints the value in hexadecimal.

Rest of the steps remain the same.

&nbsp;

## level 3

> In order to solve this level, you must figure out the random value on the stack (the value read in from `/dev/urandom`). Think about what the arguments to the read system call are.

The contents of a file can be read using the `read` syscall.

### Read syscall

```c
ssize_t read(int fd, void buf[.count], size_t count);
```

We can see that the second argument is the location of the buffer in which the data is to be read. This argument is loaded in the `rsi` register.

Let's look at how this loaded in our assembly code.

```
(gdb) disassemble main
Dump of assembler code for function main:
-- snip --;
   0x000055ca6a9e5c42 <+412>:   mov    ecx,eax
   0x000055ca6a9e5c44 <+414>:   lea    rax,[rbp-0x18]
   0x000055ca6a9e5c48 <+418>:   mov    edx,0x8
   0x000055ca6a9e5c4d <+423>:   mov    rsi,rax
   0x000055ca6a9e5c50 <+426>:   mov    edi,ecx
   0x000055ca6a9e5c52 <+428>:   call   0x55ca6a9e5210 <read@plt>
-- snip --;
```

If we look at the address `main+423`, we can see that the value of `rsi` is being copied from `rax`.

### lea instruction

The `lea` instruction loads the effective address of the instruction being pointed to.

This value in `rax` is set to `rbp-0x18` as seen in the instruction at `main+414` address.

Now that we know the location of the buffer is `rbp-0x18`, we can now check the data copied there using the `x` command.

```
(gdb) x/gx $rbp-0x18
0x7ffd3a1379a8: 0xc4b0b1fef2602408
```

The format is set to hexadecimal using `x` and the unit size is set to giga word using `g`.

&nbsp;

## level 4

> In order to solve this level, you must figure out a series of random values which will be placed on the stack. You are highly encouraged to try using combinations of `stepi`, `nexti`, `break`, `continue`, and `finish` to make sure you have a good internal understanding of these commands. The commands are all absolutely critical to navigating a program's execution.

The program takes user input and then compares it with a value.

```
The random value has been set!

Random value: 1
You input: 1
The correct answer is: a81d433af1f1ab88
```

In order to correctly provide user input, we need to know what it is being compared with before the comparison even happens.

Let's begin by disassembling the `main` function.

```
(gdb) disassemble main
Dump of assembler code for function main:
---snip---;
   0x00005603fc3b4d10 <+618>:   mov    rdx,QWORD PTR [rbp-0x10]
   0x00005603fc3b4d14 <+622>:   mov    rax,QWORD PTR [rbp-0x18]
   0x0000561c94d1bd18 <+626>:   cmp    rdx,rax
   0x0000561c94d1bd1b <+629>:   je     0x561c94d1bd27 <main+641>
   0x0000561c94d1bd1d <+631>:   mov    edi,0x1
   0x0000561c94d1bd22 <+636>:   call   0x561c94d1b280 <exit@plt>
   0x0000561c94d1bd27 <+641>:   add    DWORD PTR [rbp-0x1c],0x1
---snip---;
```

We can see that the instruction at `main+626` compares the value of the `rax` register with the value of the `rdx` register.

If the values are equal, it skips over the `exit` syscall.

Let's look at the values of these registers.

```
(gdb) p/x $rdx
$1 = 0x1
(gdb) p/x $rax
$2 = 0xce9eccd975bcd430
```

So `rdx` is the register that holds user input and `rax` is the one that holds the value it is to be compared to. We also know that the value in `rax` is copied from `rbp-0x18` by looking at the instruction at `main+622`.

We have to restart the program again.

### Read syscall

We know that the `read` syscall reads data into a buffer pointed to by it's second argument. We also know that this second argument is loaded into the `rsi` register.

```
   0x00005603fc3b4c96 <+496>:   mov    ecx,eax
   0x00005603fc3b4c98 <+498>:   lea    rax,[rbp-0x18]
   0x00005603fc3b4c9c <+502>:   mov    edx,0x8
   0x00005603fc3b4ca1 <+507>:   mov    rsi,rax
   0x00005603fc3b4ca4 <+510>:   mov    edi,ecx
   0x00005603fc3b4ca6 <+512>:   call   0x5603fc3b4210 <read@plt>
   0x00005603fc3b4cab <+517>:   lea    rdi,[rip+0xe26]        # 0x5603fc3b5ad8
```

In this case the buffer is located at `rbp-0x18` as shown by the instruction at `main+498`.

All we have to do now is to set a breakpoint at the instruction after the `read` syscall is made.

```
break *(main+517)
```

Once our program has stopped at the breakpoint, we can check the data that was copied into the buffer.

```
(gdb) x/gx $rbp-0x18
0x7ffea1c2df78: 0x1f00026c7ef5aa7f
```

Next continue the program execution until we are asked for the user input.

```
The random value has been set!

Random value: 0x1f00026c7ef5aa7f
You input: 1f00026c7ef5aa7f
The correct answer is: 1f00026c7ef5aa7f
```

We can see that the check was successfully passed. This process will repeat a couple of times but the method will be the same.

&nbsp;

## level 5

> Use gdb scripting to help you collect the random values.

From the previous level, we already know that the value that our input is being compared to is stored at `rbp-0x18`. This is the location of the `read` syscall's buffer.

```
(gdb) disass main
Dump of assembler code for function main:
---snip---;
   0x00005556d00bdd56 <+688>:   mov    ecx,eax
   0x00005556d00bdd58 <+690>:   lea    rax,[rbp-0x18]
   0x00005556d00bdd5c <+694>:   mov    edx,0x8
   0x00005556d00bdd61 <+699>:   mov    rsi,rax
   0x00005556d00bdd64 <+702>:   mov    edi,ecx
   0x00005556d00bdd66 <+704>:   call   0x5556d00bd210 <read@plt>
   0x00005556d00bdd6b <+709>:   lea    rdi,[rip+0xd46]        # 0x5556d00beab8
---snip---;
```

This time the `read` syscall is made at `main+704`. Therefore in order to check the data that is read we need to set a breakpoint at the next instruction which is at `main+709`.

```
break *(main+709)
```

Next we want to display the current variable.

```
set $currentValue = *(unsigned long long*)($rbp-0x18)
printf "Current value: %llx\n", $currentValue
```

These commands will be executed every time the breakpoint is hit.

We defined a variable `currentValue` and set it's value equal to the local variable `rbp-0x18`.

All we have to do now is put it all together in a script so that we don't have to type it out over and over.

### GDB script

The complete script looks like follows:

```gdb title="script.gdb"
start
break *main+709
commands
    silent
    set $currentValue = *(unsigned long long*)($rbp-0x18)
    printf "Current value: %llx\n", $currentValue
    continue
end
continue
```

The commands will be executed every time the breakpoint is hit.

&nbsp;

## level 7

In this level we are introduced to another way of executing the `win` function.

```
(gdb) call (void)win()
```

&nbsp;

## level 8

This time the `win` function has been broken.

```
(gdb) call (void)win()

Program received signal SIGSEGV, Segmentation fault.
```

So we can no longer use our old technique.

We can check the instruction that is the cause of this segmentation fault.

```
(gdb) x/i $rip
=> 0x564b61ea2969 <win+24>:     mov    eax,DWORD PTR [rax]
```

The dereferenced value of `rax` is being moved to `eax`.

Let us check the value of `rax`.

```
(gdb) x/i $rax
   0x0: Cannot access memory at address 0x0
```

The value of `rax` is `0x0`, and we are not allowed to access that memory location, which causes the program to crash.

```
(gdb) disassemble win

-- snip --;
   0x0000564b61ea295d <+12>:    mov    QWORD PTR [rbp-0x8],0x0
   0x0000564b61ea2965 <+20>:    mov    rax,QWORD PTR [rbp-0x8]
=> 0x0000564b61ea2969 <+24>:    mov    eax,DWORD PTR [rax]
-- snip --;
```

On disassembling `win`, we can see that `0x0` is being stored on the stack, and being moved to `rax`.

Let's set a breakpoint at `win`.

```
(gdb) break *win
```

Let's disassemble `win`.

```
(gdb) disassemble win

---snip---;
   0x0000556ccb267980 <+47>:    mov    esi,0x0
   0x0000556ccb267985 <+52>:    lea    rdi,[rip+0x749]        # 0x556ccb2680d5
   0x0000556ccb26798c <+59>:    mov    eax,0x0
   0x0000556ccb267991 <+64>:    call   0x556ccb267240 <open@plt>
---snip---;
```

This time we have stopped execution before the code-breaking instructions.

There is an `open` syscall at `win+64` which opens the `/flag` file.

```
(gdb) x/s 0x556ccb2680d5
0x556ccb2680d5: "/flag"
```

We can directly jump to the setup.

```
(gdb) jump *(win+47)
```

That gives us the flag.
