---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 3
---

:::note
For this module, `int3` displays the state of the registers, which is helpful in writing the code.
:::

:::note
Use the code snippet provided below and replace the comment with your assembly code.
:::

## Code Snippet

```python
import pwn

pwn.context.update(arch="amd64")
output = pwn.process("/challenge/run")
output.write(pwn.asm("""

# Write your assembly code here

"""))
print(output.readallS())
```

&nbsp;

## level 1

> In this level you will work with registers\_use! Please set the following:\
> &emsp;rdi = 0x1337

We can use the `mov` instruction in order to store a value in a register.

### `mov` instruction

```assembly
mov destination, sourcew
```

The first operand is the location where data is stored, while the second operand is the source of the data.

```assembly title="assembly1.asm"
add rdi, 0x1337
```

&nbsp;

## level 2

> In this level you will work with multiple registers. Please set the following:\
> &emsp;rax = 0x1337\
> &emsp;r12 = 0xCAFED00D1337BEEF\
> &emsp;rsp = 0x31337

We can use the `mov` instruction that we learned in the previous level.

```asm title="assembly2.asm"
mov rax, 0x1337
mov r12, 0xCAFED00D1337BEEF
mov rsp, 0x31337
```

&nbsp;

## level 3

> Do the following:\
> &emsp;add 0x331337 to rdi

We have to use the `add` instruction in order to add a value to a register.

### `add` instruction

```wasm
add destination, source
```

The first operand is the location at which the original data is stored, while the second operand is the source of the data to be added.

### `sub` instruction

```asm
sub destination, source
```

The first operand is the location at which the original data is stored, while the second operand is the source of the data to be subtracted.

```asm title="assembly3.asm"
add rdi, 0x331337
```

&nbsp;

## level 4

> Compute the following:\
> &emsp;f(x) = mx + b, where:\
> &emsp;&emsp;m = rdi\
> &emsp;&emsp;x = rsi\
> &emsp;&emsp;b = rdx
> 
> Place the value into rax given the above.

In order to compute this equation, we need to understand the `mul` instruction.

### `mul` instruction

The first operand is the location at which the original data is stored, while the second operand is the source of the data to be multiplied.

```wasm
mul multiplicand, multiplier
----(rax)      
```

The `mul` instruction is a bit different, i.e. the source of multiplicand is always `rax` by default and we only have control over the source of the multiplier.

So if we want to multiply `rdi` with `rsi`, we would first have to move the value of `rdi` into `rax`.

```wasm
mov rax, rdi
mul rsi
```

After that, we can just add the result of multiplication stored in `rax` with `rdx`.

```asm title="assembly4.asm"
mov rax, rdi
mul rsi
add rax, rdx
```

&nbsp;

## level 5

> Please compute the following:\
> &emsp;speed = distance / time, where:\
> &emsp;&emsp;distance = rdi\
> &emsp;&emsp;time = rsi\
> &emsp;&emsp;speed= rax
> 
> Note that distance will be at most a 64-bit value, so rdx should be 0 when dividing.

In order to compute the equation, we need to understand the `div` instruction.

### `div` instruction

```wasm
div dividend, divisor, quotient, resultant
----(rax)              (rax)     (rdx)
```

Similar to the `mov` instruction, the first operand of `div` is implicitly `rax` by default, i.e. location the dividend and quotient are always `rax`. We only have control over the source of the divisor. The resultant of the `div` instruction is always stored into `rdx` by default.

So if we want to divide `rdi` by `rsi`, we would first have to move the value of `rdi` into `rax`.

```asm title="assembly5.asm"
mov rax, rdi
div rsi
```

&nbsp;

## level 6

> Please compute the following:\
> &emsp; rdi % rsi
> 
> Place the value in rax.

In order to compute this equation, we need to learn something more about the `div` instruction.

```wasm
div destination, source, resultant
----(rax)      , source, (rdx)
```

As we saw before, the destination is `rax` by default, i.e. the quotient is stored in `rax`.

However the quotient isn't the only value generated after performing division, a leftover known as resultant is also generated. This resultant is stored in `rdx` by default.&#x20;

In the case modulus operation, the resultant is what we are interested in.

After performing the division in the same manner as [level 5](#level-5), we have to move the resultant stored in `rdx` into `rax`.

```asm title="assembly6.asm"
mov rax, rdi
div rsi
mov rax, rdx
```

&nbsp;

## level 7

> Using only one move instruction, please set the upper 8 bits of the ax register to 0x42.

### Lower register bytes

```
MSB                                    LSB
+----------------------------------------+
|                   rax                  |  64 bit
+--------------------+-------------------+
                     |        eax        |  32 bit
                     +---------+---------+
                               |   ax    |  16 bit
                               +----+----+
                               | ah | al |  8 bit each
                               +----+----+
```

In order to set the upper 8 bits of the `ax` register, we can access the `ah` register.

```asm title="assembly7.asm"
mov ah, 0x42
```

&nbsp;

## level 8

> Using only the following instruction(s):\
> &emsp;mov
> 
> Please compute the following:\
> &emsp;rax = rdi % 256\
> &emsp;rbx = rsi % 65536

In order to solve this level, we need to understand how the modulo operation translates to bits.

### Modulo operation in bits

When any binary number is modulo with `256`, the answer is the last 8 bits of the number. Similarly, when any binary number is modulo with `65536`, the answer is the last 64 bits if the number.

The diagram provided helps in understanding this concept better.

```
MSB                                    LSB
+----------------------------------------+
|                   rax                  |  64 bit
+--------------------+-------------------+
                     |        eax        |  32 bit
                     +---------+---------+
                               |   ax    |  16 bit
                               +----+----+
                               | ah | al |  8 bit each
                               +----+----+
```

The answer of `rdi modulo 256` can be obtained by simply accessing the 8-bit equivalent register of `rdi`, which is `dil`. And the answer of `rsi modulo 65536` can be obtained by accessing the 16-bit equivalent register of `rsi`, which is `si`.

```wasm
mov al, dil
mov bx, si
```

```asm title="assembly8.asm"
mov rax, 0
mov rbx, 0
mov al, dil
mov bx, si
```

&nbsp;

## level 9

> Please perform the following:\
> &emsp;Set rax to the 5th least significant byte of rdi;
>
> For example:\
> &emsp;rdi = | B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0 |\
> &emsp;Set rax to the value of B4

For this level, we need to understand the bit shifting.

### Bit shifting

It can be performed using the `shl` and `shr` instructions.

Both the instructions take two operands, the first being the register and the second being the number of bits to be shifted. Only difference is that `shl` shifts the bits to the left while `shr` shifts the bits to the right.

Let's understand using the `rdi` register.

```
+---------------------------------------+
| B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0 |
+---------------------------------------+
shl rdi, 24
+---------------------------------------+
| B4 | B3 | B2 | B1 | B0 | 0  | 0  | 0  |
+---------------------------------------+
shr rdi, 56
+---------------------------------------+
| 0  | 0  | 0  | 0  | 0  | 0  | 0  | B4 |
+---------------------------------------+
```

As we can see, on performing `shr`, the equivalent number of bits from the LSB are replaced zeroes whereas on performing `shl`, the equivalent number of bits from the MSB are replaced with zeroes.

Next, we simply have to move the value into `rax`.

```asm title="assembly9.asm"
shl rdi, 24
shr rdi, 56
mov rax, rdi
```

&nbsp;

## level 10

> Without using the following instructions:\
> &emsp;mov, xchg
>
> Please perform the following:\
> &emsp;rax = rdi AND rsi
>
> i.e. Set rax to the value of (rdi AND rsi)

In order to perform the AND operation between `rdi` and `rsi`, we need to use the `and` instruction. It is fairly straightforward and can be understood using the table provided.

### AND

| A | B | X |
|:-:|:-:|:-:|
| 0 | 0 | 0 |
| 0 | 1 | 0 |
| 1 | 0 | 0 |
| 1 | 1 | 1 |

```
    AND       
 A | B | X 
---+---+--- 
 0 | 0 | 0   
 0 | 1 | 0   
 1 | 0 | 0 
 1 | 1 | 1 
```

The next part is a bit tricky, we need to move the answer into `rax` without using `mov` or `xchg`.

Before we do anything else, we need to make sure that `rax` is empty. This can be done using `xor`.

### XOR

| A | B | X |
|:-:|:-:|:-:|
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

```
    XOR
 A | B | X
---+---+---
 0 | 0 | 0  ##
 0 | 1 | 1
 1 | 0 | 1
 1 | 1 | 0  ##
```

If we observe the table, we can see that the XOR of the same bits is always equal to zero. This means that if we XOR `rax` with itself, we can essentially set it to zero.

```wasm
xor rax, rax
```

In order to move the value of `rdi` into `rax`, we can use the `or` instruction.

### OR

| A | B | X |
|:-:|:-:|:-:|
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 | 
| 1 | 1 | 1 |

```
    OR    
 A | B | X  
---+---+--- 
 0 | 0 | 0  ##
 0 | 1 | 1  
 1 | 0 | 1  ## 
 1 | 1 | 1  
```

Looking at the table, we can see that OR of zero with any bit is equal to the bit. So if we OR `rax` which we already zeroed out, with `rdi`, the resultant will be the value of `rdi` stored in `rax`.

```wasm
or rax, rdi
```

```asm title="assembly10.asm"
and rdi, rsi
xor rax, rax
or rax, rdi
```

&nbsp;

## level 11

> Using only the following instructions:\
> &emsp;and, or, xor\
> 
> Implement the following logic:\
> &emsp;if x is even then\
> &emsp;&emsp;y = 1\
> &emsp;else\
> &emsp;&emsp;y = 0
> 	
> where:\
> &emsp;x = rdi\
> &emsp;y = rax

In order to check whether an number is even or odd we can AND it with 1.

### AND with 1

| A | B | X |
| :-: | :-: | :-: |
| 0 | 1 | 0 |
| 1 | 1 | 1 |

```
    AND       
 A | B | X 
---+---+--- 
 0 | 1 | 0  
 1 | 1 | 1  
```

We can see that that AND with 1 simply ensures the value and outputs it.

So if we want to check if the value of `rdi` is even or odd, we have to AND it with 1.

```
and rdi, 1
```

Now if `rdi` is even, the value of `rax` should be 1 and if `rdi` is odd, the value of `rax` should be 0.

In order to achieve this result, we need to first XOR `rdi` with 1.

### XOR with 1

| A | B | X |
| :-: | :-: | :-: |
| 0 | 1 | 1 |
| 1 | 1 | 0 |

```
    XOR
 A | B | X
---+---+---
 0 | 1 | 1 
 1 | 1 | 0 
```

If `rdi` is even, the result will be 1 whereas if `rdi` is odd, the result will be 0.

```
xor rdi, 1
```

Then we simply have to zero out `rax` and set it's value equal to the value of `rdx` using the same methods as [level 10](#level-10).

```asm title="assembly11.asm"
and rdi, 1
xor rdi, 1
xor rax, rax
or rax, rdi
```

&nbsp;

## level 12

> Please perform the following:\
> &emsp;Place the value stored at 0x404000 into rax
> 
> Make sure the value in rax is the original value stored at 0x404000.

### Dereferencing

When we use a `mov` instruction with a regular source operand, the value of source is moved into the destination.

```wasm
mov destination, source
----rax        , 0x404000
```

The value of register `rax` is set to `0x404000`.

However, if we put the source operand into square parenthesis, the value of source operand is treated as a pointer to an address. Thus the source operand is dereferenced.

```wasm
mov destination, [source]
----rax        , [0x404000]
```

The value of register `rax` is set to the value at address `0x404000`.

```asm title="assembly12.asm"
mov rax, [0x404000]
```

&nbsp;

## level 13

> Please perform the following:\
> &emsp;Place the value stored in rax to 0x404000

```asm title="assembly13.asm"
mov [0x404000], rax
```

&nbsp;

## level 14

> Please perform the following:\
> &emsp;Place the value stored at 0x404000 into rax\
> &emsp;Increment the value stored at the address 0x404000 by 0x1337
>
> Make sure the value in rax is the original value stored at 0x404000 and make sure that [0x404000] now has the incremented value.

```asm title="assembly14.asm"
mov rax, [0x404000]
mov rbx, [0x404000]
add rbx, 0x1337
mov [0x404000], rbx
```

&nbsp;

## level 15

> Please perform the following:\
> &emsp;Set rax to the byte at 0x404000

In order to solve this level, we need to learn about lower bit equivalent register.

```
* Quad Word = 8 Bytes = 64 bits
* Double Word = 4 bytes = 32 bits
* Word = 2 bytes = 16 bits
* Byte = 1 byte = 8 bits
```

Now we simply have to use the relevant lower bit registers.

### Lower bit equivalent registers

```
+--------------+--------------+--------------+--------------+
|    64 bit    |    32 bit    |    16 bit    |    8 bit     |
|    (qword)   |    (dword)   |    (word)    |    (byte)    |
+--------------+--------------+--------------+--------------+
|     rax      |     eax      |     ax       |    *al*      |
|     rbx      |     ebx      |     bx       |     bl       |
|     rcx      |     ecx      |     cx       |     cl       |
|     rdx      |     edx      |     dx       |     dl       |
+--------------+--------------+--------------+--------------+
```

The register with the stars are the one we have to use along with derefencing.

```asm title="assembly15.asm"
mov al, [0x404000]
```

There is one more method, to solve this level. Instead of using lower bit equivalent registers, we can use type specifiers in order to indicate data to be loaded.

### Type specifiers

There are four different specifiers for each of the four memory size names.

```
Quad word:    qword ptr
Double word:    dword ptr
Word:    word ptr
Byte:    byte ptr
```

```python title="assembly15.asm"
mov rax, byte ptr [0x404000]
```

&nbsp;

## level 16

> Please perform the following:\
> &emsp;Set rax to the byte at 0x404000\
> &emsp;Set rbx to the word at 0x404000\
> &emsp;Set rcx to the double word at 0x404000\
> &emsp;Set rdx to the quad word at 0x404000

We can solve this level using the lower bit equivalent registers mentioned in [level 15](#level-15). In that case, we can would need to know how many bits is referred to by which term.

```
* Quad Word = 8 Bytes = 64 bits
* Double Word = 4 bytes = 32 bits
* Word = 2 bytes = 16 bits
* Byte = 1 byte = 8 bits
```

Now we simply have to use the relevant lower bit registers.

### Lower bit equivalent registers

```
+--------------+--------------+--------------+--------------+
|    64 bit    |    32 bit    |    16 bit    |    8 bit     |
|    (qword)   |    (dword)   |    (word)    |    (byte)    |
+--------------+--------------+--------------+--------------+
|     rax      |     eax      |     ax       |    *al*      |
|     rbx      |     ebx      |    *bx*      |     bl       |
|     rcx      |    *ecx*     |     cx       |     cl       |
|    *rdx*     |     edx      |     dx       |     dl       |
+--------------+--------------+--------------+--------------+
```

The register with the stars are the one we have to use along with derefencing.

```asm title="assembly16.asm"
mov al, [0x404000]
mov bx, [0x404000]
mov ecx, [0x404000]
mov rdx, [0x404000]
```

There is one more method, to solve this level. Instead of using lower bit equivalent registers, we can use type specifiers in order to indicate data to be loaded.

### Type specifiers

There are four different specifiers for each of the four memory size names.

```
Quad word:    qword ptr
Double word:    dword ptr
Word:    word ptr
Byte:    byte ptr
```

```asm title="assembly16.asm"
mov al, byte ptr [0x404000]
mov bx, word ptr [0x404000]
mov ecx, dword ptr [0x404000]
mov rdx, qword ptr [0x404000]
```

&nbsp;

## level 17

> Using the earlier mentioned info, perform the following:\
> &emsp;Set \[rdi] = 0xdeadbeef00001337\
> &emsp;Set \[rsi] = 0xc0ffee0000

### Limitation of Intel syntax

Intel syntax does not allow the user to move 64-bit value directly into memory.

```
mov [address], 0xdeadbeef00001337    # Not allowed
```

Therefore, we have to move the data value as well as the address into a register first, and then move the register's content into the dereferenced memory address.

```
mov rdi, address
mov rax, 0xdeadbeef00001337
mov [rdi], rax
```

We have to do this with the other data as well.

```
mov rsi, address
mov rax, 0xc0ffee0000
mov [rsi], rax
```

```asm title="assembly17.asm"
mov rax, 0xdeadbeef00001337
mov [rdi], rax
mov rax, 0xc0ffee0000
mov [rsi], rax
```

&nbsp;

## level 18

> Perform the following:\
> &emsp;Load two consecutive quad words from the address stored in rdi\
> &emsp;Calculate the sum of the previous steps quad words.\
> &emsp;Store the sum at the address in rsi

In order to solve this level we have understand the use offsets and little endian format.

Let's say the address of `0x1337` is stored with `0x00000000deadbeef`.

```wasm
[0x1337] = 0x00000000deadbeef
```

The address `0x1337` is in fact a byte address. i.e. it can only store one byte from our entire data.

### Big endian

```
+--------+--------+--------+--------+--------+--------+--------+--------+
| 0x1337 | 0x1338 | 0x1339 | 0x1340 | 0x1341 | 0x1342 | 0x1343 | 0x1344 |
+--------+--------+--------+--------+--------+--------+--------+--------+
|   00   |   00   |   00   |   00   |   de   |   ad   |   be   |   af   |
+--------+--------+--------+--------+--------+--------+--------+--------+
```

The LSB is stored in the high memory address (`0x1344`) while the MSB is stored in the low memory address (`0x1337`).

This is the format in which humans write numbers. Network traffic is also sent in big endian format.

### Little endian

```
+--------+--------+--------+--------+--------+--------+--------+--------+
| 0x1337 | 0x1338 | 0x1339 | 0x1340 | 0x1341 | 0x1342 | 0x1343 | 0x1344 |
+--------+--------+--------+--------+--------+--------+--------+--------+
|   ef   |   be   |   ad   |   de   |   00   |   00   |   00   |   00   |
+--------+--------+--------+--------+--------+--------+--------+--------+
```

The LSB is stored in the low memory address (`0x1337`) while the MSB is stored in the high memory address (`0x1344`).

This is the format in which machines store data. This is the relevant format for our level.

### Offset

```
[0x1337] ----> 0xef
[0x1337 + 1] ----> 0xbe
[0x1337 + 2] ----> 0xad
```

We can see using the offset we can access memory stored at a relative offset.

Next, we simply have to combine these concepts to store the first and second QWORD from `[rdi]` separately.

```wasm
mov rax, qword ptr [rdi]
mov rbx, qword ptr [rdi + 8]
```

```asm title="assembly18.asm"
mov rax, qword ptr [rdi]
mov rbx, qword ptr [rdi + 8]
add rax, rbx
mov [rsi], rax
```

&nbsp;

## level 19

> Take the top value of the stack, subtract rdi from it, then put it back.

For this level we have to learn about the stack, which is a region in memory.

### Stack

The stack is a dynamic memory region which grows and shrinks as data is written and read from it. It grows from higher memory address to lower memory address.

It is a LIFO data structure. Data that goes in last comes out first and vice versa.

```
        +-------------------------+
0x50    |        aaaaaaaa         | <------ rbp 
        +-------------------------+                                                       
0x48    |        bbbbbbbb         | 
        +-------------------------+                                                           
0x40    |        cccccccc         | 
        +-------------------------+
0x38    |        dddddddd         | <------ rsp  
        +-------------------------+
```

The stack has two pointers:

### Stack pointer

It points to the last byte of data copied to the stack, i.e. the lowest memory address.

The value of the stack pointer is stored in the `rsp` register.

### Base pointer

It points to the base of the stack, i.e. the highest memory address.

The value of the stack pointer is stored in the `rbp` register.

We have to pop the top of our stack into a register before replacing it.

### Pop instruction

The `pop` instruction is used to write data on the stack.

```wasm
pop destination
```

It copies data from the stack and then increments the stack pointer `rsp` by 8. We only have to specify the destination.

```
pop rax    # Moves the data bointed to by rsp into rax and increments rsp by 8
===============================================================================
        +-------------------------+
0x50    |        aaaaaaaa         | <------ rbp 
        +-------------------------+                                                       
0x48    |        bbbbbbbb         | 
        +-------------------------+                                                           
0x40    |        cccccccc         | <------ rsp 
        +-------------------------+
0x38    |        dddddddd         | 
        +-------------------------+
```

Note that the value previous on the top of the stack is not erased. It will be replaced when the next `push` operation is performed.

We can now perform our subtraction using the `sub` instruction.

```wasm
sub rax, rdi
```

Only step remaining is to push the result of the subtraction into the location held by the original value, thus replacing it.

### Push instruction

The `push` instruction is used to write data on the stack.

```wasm
push source
```

It decrements the stack pointer `rsp` by 8 and copies data onto the stack. We only have to specify the source.

```
mov rax, eeeeeeee
push rax    # Decrements rsp by 8 and moves data in rax to the address pointed to by rsp
=========================================================================================
        +-------------------------+
0x50    |        aaaaaaaa         | <------ rbp 
        +-------------------------+                                                       
0x48    |        bbbbbbbb         | 
        +-------------------------+                                                           
0x40    |        cccccccc         | 
        +-------------------------+
0x38    |        eeeeeeee         | <------ rsp  
        +-------------------------+
```

```asm title="assembly19.asm"
pop rax
sub rax, rdi
push rax
```

&nbsp;

## level 20

> Using only following instructions:\
> &emsp;push, pop
>
> Swap values in rdi and rsi.\
> i.e.\
> If to start rdi = 2 and rsi = 5\
> Then to end rdi = 5 and rsi = 2

This level can be easily completed using the `push` and `pop` instructions.

```wasm
push rdi 
push rsi
```

These two instructions push the contents of `rdi` and `rsi` onto the stack.

When we pop data from the stack the data that was copied last pops out first due to it's LIFO behavior.

```wasm
pop rdi
pop rsi
```

So the content of `rsi` will be popped first which we will store in our `rdi` register and then we will use the `rsi` register to store the content of `rdi` which will be popped next.

```asm title="assembly20.asm"
push rdi
push rsi
pop rdi
pop rsi
```

&nbsp;

## level 21

> Without using pop, please calculate the average of 4 consecutive quad words stored on the stack.
>
> Push the average on the top of the stack.
>
> Hint:\
> &emsp;RSP+0x?? Quad Word A\
> &emsp;RSP+0x?? Quad Word B\
> &emsp;RSP+0x?? Quad Word C\
> &emsp;RSP Quad Word D

In [level 19](#level-19), we saw that the stack pointer `rsp` points to the bottom of the stack. And that this location stores 8 bytes of data which is also called a quad word.

We also saw that every other quad word sits at an offset from `rsp` which is the multiple of 8.

```
            +-------------------------+
RSP+0x18    |       Quad Word A       | <------ rbp 
            +-------------------------+                                                       
RSP+0x10    |       Quad Word B       | 
            +-------------------------+                                                           
RSP+0x08    |       Quad Word C       |
            +-------------------------+
RSP         |       Quad Word D       | <------ rsp  
            +-------------------------+
```

Using that information we found out the relative offset of all the quad words from `rsp`.

We can move the data pointed to by the stack pointer using the `mov` instruction, and then add up all the quad words.

```wasm
mov rax, [rsp]
add rax, [rsp + 8]
add rax, [rsp + 16]
add rax, [rsp + 24]
```

Now that we have the sum of all the quad words in `rax`, we can simply divide it by 4 using the `div` instruction in order to get the average.

However there is another more interesting method of dividing a number.

### Division using `shr`

We know that every bit in a byte is two to the power of some number.

```
+---------------------------------------------------------------+
|   1   |   0   |   0   |   0   |   0   |   0   |   0   |   0   |
| (2^7) | (2^6) | (2^5) | (2^4) | (2^3) | (2^2) | (2^1) | (2^0) |
+---------------------------------------------------------------+
```

The value of the byte above is 1x(2^7) which is equal to 128.

If we shift right 2 bits, we get the following result.

```
+---------------------------------------------------------------+
|   0   |   0   |   1   |   0   |   0   |   0   |   0   |   0   |
| (2^7) | (2^6) | (2^5) | (2^4) | (2^3) | (2^2) | (2^1) | (2^0) |
+---------------------------------------------------------------+
```

The value of the byte now is 1x(2^5) which is 32. So we essentially divided the number by 4 without using the `div` instruction.

Now we simply have to do the same thing with the sum stored in `rax` to find the average.

```wasm
shr rax, 2
```

Next we have to copy the average onto the stack using the `push` instruction.

```wasm
push rax
```

The stack would look something like this:

```
            +-------------------------+
RSP+0x20    |       Quad Word A       | <------ rbp 
            +-------------------------+                                                       
RSP+0x18    |       Quad Word B       | 
            +-------------------------+                                                           
RSP+0x10    |       Quad Word C       |
            +-------------------------+
RSP+0x08    |       Quad Word D       |
            +-------------------------+
RSP         |         Average         | <------ rsp  
            +-------------------------+
```

```asm title="assembly21.asm"
mov rax, [rsp]
add rax, [rsp + 8]
add rax, [rsp + 16]
add rax, [rsp + 24]
shr rax, 2
push rax
```

&nbsp;

## level 22

> Perform the following:\
> &emsp;Jump to the absolute address 0x403000

### Absolute jump

In order to perform an absolute jump, we have to specify the address to jump to instead of a label.

```
jmp 0x10
.
.
.
0x10
code
```

The problem with this is that it we cannot directly mention the address because of endianness. There are two methods of fixing this problem.

We can first copy the address in a register and then provide the register as the operand.

```asm title="assembly22.asm"
mov rax, 0x403000
jmp rax
```

For the second method we have to understand the how the `ret` instruction works in tandem with the instruction pointer.

### Instruction pointer

The instruction pointer is a register that holds the address of the instruction to be executed next, thus pointing to it.

```
            0x00    Instruction 1    ##
            0x01    Instruction 2    ## Already executed
            0x02    Instruction 3    ##
rip ------> 0x03    Instruction 4    $$ To be executed
```

In the above example, the `rip` will have the value `0x03` which is the address of `Instruction 4`.

### `ret` instruction

When we use the `ret` instruction, it pops the latest value on the stack into the instruction pointer `rip`.

```
            +------------------+
RSP+0x18    |       0x00       | <------ rbp 
            +------------------+                                                       
RSP+0x10    |       0x01       | 
            +------------------+                                                           
RSP+0x08    |       0x02       |
            +------------------+
RSP         |       0x03       | <------ rsp  
            +------------------+
=============================================
ret
=============================================
            +------------------+
RSP+0x10    |       0x00       | <------ rbp 
            +------------------+                                                       
RSP+0x08    |       0x01       | 
            +------------------+                                                           
RSP         |       0x02       | <------ rsp
            +------------------+
```

In the above example, the value of `rip` will be set to `0x03` and the instruction at address `0x03` will be executed next.

For our challenge we have to push the value on the stack and then use the `ret` instruction.

```asm title="assembly.asm"
push 0x403000
ret
```

&nbsp;

## level 23

> Perform the following:\
> &emsp;Make the first instruction in your code a jmp\
> &emsp;Make that jmp a relative jump to 0x51 bytes from the current position\
> &emsp;At the code location where the relative jump will redirect control flow set rax to 0x1

Let's learn how to perform a relative jump in the code flow.

### Relative jump

A jump can be performed using the `jmp` instruction.

```
jmp label
.
.
51 bytes
.
.
label:
# Code to be executed
```

As we can see the `jmp` instruction looks for the label mentioned and then transfers the code flow to that label.

We still need to learn how to insert 51 bytes between the `jmp` instruction and the `label`.

### `nop` instruction

The `nop` instruction makes no semantic difference to the program, i.e. it does nothing to the program logic. For this reason, it is used to pad the code.

We can repeat the `nop instruction` using a repeat loop.

### Repeat loop

The repeat loop repeats whatever instruction is mentioned within it as many times as specified.

```
.rept (number of times to be repeated)
instruction
.endr
```

Now we simply have to put our `nop` instruction inside the repeat loop and put the repeat loop between the `jmp` instruction and the `label`.

```asm title="assembly23.asm"
jmp Relative
.rept 0x51
nop
.endr
Relative:
mov rax, 0x1
```

&nbsp;

## level 24

> Create a two jump trampoline:\
> &emsp;Make the first instruction in your code a jmp\
> &emsp;Make that jmp a relative jump to 0x51 bytes from its current position\
> &emsp;At 0x51 write the following code:\
> &emsp;&emsp;Place the top value on the stack into register rdi\
> &emsp;&emsp;jmp to the absolute address 0x403000\

We have to combine the concepts learnt in [level 22](#level-22) and [level 23](#level-23).

```asm title="assembly24.asm"
jmp Relative
.rept 0x51
nop
.endr
Relative:
pop rdi
mov r10, 0x403000
jmp r10
```

&nbsp;

## level 25

> Implement the following:\
> &emsp;if [x] is 0x7f454c46:\
> &emsp;&emsp;y = [x+4] + [x+8] + [x+12]\
> &emsp;else if [x] is 0x00005A4D:\
> &emsp;&emsp;y = [x+4] - [x+8] - [x+12]\
> &emsp;else:\
> &emsp;&emsp;y = [x+4] * [x+8] * [x+12]
>
> where:\
> &emsp;x = rdi, y = rax.
>
> Assume each dereferenced value is a signed dword.\
> This means the values can start as a negative value at each memory position.
> 
> A valid solution will use the following at least once:\
> &emsp;jmp (any variant), cmp

```asm title="assembly25.asm"
mov rsi, [rdi] 
mov eax, [rdi+4] 
mov ebx, [rdi+8] 
mov ecx, [rdi+12]

cmp esi, 0x7f454c46  
je handle_case_0x7f454c46   

cmp esi, 0x00005A4D 
je handle_case_0x00005A4D   

default_case:
  imul ebx           
  imul ecx     
  int3    
  jmp end                     

case_0x7f454c46:
  add eax, ebx
  add eax, ecx 
  int3     
  jmp end                    
    
case_0x00005A4D:
  sub eax, ebx           
  sub eax, ecx 
  int3   
  jmp end                    

end:
  nop
```

&nbsp;

## level 26

> Implement the following logic:\
> &emsp;if rdi is 0:\
> &emsp;&emsp;jmp 0x403016\
> &emsp;else if rdi is 1:\
> &emsp;&emsp;jmp 0x4030e4\
> &emsp;else if rdi is 2:\
> &emsp;&emsp;jmp 0x4031e1\
> &emsp;else if rdi is 3:\
> &emsp;&emsp;jmp 0x403298\
> &emsp;else:\
> &emsp;&emsp;jmp 0x403321
>
> Please do the above with the following constraints:\
> &emsp;Assume rdi will NOT be negative\
> &emsp;Use no more than 1 cmp instruction\
> &emsp;Use no more than 3 jumps (of any variant)\
> &emsp;We will provide you with the number to 'switch' on in rdi.\
> &emsp;We will provide you with a jump table base address in rsi.\

```asm title="assembly26.asm"
cmp rdi, 3
jbe here
mov rdi, 4

here:
mov rax, [8 * rdi + rsi]
jmp rax
```

&nbsp;

## level 27

> Please compute the average of n consecutive quad words, where:\
> &emsp;rdi = memory address of the 1st quad word\
> &emsp;rsi = n (amount to loop for)\
> &emsp;rax = average computed

```asm title="assembly27.asm"
mov rax, 0
mov rbx, 1
mov rax, [rdi]

loop:
cmp rbx, rsi
jg done
add rax, [rdi + rbx * 0x8]
add rbx, 1
jmp loop

done:
div rsi
```

&nbsp;

## level 28

> Count the consecutive non-zero bytes in a contiguous region of memory, where:\
> &emsp;rdi = memory address of the 1st byte\
> &emsp;rax = number of consecutive non-zero bytes
>
> Additionally, if rdi = 0, then set rax = 0 (we will check)!

```asm title="assembly28.asm"
cmp rdi, 0
je done
mov rax, 0

loop:
cmp byte ptr [rdi], 0
je done
add rax, 1
add rdi, 1
jmp loop

done:
nop
```

&nbsp;

## level 29

> Please implement the following logic:\
> &emsp;str_lower(src_addr):\
> &emsp;&emsp;i = 0\
> &emsp;&emsp;if src_addr != 0:\
> &emsp;&emsp;&emsp;while [src_addr] != 0x00:\
> &emsp;&emsp;&emsp;&emsp;if [src_addr] less than or equal to 0x5a:\
> &emsp;&emsp;&emsp;&emsp;&emsp;[src_addr] = foo([src_addr])\
> &emsp;&emsp;&emsp;&emsp;&emsp;i += 1\
> &emsp;&emsp;&emsp;&emsp;src_addr += 1\
> &emsp;&emsp;return i
>
> foo is provided at 0x403000.\
> foo takes a single argument as a value and returns a value.
>
> All functions (foo and str_lower) must follow the Linux amd64 calling convention (also known as System V AMD64 ABI):\
> &emsp;https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
>
> Therefore, your function str_lower should look for src_addr in rdi and place the function return in rax.
>
> An important note is that src_addr is an address in memory (where the string is located) and [src_addr] refers to the byte that exists at src_addr.
>
> Therefore, the function foo accepts a byte as its first argument and returns a byte.

```asm title="assembly29.asm"
mov rax, 0
cmp rdi, 0
je done

loop:
mov rbx, 0
mov bl, [rdi]
cmp bl, 0
je done

cmp bl, 90
jg greater

push rdi
push rax
mov rdi, 0
mov dil, bl
mov r10, 0x403000
call r10
mov bl, al
pop rax
pop rdi
mov [rdi], bl
add rax, 1

greater:
add rdi, 1
jmp loop

done:
ret
```
