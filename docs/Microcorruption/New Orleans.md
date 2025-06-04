---
custom_edit_url: null
sidebar_position: 1
---


We can set a breakpoint at main using the `break main` command.

![neworleans2](https://github.com/Knign/Write-ups/assets/110326359/ad256531-9cdb-4691-901b-4664b42ac1c1)

```text title="Disassembly"
4438 <main>
// highlight-next-line
4438:  3150 9cff      add	#0xff9c, sp
443c:  b012 7e44      call	#0x447e <create_password>
4440:  3f40 e444      mov	#0x44e4 "Enter the password to continue", r15
4444:  b012 9445      call	#0x4594 <puts>
4448:  0f41           mov	sp, r15
444a:  b012 b244      call	#0x44b2 <get_password>
444e:  0f41           mov	sp, r15
4450:  b012 bc44      call	#0x44bc <check_password>
4454:  0f93           tst	r15
4456:  0520           jnz	$+0xc <main+0x2a>
4458:  3f40 0345      mov	#0x4503 "Invalid password; try again.", r15
445c:  b012 9445      call	#0x4594 <puts>
4460:  063c           jmp	$+0xe <main+0x36>
```

We can see that the breakpoint has been set.

If we continue through the program using the `continue` or `c` command, the program has stopped execution at the breakpoint.

![neworleans3](https://github.com/Knign/Write-ups/assets/110326359/fc57a6e7-b8c5-4040-ab82-d4a3104e3bba)

The program calls the following functions:
	- `create_password`: Creates and sets a password for the lock. 
	- `get_password`: Takes user input.
	- `check_password`: Checks if user input is correct.
The `create_password` function seems interesting. Let's set a breakpoint there using `break 447e` and continue execution flow using `c`.

![neworleans4](https://github.com/Knign/Write-ups/assets/110326359/865e0914-7374-4a92-8d5c-863529908837)

We can see that we are now inside the `create_password` function. Note that we could have directly jumped into this program using `let pc = 447e` command.

So this function sets the value of `r15` to be equal to the address `0x2400` in memory.And then it moves some characters which seem to be our password into that memory address.

Let's set a breakpoint at `44ac` and `continue` the execution. 

Once we hit the breakpoint we can check the memory location using the `R 2400` command
```
> R 2400
2400 5f6a 6b70 214d 7200 0000 0000 0000 0000  _jkp!Mr.........
2410 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Or we can just look in the Live Memory Dump section.

![neworleans5](https://github.com/Knign/Write-ups/assets/110326359/10f11ac0-0212-47ae-a898-cb3481003bd7)

So the string that was read into memory was `_jkp!Mr`.

Let's continue to where we are prompted for the passsword.

![neworleans6](https://github.com/Knign/Write-ups/assets/110326359/68d9622c-6f2d-416c-88e1-d1344e808bd7)

If we `send` this password to the lock, we get the following message:

![neworleans7](https://github.com/Knign/Write-ups/assets/110326359/8d1d6268-4b42-485f-9397-d177cb47ba10)

We have successfully unlocked the door and can get the `Cy Yombinator bearer bonds` or whatever they are called.

Let's go to the `check_password` function to see how it works.
