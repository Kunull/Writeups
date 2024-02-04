---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 3
---

Let's set a breakpoint as is standard practice.

![hanoi2](https://github.com/Knign/Write-ups/assets/110326359/6ed1f8cc-b48f-4055-8cb5-6e8a288eba52)

This time it only calls one function:
	- `login`
Let's investigate how this function exactly works. Set a breakpoint using `break 4520`.

![hanoi3](https://github.com/Knign/Write-ups/assets/110326359/28cef935-7fc5-474a-83f9-46b6d43fd9c9)

We can see the `getsn` call is what takes the user input. And in the next instruction at `4540`, the user input is stored at memory address `0x2400`.

![hanoi5](https://github.com/Knign/Write-ups/assets/110326359/c94918a6-156b-4174-9105-5343f62ec68b)

The instruction at `455a` compares the byte at memory address `0x2410` with `0x97`. 

If we look at that address, we can see that it is filled with zeroes. We can also do this using the `R 0x2410` command.
```
> R 2410 
2410 0000 0000 0000 0000 0000 0000 0000 0000  ................ 
2420 0000 0000 0000 0000 0000 0000 0000 0000  ................
``` 
Since our input is stored at `0x2400`, we can overwrite the byte at `0x2410` with 17 bytes minimum. As we are only supposed to enter up to 16 bytes, we are essentially performing a buffer overflow.

Let's try that out. This time we will enter user input in hexadecimal.

![hanoi4](https://github.com/Knign/Write-ups/assets/110326359/d41cdf13-070a-4722-a11c-67f8b034b872)

If we `continue` through the program execution, we are greeted with the following message.

![hanoi6](https://github.com/Knign/Write-ups/assets/110326359/aaef7fc7-0331-4ebb-b8f6-3550a27c03aa)

We just exploited our first LockIT lock with a buffer overflow. 




