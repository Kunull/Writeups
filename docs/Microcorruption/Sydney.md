---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 2
---

Let's set a breakpoint at main using `break main`.

![sydney2](https://github.com/Knign/Write-ups/assets/110326359/0705f345-b0b3-4b4a-ac50-82d2350b692b)

We can see that the program no  longer calls the `create_password` function. So we'll have to find a new approach to open the lock.

The `check_password` function is still being called, so let's set a breakpoint there.

We are then asked to enter the password.

![sydney4](https://github.com/Knign/Write-ups/assets/110326359/dd70d7b7-4d05-4a81-80ca-259741110e6a)

If we continue the program execution, it stops at the breakpoint that we set earlier at `check_password`.

![sydney3](https://github.com/Knign/Write-ups/assets/110326359/0e67c91d-60f1-4205-9dc1-49902e182731)

So the first two bytes of our input are being compared with the word `0x6348` which is `cH` in ASCII.

The next two are being compared to `0x5551` which is `UQ` in ASCII. And the next two are being compared with `0x6927` which is `i'` in ASCII and the next two to `@A`.

Let's rerun the program using the `reset` command and give it the password `cHUQi'@A`.

![sydney5](https://github.com/Knign/Write-ups/assets/110326359/3356f5e9-4fe8-4ac9-aa41-c41c89f6eb21)


Look, our password is in the memory, we're going to unlock the lock. Or are we?

See, even though the bytes are stored in memory in the correct order, they are not in the order that the program wants them to be.

The program stores bytes in little-endian format i.e. the LSB is supposed to be in the leftmost position and MSB in the rightmost.

So when it reads our first word, it expects them to in little-endian format and reads them as `0x4863`. In the same manner, the next word is read as `0x5155`, the third one is read as `0x2769` and the last word is read as `0x4140`.

In order to pass the checks, our bytes need to be flipped when they are stored so that the program will flip them when reading and interpret them correctly.

Therefore the password should actually be `HcQU'iA@`. 

![sydney6](https://github.com/Knign/Write-ups/assets/110326359/d9fb2012-77f5-402b-9436-6c3d7387b0fb)

We've now robbed the bank in Sydney.
