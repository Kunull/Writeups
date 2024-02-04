---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

![cusco2](https://github.com/Knign/Write-ups/assets/110326359/2d741c64-e9f4-46e2-9c97-dad12dd3a35d)

This time, the `main` function only calls the login function.

Let's set a breakpoint at the `login` function.

![cusco3](https://github.com/Knign/Write-ups/assets/110326359/6852b6d8-b7f8-4d33-8503-949b98dedf2a)

Once inside the `login` function, we can see that it asks the user to input the password and then jumps based on whether the password is correct.

Let's set a breakpoint right before the function returns.

![cusco4](https://github.com/Knign/Write-ups/assets/110326359/01bc3ec0-6c12-4921-9b5a-91228bf5eac5)

While examining our input in memory, we can see something interesting.

![cusco5](https://github.com/Knign/Write-ups/assets/110326359/905e8ae8-8973-4994-9fec-0164fce8ca92)

As we can see the stack pointer `sp` now points to the beginning of our input.

Let's step once to the `ret` instruction using the `s` command.

![cusco6](https://github.com/Knign/Write-ups/assets/110326359/c35894c6-1e1a-48e6-bc45-2952edfe9eb7)

The stack pointer now points at the location 16 bytes after the start of the buffer because the `add 0x10, sp` instruction just got executed.

When the the `ret` instruction executes, the the bytes pointed to by the `sp` is treated as the return address.

This looks like the start of another buffer overflow attack. What if we overwrite that address with something that we want to execute.

![cusco7](https://github.com/Knign/Write-ups/assets/110326359/df83f201-8e17-434d-841d-143c81bee36d)

Look! there's an `unlock_door` function at `0x4446`. This is something we would really like to execute.

Let's `reset` the program and this time provide an input of 18 bytes. (The program says we can only enter 8 - 16 bytes but it never checks.) 

![cusco8](https://github.com/Knign/Write-ups/assets/110326359/b02bbd42-e9a6-4293-aa0d-29c9c5005a1a)

Note that the last two bytes are reversed, this is because LSB is stored leftmost and MSB is stored rightmost. This is also known as little-endian format.

The program will interpret these bytes as `4446`.

Let's hit `c` to continue the program.

![cusco9](https://github.com/Knign/Write-ups/assets/110326359/324e8cfd-15ae-4ad2-a849-74f763c4050c)

Looks like LockIT hasn't improved their security all that much.
