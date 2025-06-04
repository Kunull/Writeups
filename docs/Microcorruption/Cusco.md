---
custom_edit_url: null
sidebar_position: 4
---

![image](https://github.com/user-attachments/assets/f1b86111-12ff-48e8-b776-7edc21fa36f3)

![image](https://github.com/user-attachments/assets/ebea8e3a-41d2-4a48-bdc5-8bac2d5eee02)

## User Manual

```
Lockitall                                            LOCKIT PRO r b.02
______________________________________________________________________

              User Manual: Lockitall LockIT Pro, rev b.02              
______________________________________________________________________


OVERVIEW

    - We have fixed issues with passwords which may be too long.
    - This lock is attached the the LockIT Pro HSM-1.


DETAILS

    The LockIT Pro b.02  is the first of a new series  of locks. It is
    controlled by a  MSP430 microcontroller, and is  the most advanced
    MCU-controlled lock available on the  market. The MSP430 is a very
    low-power device which allows the LockIT  Pro to run in almost any
    environment.

    The  LockIT  Pro   contains  a  Bluetooth  chip   allowing  it  to
    communiciate with the  LockIT Pro App, allowing the  LockIT Pro to
    be inaccessable from the exterior of the building.

    There  is no  default  password  on the  LockIT  Pro HSM-1.   Upon
    receiving the  LockIT Pro,  a new  password must  be set  by first
    connecting the LockitPRO HSM to  output port two, connecting it to
    the LockIT Pro App, and entering a new password when prompted, and
    then restarting the LockIT Pro using the red button on the back.
    
    LockIT Pro Hardware  Security Module 1 stores  the login password,
    ensuring users  can not access  the password through  other means.
    The LockIT Pro  can send the LockIT Pro HSM-1  a password, and the
    HSM will  return if the password  is correct by setting  a flag in
    memory.
    
    This is Hardware  Version B.  It contains  the Bluetooth connector
    built in, and two available  ports: the LockIT Pro Deadbolt should
    be  connected to  port  1,  and the  LockIT  Pro  HSM-1 should  be
    connected to port 2.

    This is Software Revision 02. We have improved the security of the
    lock by  removing a conditional  flag that could  accidentally get
    set by passwords that were too long.

    


(c) 2013 LOCKITALL                                            Page 1/1
```

```text title="Debugger console"
> break main
  Breakpoint set
> continue
```

![image](https://github.com/user-attachments/assets/28314ad4-90b6-4b25-8e3a-c417cb4858a6)

This time, the `main` function only calls the `login` function.

## `login`

Let's set a breakpoint at the `login` function.

```text title="Debugger console"
> break login
  Breakpoint set
> continue
```

![image](https://github.com/user-attachments/assets/37ae776f-fdf7-40d3-9d65-48013de7e62f)

Once inside the `login` function, we can see that it asks the user to input the password into a buffer using `getsn`.
The buffer is 48 bytes wide and is located at the location of the stack pointer `sp`.

Let's set a breakpoint at `0x451a`.

```text title="Debugger console"
> break 0x451a
  Breakpoint set
> continue
```

![image](https://github.com/user-attachments/assets/4ac47849-daba-463b-bf9a-b10a27ac6d0f)

![image](https://github.com/user-attachments/assets/ba490eaf-4c9d-46b0-9a63-b4aef48b6797)

That tells us that the input buffer us stored at `0x45ee`

Let's set a breakpoint right before the function returns at `0x453a`.

```text title="Debugger console"
> break 0x453a
  Breakpoint set
> continue
```

![cusco4](https://github.com/Knign/Write-ups/assets/110326359/01bc3ec0-6c12-4921-9b5a-91228bf5eac5)

![image](https://github.com/user-attachments/assets/16c3f220-b3ae-4066-89d0-90e82a18d3c9)

We can continue execution after providing the input.

```text title="Debugger console"
> continue
```

While examining our input in memory, we can see something interesting.

![image](https://github.com/user-attachments/assets/a2d8217e-f8e6-4e70-a98f-144bb2e23e48)

As we can see the stack pointer `sp` now points to the beginning of our input.

Let's step once to the `ret` instruction using the `s` command.

```text title="Debugger console"
> continue
```

![image](https://github.com/user-attachments/assets/07ad7e5f-b94c-44b2-84c8-6a39a1623ae1)

![image](https://github.com/user-attachments/assets/3527477a-834b-453f-9f5b-a57eebbad590)

The stack pointer now points at the location 16 bytes after the start of the buffer because the `add 0x10, sp` instruction just got executed.

When the the `ret` instruction executes, the bytes pointed to by the `sp` is treated as the return address.

## Return address overwrite

```
<==: Value is stored at the address
<--: Points to the address

                              ╎  .... ....  ╎
                              ┌─────────────┐   
                  *==> 0x43ee │  6161 6161  │
                 ╱     0x43f0 │  6161 6161  │
                ╱      0x43f2 │  6161 6161  │
               ║       0x43f4 │  6161 6161  │
               ║       0x43f6 │  6161 6161  │
               ║       0x43f8 │  6161 6161  │
               ║       0x43fa │  6161 6161  │
               ║       0x43fc │  6161 6161  │
input buffer ==║              ├╌╌╌╌╌╌╌╌╌╌╌╌╌┤
               ║  *==> 0x43fc │  6161 6161  │ 
               ║ ╱            ├╌╌╌╌╌╌╌╌╌╌╌╌╌┤
  return addr ==*      0x43fe │  6161 6161  │
 for login     ║              ╎  .... ....  ╎
               ║              ╎  .... ....  ╎
                ╲             ╎  .... ....  ╎
                 ╲            ╎  .... ....  ╎
                  *==> 0x441E │  6161 6161  │
                              └─────────────┘
                              ╎  .... ....  ╎                       
```

So we can overwrite the return address with out input as it overlaps with the buffer.

Let's check if there is any interesting function that we want to return execution flow to.

## `unlock_door`

![image](https://github.com/user-attachments/assets/ee1836db-7db3-4772-ba5b-c74f925be4a0)

There's an `unlock_door` function at `0x4446`. This is something we would really like to execute.

If we pass the 17th and 18th bytes as `0x46` and `0x44` respectively, we can hijack execution flow and cause `unlock_door` to be executed after `login`. 

![image](https://github.com/user-attachments/assets/4ea11e43-7b39-4977-976d-60186a1d13d4)

![image](https://github.com/user-attachments/assets/73924c08-3d1c-4b1e-802e-94f1127b047f)
