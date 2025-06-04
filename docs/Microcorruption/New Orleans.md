---
custom_edit_url: null
sidebar_position: 1
---

![image](https://github.com/user-attachments/assets/9df44578-3853-4f7c-9322-131707f7c24a)

![image](https://github.com/user-attachments/assets/887a4d5c-9766-47f1-9e0a-e09ebe456193)

## User Manual

```
Lockitall                                            LOCKIT PRO r a.01
______________________________________________________________________

              User Manual: Lockitall LockIT Pro, rev a.01              
______________________________________________________________________


OVERVIEW

    - This is the first LockIT Pro Lock.
    - This lock is not attached to any hardware security module.


DETAILS

    The LockIT Pro a.01  is the first of a new series  of locks. It is
    controlled by a  MSP430 microcontroller, and is  the most advanced
    MCU-controlled lock available on the  market. The MSP430 is a very
    low-power device which allows the LockIT  Pro to run in almost any
    environment.

    The  LockIT  Pro   contains  a  Bluetooth  chip   allowing  it  to
    communiciate with the  LockIT Pro App, allowing the  LockIT Pro to
    be inaccessable from the exterior of the building.

    There is  no default password  on the LockIT  Pro---upon receiving
    the LockIT Pro, a new password must be set by connecting it to the
    LockIT Pro  App and  entering a password  when prompted,  and then
    restarting the LockIT Pro using the red button on the back.
    
    This is Hardware  Version A.  It contains  the Bluetooth connector
    built in, and one available port  to which the LockIT Pro Deadbolt
    should be connected.

    This is Software Revision 01.

    


(c) 2013 LOCKITALL                                            Page 1/1
```

## `main`

We can set a breakpoint at `main`.

```text title="Debugger console"
> break main
  Breakpoint set
```

![image](https://github.com/user-attachments/assets/33eb383b-d6fd-4dac-9fae-df07c57ca23a)

We can see that the breakpoint has been set.

If we continue through the program using the `continue` or `c` command, the program stops execution at the breakpoint.

```text title="Debugger console"
> continue
```

![image](https://github.com/user-attachments/assets/41a9556d-e48d-43de-9a33-a4774c8fcd19)

The program calls the following functions:
	- `create_password`: Creates and sets a password for the lock. 
	- `get_password`: Takes user input.
	- `check_password`: Checks if user input is correct.


## `create_password`

The `create_password` function seems interesting. Let's set a breakpoint there using and the continue execution flow.

```text title="Debugger console"
> break create_password
  Breakpoint set
> continue
```

![image](https://github.com/user-attachments/assets/a9ef00a3-a974-4051-a302-d46da28787a1)

We can see that we are now inside the `create_password` function.

So this function sets the value of `r15` to be equal to the address `0x2400` in memory.
It then treats `r15` as memory pointer and moves some characters which seem to be our password into that memory address.

Let's set a breakpoint at `44b0` and continue the execution. 

```text title="Debugger console"
> break 0x44b0
  Breakpoint set
> continue
```

Once we hit the breakpoint we can check the memory location using the `R 2400` command.

```text title="Debugger console"
> R 0x2400
2400 697a 3746 727a 2a00 0000 0000 0000 0000  iz7Frz*.........
2410 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Or we can just look in the Live Memory Dump section.

![image](https://github.com/user-attachments/assets/f8c31497-4f34-4775-ac0a-e0bd178aa4cc)

So the string that was read into memory was `iz7Frz*`.

Let's continue to where we are prompted for the passsword.

```text title="Debugger console"
> solve
```

![image](https://github.com/user-attachments/assets/9d93dff2-606b-46c5-a668-715f1bdf5122)

![image](https://github.com/user-attachments/assets/6fc6ca78-b1e4-4a08-9c41-4a0e9a641e12)
