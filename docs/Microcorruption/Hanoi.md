---
custom_edit_url: null
sidebar_position: 3
---

![image](https://github.com/user-attachments/assets/78b6bc11-a104-46ae-b754-f05aaa60226c?raw=1)

## User Manual

```
Lockitall                                            LOCKIT PRO r b.01
______________________________________________________________________

              User Manual: Lockitall LockIT Pro, rev b.01              
______________________________________________________________________


OVERVIEW

    - This lock is attached the the LockIT Pro HSM-1.
    - We have updated  the lock firmware  to connect with the hardware
      security module.


DETAILS

    The LockIT Pro b.01  is the first of a new series  of locks. It is
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

    This is Software Revision 01,  allowing it to communicate with the
    LockIT Pro HSM-1

    


(c) 2013 LOCKITALL                                            Page 1/1
```

Let's set a breakpoint at `main` and continue execution.

```text title="Debugger Console"
> break main
  Breakpoint set
> continue
```

![image](https://github.com/user-attachments/assets/2979d941-5f61-4ff9-8255-be02867c0443?raw=1)

This time it only calls one function:
	- `login`

## `login`

Let's investigate how this function exactly works.

```text title="Debugger Console"
> break login
  Breakpoint set
> continue
```

![image](https://github.com/user-attachments/assets/9dcf7d14-ce36-4f68-84b1-4e98896206e3?raw=1)

We can see the `getsn` call is what reads in the user input. 

## `getsn`

![image](https://github.com/user-attachments/assets/a9834706-0327-4352-8002-d012c3f2cdf9?raw=1)

It set the user input character limit to `0x1c`, which is 28 bytes.
As for the location, it is set to `0x2400`.

This tells us that we can write upto 28 bytes to `0x2400`.

The instruction at `0x455a` compares the byte at memory address `0x2410` with `0x2c`. 

![image](https://github.com/user-attachments/assets/60c9f88c-c289-4f95-ae05-16f4a596bf10?raw=1)

If the values are equal, the message `"Access granted."` is printed and the `unlock_door` function is called.
If the values are unequal, the message `"That password is not correct."` is printed and the program exits.

Looking look at that address, we can see that it is filled with zeroes. 

```
> R 2410 
2410 0000 0000 0000 0000 0000 0000 0000 0000  ................ 
2420 0000 0000 0000 0000 0000 0000 0000 0000  ................
``` 

In order to complete this level, we have to modify the value at address `0x2410` and set it to `0x2c` such that the comparison is valid.

## Stack Overwrite

```
<==: Value is stored at the address
<--: Points to the address

                              ╎  .... ....  ╎
                              ┌─────────────┐   
                  *==> 0x2400 │  6161 6161  │
                 ╱     0x2402 │  6161 6161  │
                ╱      0x2404 │  6161 6161  │
               ║       0x2406 │  6161 6161  │
               ║       0x2408 │  6161 6161  │
               ║       0x240a │  6161 6161  │
               ║       0x240c │  6161 6161  │
               ║       0x240e │  6161 6161  │
input buffer ==║              ├╌╌╌╌╌╌╌╌╌╌╌╌╌┤
               ║  *==> 0x2410 │  6161 6161  │ 
               ║ ╱            ├╌╌╌╌╌╌╌╌╌╌╌╌╌┤
compared with ==       0x2412 │  6161 6161  │
0x2c           ║       0x2414 │  6161 6161  │
                ╲      0x2416 │  6161 6161  │
                 ╲     0x2418 │  6161 6161  │
                  *==> 0x241a │  6161 6161  │
                              └─────────────┘
                              ╎  .... ....  ╎                       
```

From at the stack representation above, we can see that our input overwrites the value which is being compared to `0x2c`.
Specifically, the 17th byte that we in our input coincides with the byte with is being compared from `0x2410`.

This means that using the input, we can overwrite the required value.



Since our input is stored at `0x2400`, we can overwrite the byte at `0x2410` with 17 bytes minimum. As we are only supposed to enter up to 16 bytes, we are essentially performing a buffer overflow.

Let's try that out. This time we will enter user input in hexadecimal.

![image](https://github.com/user-attachments/assets/7d0e8f48-17d4-4d33-931b-d31ddceb1dcf?raw=1)

![image](https://github.com/user-attachments/assets/a6ae8415-07c8-41e3-ae2c-386a9ca7de03?raw=1)

![image](https://github.com/user-attachments/assets/f2cd32cd-5696-4db2-8cdd-141215e75ad2?raw=1)
