---
custom_edit_url: null
sidebar_position: 2
---

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/df92d5bb-3a2a-4d6b-b874-603890c77ef1?raw=1)
</figure>

## User Manual

```
Lockitall                                            LOCKIT PRO r a.02
______________________________________________________________________

              User Manual: Lockitall LockIT Pro, rev a.02              
______________________________________________________________________


OVERVIEW

    - We have revised the software in revision 02.
    - This lock is not attached to any hardware security module.


DETAILS

    The LockIT Pro a.02  is the first of a new series  of locks. It is
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

    This is  Software Revision 02.  We have received reports  that the
    prior  version of  the  lock was  bypassable  without knowing  the
    password. We have fixed this and removed the password from memory.

    


(c) 2013 LOCKITALL                                            Page 1/1
```

Let's set a breakpoint at main and continue execution flow.

```text title="Debugger Console"
> break main
  Breakpoint set
> continue
```

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/62bc1214-bfe6-4f31-81a0-d9de38b00ae9?raw=1)
</figure>

We can see that the program no  longer calls the `create_password` function. So we'll have to find a new approach to open the lock.

## `check_password`

The `check_password` function is still being called, so let's set a breakpoint there.

```text title="Debugger Console"
> break check_password
  Breakpoint set
> continue
```

We are then asked to enter the password.

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/fbde1a58-9f54-4620-a82a-90e2f187c25a?raw=1)
</figure>

If we continue the program execution, it stops at the breakpoint that we set earlier at `check_password`.

```text title="Debugger Console"
> continue
```

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/d87b9f8c-f64c-466d-ab79-68eeaef11465?raw=1)
</figure>

So the user's input is being compared as follows:

- 1st and 2nd bytes: `0x5567`, `Ug` in ASCII
- 3rd and 4th bytes: `0x6b25`, `k%` in ASCII
- 5th and 6th bytes: `0x253e`, `%>` in ASCII
- 7th and 8th bytes: `0x793e`, `y>` in ASCII


Let's rerun the program using the `reset` command and give it the password `Ugk%%>y>`.

```text title="Debugger Console"
> reset
```

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/f976fea7-18b2-4b03-830d-30f77ca1e55a?raw=1)
</figure>

Our password is in the memory, we're going to unlock the lock, right?

```text title="Debugger Console"
> continue
CPUOFF flag set; program no longer running. CPU must now be reset.
```

If we continue execution, the program exits. We can find the cause by looking the registers, especially the status register `sr`.

Let's set a breakpoint at the instruction right after the first comparison.

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/201b4689-f577-4de3-a0e0-2fbf3ef0c095?raw=1)
</figure>

```text title="Debugger Console"
> break 0x4490
  Breakpoint set
> continue
```

Next, let's reset the program, and repeat the steps.

```text title="Debugger Console"
> reset
```

Once we hit the breakpoint at `0x4490`, we can see that the `sr` register is modified.

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/42d15f0a-7372-473e-bd4a-eea068342f51?raw=1)
</figure>

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/c730e840-2335-4e5e-b660-8401f7df86f8?raw=1)
</figure>

## Status register `sr`

| Bit    | Flag                 | Value | Meaning                                                                                  |
| ------ | -------------------- | ----- | ---------------------------------------------------------------------------------------- |
| 0      | **C (Carry)**        | **1** | A carry occurred (or no borrow in compare/subtract) — in unsigned math: `b ≥ a` in `cmp` |
| 1      | **Z (Zero)**         | 0     | Result ≠ 0                                                                               |
| 2      | **N (Negative)**     | 0     | Result is not negative (MSB is 0)                                                        |
| 3      | **GIE (Interrupts)** | 0     | General interrupts are disabled                                                          |

Then, the `jnz` instruction checks if the zero bit of the status register `sr` is set. 
If it isn't set, that means the difference between the two values was not 0, and thus the values being compared were not the same. 

In order to undertand why the values were not the same even when we explicitely set them to be, we have to understand Endinaness.

### Endianness

#### Big endian

```
  0x439c   0x439d   
┌────────┬────────┐
│   55   │   67   │ 
└────────┴────────┘
```

The LSB is stored in the high memory address (`0x439d`) while the MSB is stored in the low memory address (`0x439c`).

This is the format in which humans write numbers. Network traffic is also sent in big endian format.

#### Little endian

```
  0x439c   0x439d   
┌────────┬────────┐
│   67   │   55   │ 
└────────┴────────┘
```

The LSB is stored in the low memory address (`0x439c`) while the MSB is stored in the high memory address (`0x439d`).

This is the format in which machines store data. This is the relevant format for our level.

So when it reads our first word for comparison, it expects them to in little-endian format i.e. `0x6755`. In the same manner, the next word should be `0x256b`, the third one should `0x3e25` and the last word should `0x3e79`.

In order to pass the checks, our bytes need to be flipped when they are stored so that the program, when reading, will interpret them correctly.

Therefore our input should actually be `gU%k>%>y`. 

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/b05a1cf5-1afb-4032-b344-d5191ead7a14?raw=1)
</figure>

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/c51e9e1b-955e-4a24-80a3-1be1e1590869?raw=1)
</figure>

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/9b24aaac-4762-44a0-8a50-31808f4b2473?raw=1)
</figure>
