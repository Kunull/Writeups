---
custom_edit_url: null
sidebar_position: 5
---


<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/432b7a93-2754-4bc0-836f-4d70f5b61a72?raw=1)
</figure>

## User Manual

```
Lockitall                                            LOCKIT PRO r a.03
______________________________________________________________________

              User Manual: Lockitall LockIT Pro, rev a.03              
______________________________________________________________________


OVERVIEW

    - Lockitall developers  have implemented  military-grade on-device
      encryption to keep the password secure.
    - This lock is not attached to any hardware security module.


DETAILS

    The LockIT Pro a.03  is the first of a new series  of locks. It is
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

    This is Software Revision 02. This release contains military-grade
    encryption so users can be confident that the passwords they enter
    can not be read from memory.   We apologize for making it too easy
    for the password to be recovered on prior versions.  The engineers
    responsible have been sacked.

    


(c) 2013 LOCKITALL                                            Page 1/1
```

```text title="Debugger Console"
> break main
  Breakpoint set
> continue
```

If we look at the `main` function, we can see that it is much shorter now.

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/89b4db84-aaa6-42b6-bce3-203336851cab?raw=1)
</figure>

It makes the following calls:
	- `enc`: Encodes the passwords.
	- `0x2400`: It is a address in memory.
That is interesting, why would it call to a memory address? Could it be instructions? Before we look into that, let's set a breakpoint there using `break 444a`.

Let's set a breakpoint where the call is made and continue execution.

```text title="Debugger Console"
> break 0x444a
  Breakpoint set
> continue
```

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/215083cc-1bc3-4161-a004-b025fc0f0083?raw=1)
</figure>

If we check the memory dump, we can see that the bytes in memory.

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/593dde5f-6485-4772-a414-3687e293e06a?raw=1)
</figure>

Let's get a better look:

```
> R 2400 400
2400 0b12 0412 0441 2452 3150 e0ff 3b40 2045  .....A$R1P..;@ E
2410 073c 1b53 8f11 0f12 0312 b012 6424 2152  .<.S........d$!R
2420 6f4b 4f93 f623 3012 0a00 0312 b012 6424  oKO..#0.......d$
2430 2152 3012 1f00 3f40 dcff 0f54 0f12 2312  !R0...?@...T..#.
2440 b012 6424 3150 0600 b490 b9fc dcff 0520  ..d$1P......... 
2450 3012 7f00 b012 6424 2153 3150 2000 3441  0....d$!S1P .4A
2460 3b41 3041 1e41 0200 0212 0f4e 8f10 024f  ;A0A.A.....N...O
2470 32d0 0080 b012 1000 3241 3041 d21a 189a  2.......2A0A....
2480 22dc 45b9 4279 2d55 858e a4a2 67d7 14ae  ".E.By-U....g...
2490 a119 76f6 42cb 1c04 0efa a61b 74a7 416b  ..v.B.......t.Ak
24a0 d237 a253 22e4 66af c1a5 938b 8971 9b88  .7.S".f......q..
24b0 fa9b 6674 4e21 2a6b b143 9151 3dcc a6f5  ..ftN!*k.C.Q=...
24c0 daa7 db3f 8d3c 4d18 4736 dfa6 459a 2461  ...?.<M.G6..E.$a
24d0 921d 3291 14e6 8157 b0fe 2ddd 400b 8688  ..2....W..-.@...
24e0 6310 3ab3 612b 0bd9 483f 4e04 5870 4c38  c.:.a+..H?N.XpL8
24f0 c93c ff36 0e01 7f3e fa55 aeef 051c 242c  .<.6..>.U....$,
2500 3c56 13af e57b 8abf 3040 c537 656e 8278  <V...{..0@.7en.x
2510 9af9 9d02 be83 b38c e181 3ad8 395a fce3  ..........:.9Z..
2520 4f03 8ec9 9395 4a15 ce3b fd1e 7779 c9c3  O.....J..;..wy..
2530 5ff2 3dc7 5953 8826 d0b5 d9f8 639e e970  _.=.YS.&....c..p
2540 01cd 2119 ca6a d12c 97e2 7538 96c5 8f28  ..!..j.,..u8...(
2550 d682 1be5 ab20 7389 48aa 1fa3 472f a564  ..... s.H...G/.d
2560 de2d b710 9081 5205 8d44 cff4 bc2e 577a  .-....R..D....Wz
2570 d5f4 a851 c243 277d a4ca 1e6b 0000 0000  ...Q.C'}...k....
2580 0000 0000 0000 0000 0000 0000 0000 0000  ................
```
I think it is time to use the disassembler that we have been provided.

```
2400 0b12 0412 0441 2452 3150 e0ff 3b40 2045  
2410 073c 1b53 8f11 0f12 0312 b012 6424 2152  
2420 6f4b 4f93 f623 3012 0a00 0312 b012 6424  
2430 2152 3012 1f00 3f40 dcff 0f54 0f12 2312  
2440 b012 6424 3150 0600 b490 b9fc dcff 0520  
2450 3012 7f00 b012 6424 2153 3150 2000 3441
2460 3b41 3041 1e41 0200 0212 0f4e 8f10 024f 
2470 32d0 0080 b012 1000 3241 3041 d21a 189a  
2480 22dc 45b9 4279 2d55 858e a4a2 67d7 14ae 
2490 a119 76f6 42cb 1c04 0efa a61b 74a7 416b
24a0 d237 a253 22e4 66af c1a5 938b 8971 9b88  
24b0 fa9b 6674 4e21 2a6b b143 9151 3dcc a6f5  
24c0 daa7 db3f 8d3c 4d18 4736 dfa6 459a 2461  
24d0 921d 3291 14e6 8157 b0fe 2ddd 400b 8688  
24e0 6310 3ab3 612b 0bd9 483f 4e04 5870 4c38  
24f0 c93c ff36 0e01 7f3e fa55 aeef 051c 242c  
2500 3c56 13af e57b 8abf 3040 c537 656e 8278  
2510 9af9 9d02 be83 b38c e181 3ad8 395a fce3  
2520 4f03 8ec9 9395 4a15 ce3b fd1e 7779 c9c3  
2530 5ff2 3dc7 5953 8826 d0b5 d9f8 639e e970  
2540 01cd 2119 ca6a d12c 97e2 7538 96c5 8f28  
2550 d682 1be5 ab20 7389 48aa 1fa3 472f a564 
2560 de2d b710 9081 5205 8d44 cff4 bc2e 577a  
2570 d5f4 a851 c243 277d a4ca 1e6b 0000 0000  
2580 0000 0000 0000 0000 0000 0000 0000 0000  
```

If we clean the bytes, and enter those into the disassembler, we can see the respective assembly instructions.

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/f22dc196-acb7-4aca-aa0f-d358c16fdd6b?raw=1)
</figure>

There's more instructions but for now let's go through these first.

It seems like the last instruction is comparing the the data at `r4-0x24` with `0xfcb9`.

When the `add #0x4, r4` instruction is executed, we can see that in the register state table, the value of `r4`.

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/0aa04606-978f-4b67-a487-29013c605a38?raw=1)
</figure>

So the the data that is being compared is from `0x43fe-0x24` which is `0x43da`.

Let's continue input our password.

```text title="Debugger Console"
> continue
```

<figure style={{ textAlign: 'center' }}>
![reykjavik6](https://github.com/Knign/Write-ups/assets/110326359/8ced3473-52b5-41e2-bf80-9ff3ddb387ef)
</figure>

If we check the locations at which our input is stored we can see that it is also stored at `0x43da`.

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/6c1fac82-23ec-4ac9-b0f0-4ad83a5fa1bc?raw=1)
</figure>

That's it! So we can just set the data at address `0x43da` to be `0xfcb9`.

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/6776f858-318d-40a9-8a95-3b75d685837b?raw=1)
</figure>

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/0ab73899-c091-4686-99ba-b6bc790a70ec?raw=1)
</figure>

<figure style={{ textAlign: 'center' }}>
![image](https://github.com/user-attachments/assets/271149df-ada9-44eb-98e6-a0d63aa6827f?raw=1)
</figure>
