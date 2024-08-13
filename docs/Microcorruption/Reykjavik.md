---
custom_edit_url: null
sidebar_position: 5
---

If we look at the `main` function, we can see that it is much shorter now.

![reykjavik2](https://github.com/Knign/Write-ups/assets/110326359/71f5066e-d894-4ca6-aaaa-2124cbe128e0)

It makes the following calls:
	- `enc`: Encodes the passwords.
	- `0x2400`: It is a address in memory.
That is interesting, why would it call to a memory address? Could it be instructions? Before we look into that, let's set a breakpoint there using `break 444a`.

If we step through the function and then check the memory address, we can see that the bytes in memory.

![reykjavik3](https://github.com/Knign/Write-ups/assets/110326359/92d6814a-d77f-4a9e-9a29-200c04211a78)

Let's get a better look using the following command:
```
> R 2400 400
2400 0b12 0412 0441 2452 3150 e0ff 3b40 2045  .....A$R1P..;@ E
2410 073c 1b53 8f11 0f12 0312 b012 6424 2152  .<.S........d$!R
2420 6f4b 4f93 f623 3012 0a00 0312 b012 6424  oKO..#0.......d$
2430 2152 3012 1f00 3f40 dcff 0f54 0f12 2312  !R0...?@...T..#.
2440 b012 6424 3150 0600 b490 e182 dcff 0520  ..d$1P......... 
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

If we clean the bytes, and enter those into the disassembler, we can see the respective assembly instructions.

![reykjavik4](https://github.com/Knign/Write-ups/assets/110326359/e268b200-cbae-4e99-b7e3-68f3f396a267)

There's more instructions but for now let's go through these first.

It seems like the last instruction is comparing the the data at `r4 - 0x24` with `0x82e1`.

Looking at the register state table, we can see the value of `r4`.

![reykjavik5](https://github.com/Knign/Write-ups/assets/110326359/084d200d-7b4d-418a-af8f-0ad49d2d759e)

So the the data that is being compared is from `0x43fe - 0x24` which is `0x43da`.

Let's input our password.

![reykjavik6](https://github.com/Knign/Write-ups/assets/110326359/8ced3473-52b5-41e2-bf80-9ff3ddb387ef)

If we check the locations at which our input is stored we can see that it is also stored at `0x43da`.

![reykjavik7](https://github.com/Knign/Write-ups/assets/110326359/5b381085-5302-4568-a7de-c87bef707171)

Note that for this comparison, the program will interpret the bytes as little endian, so we have to store `0xe182` into memory.

Let's `reset` the program and provide our input.

![reykjavik8](https://github.com/Knign/Write-ups/assets/110326359/42c34b67-9a6a-4c88-911b-78270c35c8a0)

If we `continue` the program execution:

![reykjavik9](https://github.com/Knign/Write-ups/assets/110326359/f034af3a-b6db-47ae-bbbc-febd43bb703c)

Looks like some more engineers are going to be sacked...
