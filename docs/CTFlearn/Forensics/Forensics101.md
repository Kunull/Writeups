---
custom_edit_url: null
---

> Think the flag is somewhere in there. Would you help me find it? https://mega.nz/#!OHohCbTa!wbg60PARf4u6E6juuvK9-aDRe_bgEL937VO01EImM7c

Let's open the link and see what is in the MEGA folder.

![1](https://github.com/Knign/Write-ups/assets/110326359/b758c9c0-5d1c-4469-9dbd-9ec347badd27)

It's an image with a Minion on it. It also has some text but none of it is in the format of our flag.

There are some strings inside of an image file as well. These strings can be extracted using the `strings` utility in Linux.
```
$ strings 95f6edfb66ef42d774a5a34581f19052.jpg 
-- snip --;
flag{wow!_data_is_cool}
-- snip --;
```
Alternatively we can also use the `Strings` operation inside Cyberchef in order to find the flag.

![2](https://github.com/Knign/Write-ups/assets/110326359/c696a487-d531-4c28-a5a3-ea2570ecdf8a)

## Flag
```
flag{wow!_data_is_cool}
```
