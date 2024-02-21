---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> Find the flag in the jpeg file. Good Luck!
> [Snowboard.jpg](https://ctflearn.com/challenge/download/934)

![1](https://github.com/Knign/Write-ups/assets/110326359/8f455b82-a5e0-4197-a2af-b2c0cbe0cb2f)

We can use the `exiftool` utility to view the image metadata.
```
$ exiftool 934 | grep "CTFlearn"
Comment                         : CTFlearn{CTFIsEasy!!!}.
```
That however is just a dummy flag.
```
$ strings 934
JFIF
CTFlearn{CTFIsEasy!!!}
Q1RGbGVhcm57U2tpQmFuZmZ9Cg==
-- snip --;
```
