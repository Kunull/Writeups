---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> Pay attention to those strings!
> [PikesPeak.jpg](https://ctflearn.com/challenge/download/935)

We can use the `strings` utility in order to view all the strings present in the image which length more than 4 characters.
```
$ strings 935
JFIF
CTFLEARN{PikesPeak}
CTFLearn{Colorado}
%ctflearn{MountainMountainMountain}
#cTfLeArN{CTFMountainCTFmOUNTAIN}
CTF{AsPEN.Vail}
CTFlearn{Gandalf}
ctflearning{AUCKLAND}
ctfLEARN{MtDoom}
6ctflearninglearning{Mordor.TongariroAlpineCrossing}
+CTFLEARN{MountGedePangrangoNationalPark}
$ctflearncTfLeARN{MountKosciuszko}
-- snip --;
```
Only one of the flags present are in the correct format.
## Flag
```
CTFlearn{Gandalf}
```
