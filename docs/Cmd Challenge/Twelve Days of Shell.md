---
custom_edit_url: null
sidebar_position: 3
---

## level 1
> On the first day of Shell my true love gave to me
> A list of files in the directory tree …

```
ls
```

&nbsp;


## level 2
> On the second day of Shell my true love gave to me
> Two lines a-laughing …

```
cat night-before-christmas.txt | grep "laugh"
```

&nbsp;


## level 3
> On the third day of Shell my true love gave to me
> Three lines at the beginning …

```
head -n 3 night-before-christmas.txt
```

&nbsp;

## level 4
> On the fourth day of Shell my true love gave to me
> Four lines at the end …

```
tail -n 4 night-before-christmas.txt
```

&nbsp;

## level 5
> On just about every Unix and Unix-like operating systems there is a command named ls. ls is short for "list" and can be used to list files in your current working directory. Try sending the command ls in the command box to list all files in the directory.

```
cat night-before-christmas.txt | grep -i "^the" 
```

&nbsp;

## level 6
> On the sixth day of Shell my true love gave to me
> Six lines that are exciting! …

```
cat night-before-christmas.txt | grep -i "!" 
```

&nbsp;

## level 7
> On the seventh day of Shell my true love gave to me
> Seven files that start with "Santa" …

```
find Santa* 
```

&nbsp;

## level 8
> On the eighth day of Shell my true love gave to me
> Eight elves in Santa's Workhop/ …

```
mv Elves/* Workshop
```

&nbsp;

## level 9
> On the ninth day of Shell my true love gave to me
> Nine names of Santa's Reindeer …

```
find ./ -type f
```

&nbsp;

## level 10
> On the tenth day of Shell my true love gave to me
> Ten Lords by their names sorted …

```
cat lords.txt | sort
```

&nbsp;

## level 11
> On the eleventh day of Shell my true love gave to me
> Eleven lines with pipers ♫ piping ♫ …

```
find -name "piper" -exec grep piping {} \;
```

&nbsp;

## level 12
> On the eighth day of Shell my true love gave to me
> Eight elves in Santa's Workhop/ …

```
echo "$(<twelve-days-of-shell.txt)"
```
