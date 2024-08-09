---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 2
title: Oops I deleted my bin/ dir :(
---


# level 1
> For now, all you need to do is figure out where you are, print the current working directory.

```
pwd
```

&nbsp;

# level 2
> List all of the files on a single line, in the current working directory.

```
echo *
```

&nbsp;

# level 3
> Oh no! You now remember there is a very important file in this directory. Display its contents before the data is lost for forever!

```
echo "$(<my-dissertation.txt)"
```

&nbsp;

# level 4
> You know there is a process on machine that is deleting files, the first thing you want to do is identify the name of it. Print the name of the process

```
echo "$(</proc/42/cmdline)"
```

&nbsp;

# level 5 
> You managed to save your important file. Now that you know the process name it will be good to kill it before it does any more damanage.

```
kill 42
```
