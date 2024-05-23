---
sidebar_position: 2
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## level 1

> - the challenge checks for a specific parent process : bash

```
hacker@program-interaction~level1:/$ /bin/bash
```

```
hacker@program-interaction~level1:/$ /challenge/embryoio_level1 
```

&nbsp;

## level 2

> - the challenge checks for a specific parent process : bash
> - the challenge will check for a hardcoded password over stdin : ohlxdzwk

```
hacker@program-interaction~level2:/$ /bin/bash
```

```
hacker@program-interaction~level2:/$ /challenge/embryoio_level2 
```

&nbsp;

## level 3

> - the challenge checks for a specific parent process : bash
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:zjknqbgpym

```
hacker@program-interaction~level3:/$ /bin/bash
```

```
hacker@program-interaction~level3:/$ /challenge/embryoio_level3 zjknqbgpym
```

&nbsp;

## level 4

> - the challenge checks for a specific parent process : bash
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : eoenyp:erxmsdihin

```
hacker@program-interaction~level4:/$ /bin/bash
```

```
hacker@program-interaction~level4:/$ export eoenyp=erxmsdihin
```

```
hacker@program-interaction~level4:/$ /challenge/embryoio_level4 
```

&nbsp;

## level 5

> - the challenge checks for a specific parent process : bash
> - the challenge will check that input is redirected from a specific file path : /tmp/etgyzz
> - the challenge will check for a hardcoded password over stdin : fzgfqswr

```
hacker@program-interaction~level5:/$ /bin/bash
```

```
hacker@program-interaction~level5:/$ echo "fzgfqswr" > /tmp/etgyzz
```

```
hacker@program-interaction~level5:/$ /challenge/embryoio_level5 < /tmp/etgyzz
```

&nbsp;

## level 6

> - the challenge checks for a specific parent process : bash
> - the challenge will check that output is redirected to a specific file path : /tmp/mriavb

```
hacker@program-interaction~level6:/$ /bin/bash
```

```
hacker@program-interaction~level6:/$ /challenge/embryoio_level6 > /tmp/mriavb
```

```
hacker@program-interaction~level6:/$ cat /tmp/mriavb
```

&nbsp;

## level 7

> - the challenge checks for a specific parent process : bash
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

```
hacker@program-interaction~level7:/$ /bin/bash
```

```
hacker@program-interaction~level7:/$ env -i /challenge/embryoio_level7 
```

&nbsp;

## level 8

> - the challenge checks for a specific parent process : shellscript

```bash.sh
#!/bin/bash

/challenge/embroio_level8
```

```
hacker@program-interaction~level8:~$ bash embryoio8.sh 
```

&nbsp;

## level 9

> - the challenge checks for a specific parent process : shellscript
> - the challenge will check for a hardcoded password over stdin : arstshwf

```bash.sh
#!/bin/bash

/challenge/embryoio_level9
```

```
hacker@program-interaction~level9:~$ bash embryoio9.sh 
```

&nbsp;

## level 10

> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:asbiaaphyn

```bash.sh title="embryoio10.sh"
#!/bin/bash

/challenge/embryoio_level10 asbiaaphyn
```

```
hacker@program-interaction~level10:~$ bash embryoio10.sh 
```

&nbsp;

## level 11

> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : xwzejc:oniobeaqfb

```bash.sh title="embryoio11.sh"
#!/bin/bash

export xwzejc=oniobeaqfb
/challenge/embryoio_level11
```

```
hacker@program-interaction~level11:~$ bash embryoio11.sh 
```

&nbsp;

## level 12

> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that input is redirected from a specific file path : /tmp/kzgaox
> - the challenge will check for a hardcoded password over stdin : bczijbap

```bash.sh title="embryoio12.sh"
#!/bin/bash

echo "bczijbap" > /tmp/kzgaox
/challenge/embryoio_level12 < /tmp/kzgaox
```

```
hacker@program-interaction~level12:~$ bash embryoio12.sh
```

&nbsp;

## level 13

> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that output is redirected to a specific file path : /tmp/umcqpn

```bash.sh title="embryoio13.sh"
#!/bin/bash

/challenge/embryoio_level13 > /tmp/umcqpn
```

```
hacker@program-interaction~level13:~$ nano embryoio13.sh
```

```
hacker@program-interaction~level13:~$ cat /tmp/umcqpn
```

&nbsp;

## level 14

> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

```bash.sh title="embryoio14.sh"
#!/bin/bash

env -i /challenge/embryoio_level14
```

```
hacker@program-interaction~level14:~$ bash embryoio14.sh 
```

&nbsp;

## level 15

> - the challenge checks for a specific parent process : ipython

```
hacker@program-interaction~level15:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

WARNING: your terminal doesn't support cursor position requests (CPR).
In [1]:
```

```python
from pwn import *

p = process(["/challenge/embryoio_level15"])
p.interactive()
```

```python
import subprocess

p = subprocess.Popen(["/challenge/embryoio_level15"]); 
p.communicate()
```

```python
import subprocess  

subprocess.call(["/challenge/embryoio_level15"]);
```

&nbsp;

## level 16

> - the challenge checks for a specific parent process : ipython
> - the challenge will check for a hardcoded password over stdin : dwlvbdjr

```
hacker@program-interaction~level15:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

WARNING: your terminal doesn't support cursor position requests (CPR).
In [1]:
```

```python
from pwn import *

p = process(["/challenge/embryoio_level16"])
p.interactive()
```

```python
import subprocess

p = subprocess.Popen(["/challenge/embryoio_level15"]); 
p.communicate()
```

```python
import subprocess

subprocess.call(["/challenge/embryoio_level16"]);
```

&nbsp;

## level 17

> - the challenge checks for a specific parent process : ipython
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:fkfxeulkjy

```
hacker@program-interaction~level17:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

WARNING: your terminal doesn't support cursor position requests (CPR).
In [1]:
```

```python
from pwn import *

p = process(["/challenge/embryoio_level17", "fkfxeulkjy"])
p.interactive()
```

```python
import subprocess

p = subprocess.Popen(["/challenge/embryoio_level17", "fkfxeulkjy"]); 
p.communicate()
```

```python
import subprocess

subprocess.call(["/challenge/embryoio_level17", "fkfxeulkjy"]);
```

&nbsp;

## level 18

> - the challenge checks for a specific parent process : ipython
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : cnsysl:idndqtahuc

```
hacker@program-interaction~level18:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

WARNING: your terminal doesn't support cursor position requests (CPR).
In [1]:
```

```python
from pwn import *

p = process(["/challenge/embryoio_level18"], env={"cnsysl":"idndqtahuc"})
p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level18"], env={"cnsysl":"idndqtahuc"}); 
p.communicate()
```

```python
import subprocess

subprocess.call(["/challenge/embryoio_level18"], env={"cnsysl":"idndqtahuc"});
```

&nbsp;

## level 19

> - the challenge checks for a specific parent process : ipython
> - the challenge will check that input is redirected from a specific file path : /tmp/etksmq
> - the challenge will check for a hardcoded password over stdin : tbbefvop

```
hacker@program-interaction~level19:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

WARNING: your terminal doesn't support cursor position requests (CPR).
In [1]:
```

```python
from pwn import *
import os

with open("/tmp/etksmq", 'w') as file:
    file.write("tbbefvop")

fd = os.open("/tmp/etksmq", os.O_RDONLY)

p = process(["/challenge/embryoio_level19"], stdin=fd)
p.interactive()
```

We have to open the `/tmp/etksmq` file and write `tbbefvop` to it.
Then we open the file again in `O_RDONLY` mode and save it as `fd` file descriptor.
We then pass this `fd` as STDIN.

```python
import subprocess as sp
import os

with open("/tmp/etksmq", "w") as file:
    file.write("tbbefvop")

fd = os.open("/tmp/etksmq", os.O_RDONLY)

p = sp.Popen(["/challenge/embryoio_level19"], stdin=fd); 
p.communicate()
```

```python
import subprocess
import os

with open("/tmp/etksmq", "w") as file:
    file.write("tbbefvop")

fd = os.open("/tmp/etksmq", os.O_RDONLY)

p = subprocess.call(["/challenge/embryoio_level19"], stdin=fd);
```

&nbsp;

## level 20

> - the challenge checks for a specific parent process : ipython
> - the challenge will check that output is redirected to a specific file path : /tmp/wxngwq

```
hacker@program-interaction~level20:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

WARNING: your terminal doesn't support cursor position requests (CPR).
In [1]:
```

```python
from pwn import *
import os

fd = os.open("/tmp/wxngwq", os.O_WRONLY | os.O_CREAT)

p = process(["/challenge/embryoio_level20"], stdout=fd)

with open("/tmp/wxngwq", "r") as file:
	print(file.read())
p.interactive()
```

This time we open the `/tmp/wxngwq` with the `O_WRONLY` option. We also specify the `O_CREAT` option so that the file will be created if it doesn't already exist.
We then pass this `fd` file descriptor as STDOUT so the program can write to it.
Lastly we just open it file with `r` permissions and print the contents.

```python
import subprocess as sp
import os

fd = os.open("/tmp/wxngwq", os.O_WRONLY | os.O_CREAT)

p = sp.Popen(["/challenge/embryoio_level20"], stdout=fd); 

with open("/tmp/wxngwq", "r") as file:
	print(file.read())
p.communicate()
```

```python
import subprocess
import os

fd = os.open("/tmp/wxngwq", os.O_WRONLY | os.O_CREAT)

p = subprocess.call(["/challenge/embryoio_level20"], stdout=fd); 

with open("/tmp/wxngwq", "r") as file:
	print(file.read())
```

&nbsp;

## level 21

> - the challenge checks for a specific parent process : ipython
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

```
hacker@program-interaction~level21:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

WARNING: your terminal doesn't support cursor position requests (CPR).
In [1]:
```

```python
from pwn import *
import os

p = process(["/challenge/embryoio_level21"], env={})
p.interactive()
```

The `env` parameter is a list. If we keep this list as blank it will we considered as empty.

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level21"], env={}); 
p.communicate()
```

```python
import subprocess

subprocess.call(["/challenge/embryoio_level21"], env={});
```

&nbsp;

## level 22

> - the challenge checks for a specific parent process : python

```python
from pwn import *

p = process(["/challenge/embryoio_level22"])
p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level22"]); 
p.communicate()
```

```python
import subprocess

p = subprocess.call(["/challenge/embryoio_level22"]);
```

```
hacker@program-interaction~level22:~$ python embryoio22.py 
```

&nbsp;

## level 23

> - the challenge checks for a specific parent process : python
> - the challenge will check for a hardcoded password over stdin : ulelosql

```python title="embryoio23.py"
from pwn import *

p = process(["/challenge/embryoio_level23"])
p.interactive()
```

```python title="embryoio23.py"
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level23"]); 
p.communicate()
```

```python title="embryoio23.py"
import subprocess

p = subprocess.call(["/challenge/embryoio_level23"]); 
```

```
hacker@program-interaction~level23:~$ python embryoio23.py 
```

&nbsp;

## level 24

> - the challenge checks for a specific parent process : python
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:ebyhyvaqeu

```python title="embryoio24.py"
from pwn import *

p = process(["/challenge/embryoio_level24", "ebyhyvaqeu"])
p.interactive()
```

```python title="embryoio24.py"
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level24", "ebyhyvaqeu"]); 
p.communicate()
```

```python title="embryoio24.py"
import subprocess

subprocess.call(["/challenge/embryoio_level24", "ebyhyvaqeu"]);
```

```
hacker@program-interaction~level24:~$ python embryoio24.py 
```

&nbsp;

## level 25

> - the challenge checks for a specific parent process : python
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : zxkabi:nuscpaudrt

```python title="embryoio25.py"
from pwn import *

p = process(["/challenge/embryoio_level25"], env={"zxkabi":"nuscpaudrt"})
p.interactive()
```

```python title="embryoio25.py"
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level25"], env={"zxkabi":"nuscpaudrt"}); 
p.communicate()
```

```python title="embryoio25.py"
import subprocess

p = subprocess.call(["/challenge/embryoio_level25"], env={"zxkabi":"nuscpaudrt"});
```

```
hacker@program-interaction~level25:~$ python embryoio25.py 
```

&nbsp;

## level 26

> - the challenge checks for a specific parent process : python
> - the challenge will check that input is redirected from a specific file path : /tmp/touekf
> - the challenge will check for a hardcoded password over stdin : fnzkutbe

```python title="embryoio26.py"
from pwn import *
import os

with open("/tmp/touekf", "w") as file:
    file.write("fnzkutbe")

fd = os.open("/tmp/touekf", os.O_RDONLY)

p = process(["/challenge/embryoio_level26"], stdin=fd)
p.interactive()
```

```python title="embryoio26.py"
import subprocess as sp
import os

with open("/tmp/touekf", "w") as file:
    file.write("fnzkutbe")

fd = os.open("/tmp/touekf", os.O_RDONLY)

p = sp.Popen(["/challenge/embryoio_level26"], stdin=fd); 
p.communicate()
```

```python title="embryoio26.py"
import subprocess
import os

with open("/tmp/touekf", "w") as file:
    file.write("fnzkutbe")

fd = os.open("/tmp/touekf", os.O_RDONLY)

p = subprocess.call(["/challenge/embryoio_level26"], stdin=fd);
```

```
hacker@program-interaction~level26:~$ python embryoio26.py 
```

&nbsp;

## level 27

> - the challenge checks for a specific parent process : python
> - the challenge will check that output is redirected to a specific file path : /tmp/btxtnc

```python title="embryoio27.py"
from pwn import *
import os

fd = os.open("/tmp/btxtnc", os.O_WRONLY | os.O_CREAT)

p = process(["/challenge/embryoio_level27"], stdout=fd)

with open("/tmp/btxtnc", "r") as file:
	print(file.read())
p.interactive()
```

```python title="embryoio27.py"
import subprocess as sp
import os

fd = os.open("/tmp/btxtnc", os.O_WRONLY | os.O_CREAT)

p = sp.Popen(["/challenge/embryoio_level27"], stdout=fd); 

with open("/tmp/btxtnc", "r") as file:
	print(file.read())
p.communicate()
```

```python title="embryoio27.py"
import subprocess
import os

fd = os.open("/tmp/btxtnc", os.O_WRONLY | os.O_CREAT)

p = subprocess.call(["/challenge/embryoio_level27"], stdout=fd); 

with open("/tmp/btxtnc", "r") as file:
	print(file.read())
```

```
hacker@program-interaction~level27:~$ python embryoio27.py 
```

&nbsp;

## level 28

> - the challenge checks for a specific parent process : python
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

```python title="embryoio28.py"
from pwn import *
import os

p = process(["/challenge/embryoio_level28"], env={})

p.interactive()
```

```python title="embryoio28.py"
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level28"], env={}); 
p.communicate()
```

```python title="embryoio28.py"
import subprocess 

p = subprocess.call(["/challenge/embryoio_level28"], env={}); 
```

```
hacker@program-interaction~level28:~$ python embryoio28.py 
```

&nbsp;

## level 29

> - the challenge checks for a specific parent process : binary

```c title="embryoio29.c"
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
	execve("/challenge/embryoio_level29", NULL, NULL);
	exit(0);
}

int main (int argc, char argv[]) {
	pid_t cpid;

	if (fork() == 0) {
		pwncollege();
	}
	else {
		cpid = wait(NULL);
	}

	return 0;
}
```

```c title="embryoio29.c"
#include <stdio.h>
#include <unistd.h>

int main (int argc, char argv[]) {
    int pid;
    int pstat;

    switch(pid = fork()) {
        case -1:
            printf("Error\n");
            break;
        case 0:
            pwncollege();
    }

    waitpid(pid, (int *)&pstat, 0);
    return 0;
}

void pwncollege () {
    execl("/challenge/embryoio_level29", (char *)NULL);
}
```

```
hacker@program-interaction~level29:~$ gcc embryoio29.c -o embryoio29
embryoio29.c: In function ‘main’:
embryoio29.c:12:6: warning: implicit declaration of function ‘fork’ [-Wimplicit-function-declaration]
   12 |  if (fork() == 0) {
      |      ^~~~
embryoio29.c:13:3: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
   13 |   execve(filename, NULL, NULL);
      |   ^~~~~~
embryoio29.c:17:10: warning: implicit declaration of function ‘wait’ [-Wimplicit-function-declaration]
   17 |   cpid = wait(NULL);
      |          ^~~~
```

```
hacker@program-interaction~level29:~$ ./embryoio29 
```

&nbsp;

## level 30

> - the challenge checks for a specific parent process : binary
> - the challenge will check for a hardcoded password over stdin : apyhlmya

```c title="embryoio30.c"
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
	execve("/challenge/embryoio_level30", NULL, NULL);
	exit(0);
}

int main (int argc, char argv[]) {
	pid_t cpid;

	if (fork() == 0) {
		pwncollege();
	}
	else {
		cpid = wait(NULL);
	}

	return 0;
}
```

```c title="embryoio30.c"
#include <stdio.h>
#include <unistd.h>

int main (int argc, char argv[]) {
    int pid;
    int pstat;

    switch(pid = fork()) {
        case -1:
            printf("Error\n");
            break;
        case 0:
            pwncollege();
    }

    waitpid(pid, (int *)&pstat, 0);
    return 0;
}

void pwncollege () {
    execl("/challenge/embryoio_level30", (char *)NULL);
}
```

```
hacker@program-interaction~level30:~$ gcc embryoio30.c -o embryoio30
embryoio30.c: In function ‘main’:
embryoio30.c:12:6: warning: implicit declaration of function ‘fork’ [-Wimplicit-function-declaration]
   12 |  if (fork() == 0) {
      |      ^~~~
embryoio30.c:13:3: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
   13 |   execve(filename, NULL, NULL);
      |   ^~~~~~
embryoio30.c:17:10: warning: implicit declaration of function ‘wait’ [-Wimplicit-function-declaration]
   17 |   cpid = wait(NULL);
      |          ^~~~
```

```
hacker@program-interaction~level30:~$ ./embryoio30 
```

&nbsp;

## level 31

> - the challenge checks for a specific parent process : binary
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:chapeafvrb

```c title="embryoio31.c"
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
	execve(filename, argv, NULL);
    exit(0);
}

int main (int argc, char argv[]) {
    const char filename[100] = "/challenge/embryoio_level31";
    
    pid_t cpid;
 
    char *argv[] = {filename, "chapeafvrb", NULL};

    int newfd;
    dup2(0, newfd);

    if (fork() == 0) {
	    
    }
    else {
        cpid = wait(NULL);
    }

     return 0;
}
```

```c title="embryoio31.c"
#include <stdio.h>
#include <unistd.h>

int main (int argc, char argv[]) {
    int pid;
    int pstat;

    switch(pid = fork()) {
        case -1:
            printf("Error\n");
            break;
        case 0:
            pwncollege();
    }

    waitpid(pid, (int *)&pstat, 0);
    return 0;
}

void pwncollege () {
    execl("/challenge/embryoio_level31", "chapeafvrb", (char *)NULL);
}
```

```
hacker@program-interaction~level31:~$ gcc embryoio31.c -o embryoio31
embryoio31.c: In function ‘main’:
embryoio31.c:12:21: warning: initialization discards ‘const’ qualifier from pointer target type [-Wdiscarded-qualifiers]
   12 |     char *argv[] = {filename, "chapeafvrb", NULL};
      |                     ^~~~~~~~
embryoio31.c:15:5: warning: implicit declaration of function ‘dup2’ [-Wimplicit-function-declaration]
   15 |     dup2(0, newfd);
      |     ^~~~
embryoio31.c:17:9: warning: implicit declaration of function ‘fork’ [-Wimplicit-function-declaration]
   17 |     if (fork() == 0) {
      |         ^~~~
embryoio31.c:18:6: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
   18 |      execve(filename, argv, NULL);
      |      ^~~~~~
embryoio31.c:22:16: warning: implicit declaration of function ‘wait’ [-Wimplicit-function-declaration]
   22 |         cpid = wait(NULL);
      |                ^~~~
```

```
hacker@program-interaction~level31:~$ ./embryoio31 
```

&nbsp;

## level 32

> - the challenge checks for a specific parent process : binary
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : mrsqev:oaxcmkzbmf

```c title="embryoio32.c"
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
}

int main () {
    const char filename[100] = "/challenge/embryoio_level32";
    
    pid_t cpid;
 
    char *envp[] = {"mrsqev=oaxcmkzbmf", NULL};

    int newfd;
    dup2(0, newfd);

    if (fork() == 0) {
	    execve(filename, NULL, envp);
        exit(0);
    }
    else {
        cpid = wait(NULL);
    }

     return 0;
}
```

```c title="embryoio32.c"
#include <stdio.h>
#include <unistd.h>

int main (int argc, char argv[]) {
    int pid;
    int pstat;
    
    switch(pid = fork()) {
        case -1:
            printf("Error\n");
        case 0:
            pwncollege();
    }

    waitpid(pid, (int *)&pstat, 0);
    return 0;
}

void pwncollege () {
    setenv("mrsqev", "oaxcmkzbmf", 1);
    execl("/challenge/embryoio_level32", (char *)NULL);
}
```


```
hacker@program-interaction~level32:~$ gcc embryoio32.c -o embryoio32
embryoio32.c: In function ‘main’:
embryoio32.c:15:5: warning: implicit declaration of function ‘dup2’ [-Wimplicit-function-declaration]
   15 |     dup2(0, newfd);
      |     ^~~~
embryoio32.c:17:9: warning: implicit declaration of function ‘fork’ [-Wimplicit-function-declaration]
   17 |     if (fork() == 0) {
      |         ^~~~
embryoio32.c:18:6: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
   18 |      execve(filename, NULL, envp);
      |      ^~~~~~
embryoio32.c:22:16: warning: implicit declaration of function ‘wait’ [-Wimplicit-function-declaration]
   22 |         cpid = wait(NULL);
      |                ^~~~
```

```
hacker@program-interaction~level32:~$ ./embryoio32 
```

&nbsp;

## level 33

> - the challenge checks for a specific parent process : binary
> - the challenge will check that input is redirected from a specific file path : /tmp/brxhzr
> - the challenge will check for a hardcoded password over stdin : trimcsgm

```c title="embryoio33.c"
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
	execve("/challenge/embryoio_level33", NULL, NULL);
	exit(0);
}

int main (int argc, char argv[]) {
	pid_t cpid;
    FILE *fptr;

    fptr = fopen("/tmp/brxhzr", "w");  
    fprintf(fptr, "trimcsgm");  
    fclose(fptr);

	freopen("/tmp/brxhzr", "r", stdin);

	if (fork() == 0) {
		pwncollege();
	}
	else {
		cpid = wait(NULL);
	}

	return 0;
}
```

```c title="embryoio33.c"
#include <stdio.h>
#include <unistd.h>

int main (int argc, char argv[]) {
    int pid;
    int pstat;
    int fd;
    FILE *fptr;

    fptr = fopen("/tmp/brxhzr", "w");  
    fprintf(fptr, "trimcsgm");  
    fclose(fptr);

    freopen("/tmp/brxhzr", "r", stdin);
    
    switch(pid = fork()) {
        case -1:
            printf("Error\n");
        case 0:
            pwncollege();
    }

    waitpid(pid, (int *)&pstat, 0);
    return 0;
}

void pwncollege () {
    execl("/challenge/embryoio_level33", (char *)NULL);
}
```

```
hacker@program-interaction~level34:~$ gcc embryoio33.c -o embryoio33
```

```
hacker@program-interaction~level34:~$ ./embryoio33
```

&nbsp;

## level 34

> - the challenge checks for a specific parent process : binary
> - the challenge will check that output is redirected to a specific file path : /tmp/cigexf

```c title="embryoio34.c"
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
	execve("/challenge/embryoio_level34", NULL, NULL);
	exit(0);
}

int main (int argc, char argv[]) {
	pid_t cpid;

	freopen("/tmp/cigexf", "w", stdout);

	if (fork() == 0) {
		pwncollege();
	}
	else {
		cpid = wait(NULL);
	}

	return 0;
}
```

```c title="embryoio34.c"
#include <stdio.h>
#include <unistd.h>

int main (int argc, char argv[]) {
    int pid;
    int pstat;
    int fd;

    freopen("/tmp/cigexf", "w", stdout);
  
    switch(pid = fork()) {
        case -1:
            printf("Error\n");
        case 0:
            pwncollege();
    }

    waitpid(pid, (int *)&pstat, 0);
    return 0;
}

void pwncollege () {
    execl("/challenge/embryoio_level34", (char *)NULL);
}
```

```
hacker@program-interaction~level34:~$ gcc embryoio34.c -o embryoio34
```

```
hacker@program-interaction~level34:~$ ./embryoio34
```

```
hacker@program-interaction~level34:~$ cat /tmp/cigexf
```

&nbsp;

## level 35

> - the challenge checks for a specific parent process : binary
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

```c title="embryoio35.c"
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
}

int main () {
    const char filename[100] = "/challenge/embryoio_level35";
    
    pid_t cpid;
 
    char *envp[] = {"mrsqev=oaxcmkzbmf", NULL};

    int newfd;
    dup2(0, newfd);

    if (fork() == 0) {
	    execve(filename, NULL, envp);
        exit(0);
    }
    else {
        cpid = wait(NULL);
    }

     return 0;
}
```

```c title="embryoio35.c"
#include <stdio.h>
#include <unistd.h>

int main (int argc, char argv[]) {
    int pid;
    int pstat;

    switch(pid = fork()) {
        case -1:
            printf("Error\n");
            break;
        case 0:
            pwncollege();
    }

    waitpid(pid, (int *)&pstat, 0);
    return 0;
}

void pwncollege () {
    char *empty_env[] = { NULL };
    execle("/challenge/embryoio_level35", "/challenge/embryoio_level35", (char *)NULL, empty_env);
}
```

```
hacker@program-interaction~level35:~$ gcc embryoio35.c -o embryoio35
```

```
hacker@program-interaction~level35:~$ ./embryoio35
```

&nbsp;

## level 36

> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdout : cat

```
hacker@program-interaction~level36:/$ /bin/bash
```

```
hacker@program-interaction~level36:/$ /challenge/embryoio_level36 | cat
```

&nbsp;

## level 37

> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdout : grep

```
hacker@program-interaction~level37:/$ /bin/bash
```

```
hacker@program-interaction~level37:/$ /challenge/embryoio_level37 | grep "pwn.college"
```

&nsbsp;

## level 38

> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdout : sed

```
acker@program-interaction~level38:/$ /bin/bash
```

```
hacker@program-interaction~level38:/$ /challenge/embryoio_level38 | sed 's/ / /'
```

&nbsp;

## level 39

> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdout : rev

```
hacker@program-interaction~level39:/$ /bin/bash
```

```
hacker@program-interaction~level39:/$ /challenge/embryoio_level39 | rev | rev
```

&nbsp;

## level 40

> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdin : cat
> - the challenge will check for a hardcoded password over stdin : ltpwrbhw

```
hacker@program-interaction~level40:/$ /bin/bash 
```

```
hacker@program-interaction~level40:/$ cat | /challenge/embryoio_level40 
```

&nbsp;

## level 41

> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdin : rev
> - the challenge will check for a hardcoded password over stdin : vnyeyriu

```
hacker@program-interaction~level41:/$ /bin/bash
```

```
hacker@program-interaction~level41:/$ rev | rev | /challenge/embryoio_level41 
```

&nbsp;

## level 42

> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdout : cat

```bash title="embryoio42.sh"
#!/bin/bash

/challenge/embryoio_level42 | cat
```

```
hacker@program-interaction~level42:~$ bash embryoio42.sh
```

&nbsp;

## level 43

> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdout : grep

```bash title="embryoio43.sh"
#!/bin/sh

/challenge/embryoio_level43 | grep "pwn"
```

```
hacker@program-interaction~level43:~$ bash embryoio43.sh
```

&nbsp;

## level 44

> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdout : sed

```bash title="embryoio44.sh"
#!/bin/sh

/challenge/embryoio_level44 | sed -n "/pwn/p"
```

```
hacker@program-interaction~level44:~$ bash embryoio44.sh
```

&nbsp;

## level 45

> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdout : rev

```bash title="embryoio45.sh"
#!/bin/sh

/challenge/embryoio_level45 | rev | rev
```

```
hacker@program-interaction~level45:~$ bash embryoio45.sh 
```

&nbsp;

## level 46

> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdin : cat
> - the challenge will check for a hardcoded password over stdin : hukyaqik

```bash title="embryoio46.sh"
#!/bin/bash

cat | /challenge/embryoio_level42
```

```
hacker@program-interaction~level46:~$ bash embryoio46.sh 
```

&nbsp;

## level 47

> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdin : rev
> - the challenge will check for a hardcoded password over stdin : xpiyvdor

```bash title="embryoio47.sh"
#!/bin/bash

rev | rev | /challenge/embryoio_level47
```

```
hacker@program-interaction~level47:~$ bash embryoio47.sh 
```

&nbsp;

## level 48

> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdout : cat

```
hacker@program-interaction~level48:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

In [1]: 
```

```python
from pwn import *

p = process(["/challenge/embryoio_level48"], stdout=PIPE); 
p2 = process(["/usr/bin/cat"], stdout=p.stdout);
p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level48"], stdout=sp.PIPE); 
p2 = sp.Popen(["/usr/bin/cat"], stdin=p.stdout);
p2.communicate()
```

&nbsp;

## level 49

> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdout : grep

```
hacker@program-interaction~level49:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

In [1]:
```

```python
from pwn import *

p = process(["/challenge/embryoio_level49"], stdout=PIPE); 
p2 = process(["/usr/bin/grep", "pwn"], stdout=p.stdout);
p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level49"], stdout=sp.PIPE); 
p2 = sp.Popen(["/usr/bin/grep", "pwn"], stdin=p.stdout);
p2.communicate()
```

&nbsp;

## level 50

> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdout : sed

```
hacker@program-interaction~level50:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

In [1]:
```

```python
from pwn import *

p = process(["/challenge/embryoio_level50"], stdout=PIPE); 
p2 = process(["/usr/bin/sed", "-n", "/pwn/p"], stdout=p.stdout);
p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level50"], stdout=sp.PIPE); 
p2 = sp.Popen(["/usr/bin/sed", "-n", "/pwn/p"], stdin=p.stdout);
p2.communicate()
```

&nbsp;

## level 51

> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdout : rev

```
hacker@program-interaction~level51:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

In [1]: 
```

```python
from pwn import *

p = process(["/challenge/embryoio_level51"], stdout=PIPE); 
p2 = process(["/usr/bin/rev"], stdout=p.stdout);
p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level51"], stdout=sp.PIPE); 
p2 = sp.Popen(["/usr/bin/rev"], stdin=p.stdout, stdout=sp.PIPE);
p3 = sp.Popen(["/usr/bin/rev"], stdin=p2.stdout);
p3.communicate()
```

&nbsp;

## level 52

> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdin : cat
> - the challenge will check for a hardcoded password over stdin : nlcncamf

```
hacker@program-interaction~level52:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

In [1]:
```

```python
from pwn import *

p = process(["/usr/bin/cat"], stdout=PIPE);
p2 = process(["/challenge/embryoio_level52"], stdout=p.stdout); 
p2.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/usr/bin/cat"], stdout=sp.PIPE);
p2 = sp.Popen(["/challenge/embryoio_level52"], stdin=p.stdout); 
p2.communicate()
```

&nbsp;

## level 53

> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdin : rev
> - the challenge will check for a hardcoded password over stdin : piamnajl

```
hacker@program-interaction~level53:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

In [1]:
```

```python
from pwn import *

p = process(["/usr/bin/rev"], stdout=PIPE);
p2 = process(["/challenge/embryoio_level53"], stdout=p.stdout); 
p2.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/usr/bin/rev"], stdout=sp.PIPE);
p2 = sp.Popen(["/usr/bin/rev"], stdin=p.stdout, stdout=sp.PIPE);
p3 = sp.Popen(["/challenge/embryoio_level53"], stdin=p2.stdout); 
p3.communicate()
```

&nbsp;

## level 54

> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdout : cat

```python title="embryoio54.py"
from pwn import *

p = process(["/challenge/embryoio_level54"], stdout=PIPE); 
p2 = process(["/usr/bin/cat"], stdout=p.stdout);
p.interactive()
```

```python title="embryoio54.py"
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level54"], stdout=sp.PIPE); 
p2 = sp.Popen(["/usr/bin/cat"], stdin=p.stdout);
p2.communicate()
```

```
hacker@program-interaction~level54:~$ python embryoio54.py 
```

&nbsp;

## level 55

> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdout : grep

```python title="embryoio55.py"
from pwn import *

p = process(["/challenge/embryoio_level55"], stdout=PIPE); 
p2 = process(["/usr/bin/grep", "pwn.college"], stdout=p.stdout);
p.interactive()
```

```python title="embryoio55.py"
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level55"], stdout=sp.PIPE); 
p2 = sp.Popen(["/usr/bin/grep", "pwn.college"], stdin=p.stdout);
p2.communicate()
```

```
hacker@program-interaction~level55:~$ python embryoio55.py
```

&nbsp;

## level 56

> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdout : sed

```python title="embryoio56.py"
from pwn import *

p = process(["/challenge/embryoio_level56"], stdout=PIPE); 
p2 = process(["/usr/bin/sed", "-n", "/pwn/p"], stdout=p.stdout);
p.interactive()
```

```python title="embryoio56.py"
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level56"], stdout=sp.PIPE); 
p2 = sp.Popen(["/usr/bin/sed", "-n", "/pwn/p"], stdin=p.stdout);
p2.communicate()
```

```
hacker@program-interaction~level56:/$ python embryoio56.py
```

&nbsp;

## level 57

> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdout : rev

```python title="embryoio57.py"
from pwn import *

p = process(["/challenge/embryoio_level57"], stdout=PIPE); 
p2 = process(["/usr/bin/rev"], stdout=p.stdout);
p.interactive()
```

```python title="embryoio57.py"
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level57"], stdout=sp.PIPE); 
p2 = sp.Popen(["/usr/bin/rev"], stdin=p.stdout, stdout=sp.PIPE);
p3 = sp.Popen(["/usr/bin/rev"], stdin=p2.stdout);
p3.communicate()
```

```
hacker@program-interaction~level57:/$ python embryoio57.py
```

&nbsp;

## level 58

> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdin : cat
> - the challenge will check for a hardcoded password over stdin : yhjdoqbb

```python title="embryoio58.py"
from pwn import *

p = process(["/usr/bin/cat"], stdout=PIPE);
p2 = process(["/challenge/embryoio_level58"], stdout=p.stdout); 
p2.interactive()
```

```python title="embryoio58.py"
import subprocess as sp

p = sp.Popen(["/usr/bin/cat"], stdout=sp.PIPE);
p2 = sp.Popen(["/challenge/embryoio_level58"], stdin=p.stdout); 
p2.communicate()
```

```
hacker@program-interaction~level58:/$ python embryoio58.py
```

&nbsp;

## level 59

> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdin : rev
> - the challenge will check for a hardcoded password over stdin : qxfrhkpq

```python title="embryoio59.py"
from pwn import *

p = process(["/usr/bin/rev"], stdout=PIPE);
p2 = process(["/challenge/embryoio_level59"], stdout=p.stdout); 
p2.interactive()
```

```python title="embryoio59.py"
import subprocess as sp

p = sp.Popen(["/usr/bin/rev"], stdout=sp.PIPE);
p2 = sp.Popen(["/usr/bin/rev"], stdin=p.stdout, stdout=sp.PIPE);
p3 = sp.Popen(["/challenge/embryoio_level59"], stdin=p2.stdout); 
p.communicate()
```

```
hacker@program-interaction~level59:~$ python embryoio59.py 
```
