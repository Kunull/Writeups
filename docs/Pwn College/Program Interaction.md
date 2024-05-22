---
sidebar_position: 2
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

## level 1

```
hacker@program-interaction~level1:/$ /challenge/embryoio_level1 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : bash

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is the bash shell. If this is a check for the parent process, then,
[TEST] most likely, this is what you do by default anyways, but we'll check just in case...
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be bash.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be running in its default, interactive mode (/bin/bash with no commandline arguments). Your commandline arguments are: ['/bin/bash', '--init-file', '/usr/lib/code-server/lib/vscode/out/vs/workbench/contrib/terminal/browser/media/shellIntegration-bash.sh']
```

```
hacker@program-interaction~level1:/$ /bin/bash
```

```
hacker@program-interaction~level1:/$ /challenge/embryoio_level1 
```

&nbsp;

## level 2

```
hacker@program-interaction~level2:/$ /challenge/embryoio_level2 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : bash
- the challenge will check for a hardcoded password over stdin : ohlxdzwk

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is the bash shell. If this is a check for the parent process, then,
[TEST] most likely, this is what you do by default anyways, but we'll check just in case...
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be bash.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be running in its default, interactive mode (/bin/bash with no commandline arguments). Your commandline arguments are: ['/bin/bash', '--init-file', '/usr/lib/code-server/lib/vscode/out/vs/workbench/contrib/terminal/browser/media/shellIntegration-bash.sh']
```

```
hacker@program-interaction~level2:/$ /bin/bash
```

```
hacker@program-interaction~level2:/$ /challenge/embryoio_level2 
```

&nbsp;

## level 3

```
hacker@program-interaction~level3:/$ /challenge/embryoio_level3 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : bash
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:zjknqbgpym

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is the bash shell. If this is a check for the parent process, then,
[TEST] most likely, this is what you do by default anyways, but we'll check just in case...
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be bash.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be running in its default, interactive mode (/bin/bash with no commandline arguments). Your commandline arguments are: ['/bin/bash', '--init-file', '/usr/lib/code-server/lib/vscode/out/vs/workbench/contrib/terminal/browser/media/shellIntegration-bash.sh']
```

```
hacker@program-interaction~level3:/$ /bin/bash
```

```
hacker@program-interaction~level3:/$ /challenge/embryoio_level3 zjknqbgpym
```

&nbsp;

## level 4

```
hacker@program-interaction~level4:/$ /challenge/embryoio_level4 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : bash
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : eoenyp:erxmsdihin

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is the bash shell. If this is a check for the parent process, then,
[TEST] most likely, this is what you do by default anyways, but we'll check just in case...
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be bash.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be running in its default, interactive mode (/bin/bash with no commandline arguments). Your commandline arguments are: ['/bin/bash', '--init-file', '/usr/lib/code-server/lib/vscode/out/vs/workbench/contrib/terminal/browser/media/shellIntegration-bash.sh']
```

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

```
hacker@program-interaction~level5:/$ /challenge/embryoio_level5 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : bash
- the challenge will check that input is redirected from a specific file path : /tmp/etgyzz
- the challenge will check for a hardcoded password over stdin : fzgfqswr

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is the bash shell. If this is a check for the parent process, then,
[TEST] most likely, this is what you do by default anyways, but we'll check just in case...
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be bash.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be running in its default, interactive mode (/bin/bash with no commandline arguments). Your commandline arguments are: ['/bin/bash', '--init-file', '/usr/lib/code-server/lib/vscode/out/vs/workbench/contrib/terminal/browser/media/shellIntegration-bash.sh']
```

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

```
hacker@program-interaction~level6:/$ /challenge/embryoio_level6 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : bash
- the challenge will check that output is redirected to a specific file path : /tmp/mriavb

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is the bash shell. If this is a check for the parent process, then,
[TEST] most likely, this is what you do by default anyways, but we'll check just in case...
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be bash.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be running in its default, interactive mode (/bin/bash with no commandline arguments). Your commandline arguments are: ['/bin/bash', '--init-file', '/usr/lib/code-server/lib/vscode/out/vs/workbench/contrib/terminal/browser/media/shellIntegration-bash.sh']
```

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

```
hacker@program-interaction~level7:/$ /challenge/embryoio_level7 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : bash
- the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is the bash shell. If this is a check for the parent process, then,
[TEST] most likely, this is what you do by default anyways, but we'll check just in case...
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be bash.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be running in its default, interactive mode (/bin/bash with no commandline arguments). Your commandline arguments are: ['/bin/bash', '--init-file', '/usr/lib/code-server/lib/vscode/out/vs/workbench/contrib/terminal/browser/media/shellIntegration-bash.sh']
```

```
hacker@program-interaction~level7:/$ /bin/bash
```

```
hacker@program-interaction~level7:/$ env -i /challenge/embryoio_level7 
```

&nbsp;

## level 8

```
hacker@program-interaction~level8:/$ /challenge/embryoio_level8 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : shellscript

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is a non-interactive shell script.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

```bash.sh
#!/bin/bash

/challenge/embroio_level8
```

```
hacker@program-interaction~level8:~$ bash embryoio8.sh 
```

&nbsp;

## level 9

```
hacker@program-interaction~level9:/$ /challenge/embryoio_level9 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : shellscript
- the challenge will check for a hardcoded password over stdin : arstshwf

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is a non-interactive shell script.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

```bash.sh
#!/bin/bash

/challenge/embryoio_level9
```

```
hacker@program-interaction~level9:~$ bash embryoio9.sh 
```

&nbsp;

## level 10

```
hacker@program-interaction~level10:/$ /challenge/embryoio_level10 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : shellscript
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:asbiaaphyn

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is a non-interactive shell script.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

```bash.sh
#!/bin/bash

/challenge/embryoio_level10 asbiaaphyn
```

```
hacker@program-interaction~level10:~$ bash embryoio10.sh 
```

&nbsp;

## level 11

```
hacker@program-interaction~level11:/$ /challenge/embryoio_level11 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : shellscript
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : xwzejc:oniobeaqfb

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is a non-interactive shell script.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

```bash.sh
#!/bin/bash

export xwzejc=oniobeaqfb
/challenge/embryoio_level11
```

```
hacker@program-interaction~level11:~$ bash embryoio11.sh 
```

&nbsp;

## level 12

```
hacker@program-interaction~level12:/$ /challenge/embryoio_level12 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : shellscript
- the challenge will check that input is redirected from a specific file path : /tmp/kzgaox
- the challenge will check for a hardcoded password over stdin : bczijbap

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is a non-interactive shell script.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

```bash.sh
#!/bin/bash

echo "bczijbap" > /tmp/kzgaox
/challenge/embryoio_level12 < /tmp/kzgaox
```

```
hacker@program-interaction~level12:~$ bash embryoio12.sh
```

&nbsp;

## level 13

```
hacker@program-interaction~level13:/$ /challenge/embryoio_level13 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : shellscript
- the challenge will check that output is redirected to a specific file path : /tmp/umcqpn

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is a non-interactive shell script.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

```bash.sh
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

```
hacker@program-interaction~level14:/$ /challenge/embryoio_level14 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : shellscript
- the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure the process is a non-interactive shell script.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The shell process must be executing a shell script that you wrote like this: `bash my_script.sh`
```

```bash.sh
#!/bin/bash

env -i /challenge/embryoio_level14
```

```
hacker@program-interaction~level14:~$ bash embryoio14.sh 
```

&nbsp;

## level 15

```
hacker@program-interaction~level15:/$ /challenge/embryoio_level15 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : ipython

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is an interactive ipython instance.

[INFO] Since ipython runs as a script inside python, this will check a few things:
[INFO] 1. That the process itself is python.
[INFO] 2. That the module being run in python is ipython.
[INFO] If the process being checked is just a normal 'ipython', you'll be okay!

[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

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

```
hacker@program-interaction~level16:/$ /challenge/embryoio_level16 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : ipython
- the challenge will check for a hardcoded password over stdin : dwlvbdjr

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is an interactive ipython instance.

[INFO] Since ipython runs as a script inside python, this will check a few things:
[INFO] 1. That the process itself is python.
[INFO] 2. That the module being run in python is ipython.
[INFO] If the process being checked is just a normal 'ipython', you'll be okay!

[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

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

```
hacker@program-interaction~level17:/$ /challenge/embryoio_level17 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : ipython
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:fkfxeulkjy

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is an interactive ipython instance.

[INFO] Since ipython runs as a script inside python, this will check a few things:
[INFO] 1. That the process itself is python.
[INFO] 2. That the module being run in python is ipython.
[INFO] If the process being checked is just a normal 'ipython', you'll be okay!

[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

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

```
hacker@program-interaction~level18:/$ /challenge/embryoio_level18 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : ipython
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : cnsysl:idndqtahuc

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is an interactive ipython instance.

[INFO] Since ipython runs as a script inside python, this will check a few things:
[INFO] 1. That the process itself is python.
[INFO] 2. That the module being run in python is ipython.
[INFO] If the process being checked is just a normal 'ipython', you'll be okay!

[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

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

```
hacker@program-interaction~level19:/$ /challenge/embryoio_level19 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : ipython
- the challenge will check that input is redirected from a specific file path : /tmp/etksmq
- the challenge will check for a hardcoded password over stdin : tbbefvop

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is an interactive ipython instance.

[INFO] Since ipython runs as a script inside python, this will check a few things:
[INFO] 1. That the process itself is python.
[INFO] 2. That the module being run in python is ipython.
[INFO] If the process being checked is just a normal 'ipython', you'll be okay!

[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

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

```
hacker@program-interaction~level20:/$ /challenge/embryoio_level20 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : ipython
- the challenge will check that output is redirected to a specific file path : /tmp/wxngwq

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is an interactive ipython instance.

[INFO] Since ipython runs as a script inside python, this will check a few things:
[INFO] 1. That the process itself is python.
[INFO] 2. That the module being run in python is ipython.
[INFO] If the process being checked is just a normal 'ipython', you'll be okay!

[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

```
hacker@program-interaction~level20:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

WARNING: your terminal doesn't support cursor position requests (CPR).
In [1]:
```

```python.py
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

```python.py
import subprocess as sp
import os

fd = os.open("/tmp/wxngwq", os.O_WRONLY | os.O_CREAT)

p = sp.Popen(["/challenge/embryoio_level20"], stdout=fd); 

with open("/tmp/wxngwq", "r") as file:
	print(file.read())
p.communicate()
```

```python.py
import subprocess
import os

fd = os.open("/tmp/wxngwq", os.O_WRONLY | os.O_CREAT)

p = subprocess.call(["/challenge/embryoio_level20"], stdout=fd); 

with open("/tmp/wxngwq", "r") as file:
	print(file.read())
```

&nbsp;

## level 21

```
hacker@program-interaction~level21:/$ /challenge/embryoio_level21 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : ipython
- the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is an interactive ipython instance.

[INFO] Since ipython runs as a script inside python, this will check a few things:
[INFO] 1. That the process itself is python.
[INFO] 2. That the module being run in python is ipython.
[INFO] If the process being checked is just a normal 'ipython', you'll be okay!

[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

```
hacker@program-interaction~level21:/$ ipython
Python 3.8.10 (default, Nov 22 2023, 10:22:35) 
Type 'copyright', 'credits' or 'license' for more information
IPython 8.12.3 -- An enhanced Interactive Python. Type '?' for help.

WARNING: your terminal doesn't support cursor position requests (CPR).
In [1]:
```

```python.py
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

```
hacker@program-interaction~level22:/$ /challenge/embryoio_level22 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : python

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is a non-interactive python instance (i.e., an executing python script).
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

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

```
hacker@program-interaction~level23:/$ /challenge/embryoio_level23 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : python
- the challenge will check for a hardcoded password over stdin : ulelosql

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is a non-interactive python instance (i.e., an executing python script).
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

```python
from pwn import *

p = process(["/challenge/embryoio_level23"])
p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level23"]); 
p.communicate()
```

```python
import subprocess

p = subprocess.call(["/challenge/embryoio_level23"]); 
```

```
hacker@program-interaction~level23:~$ python embryoio23.py 
```

&nbsp;

## level 24

```
hacker@program-interaction~level24:/$ /challenge/embryoio_level24 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : python
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:ebyhyvaqeu

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is a non-interactive python instance (i.e., an executing python script).
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

```python
from pwn import *

p = process(["/challenge/embryoio_level24", "ebyhyvaqeu"])
p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level24", "ebyhyvaqeu"]); 
p.communicate()
```

```python
import subprocess

subprocess.call(["/challenge/embryoio_level24", "ebyhyvaqeu"]);
```

```
hacker@program-interaction~level24:~$ python embryoio24.py 
```

&nbsp;

## level 25

```
hacker@program-interaction~level25:/$ /challenge/embryoio_level25 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : python
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : zxkabi:nuscpaudrt

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is a non-interactive python instance (i.e., an executing python script).
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

```python
from pwn import *

p = process(["/challenge/embryoio_level25"], env={"zxkabi":"nuscpaudrt"})
p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level25"], env={"zxkabi":"nuscpaudrt"}); 
p.communicate()
```

```python
import subprocess

p = subprocess.call(["/challenge/embryoio_level25"], env={"zxkabi":"nuscpaudrt"});
```

```
hacker@program-interaction~level25:~$ python embryoio25.py 
```

&nbsp;

## level 26

```
hacker@program-interaction~level26:/$ /challenge/embryoio_level26 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : python
- the challenge will check that input is redirected from a specific file path : /tmp/touekf
- the challenge will check for a hardcoded password over stdin : fnzkutbe

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is a non-interactive python instance (i.e., an executing python script).
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

```python
from pwn import *
import os

with open("/tmp/touekf", "w") as file:
    file.write("fnzkutbe")

fd = os.open("/tmp/touekf", os.O_RDONLY)

p = process(["/challenge/embryoio_level26"], stdin=fd)
p.interactive()
```

```python
import subprocess as sp
import os

with open("/tmp/touekf", "w") as file:
    file.write("fnzkutbe")

fd = os.open("/tmp/touekf", os.O_RDONLY)

p = sp.Popen(["/challenge/embryoio_level26"], stdin=fd); 
p.communicate()
```

```python
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

```
hacker@program-interaction~level27:/$ /challenge/embryoio_level27 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : python
- the challenge will check that output is redirected to a specific file path : /tmp/btxtnc

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is a non-interactive python instance (i.e., an executing python script).
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

```python
from pwn import *
import os

fd = os.open("/tmp/btxtnc", os.O_WRONLY | os.O_CREAT)

p = process(["/challenge/embryoio_level27"], stdout=fd)

with open("/tmp/btxtnc", "r") as file:
	print(file.read())
p.interactive()
```

```python
import subprocess as sp
import os

fd = os.open("/tmp/btxtnc", os.O_WRONLY | os.O_CREAT)

p = sp.Popen(["/challenge/embryoio_level27"], stdout=fd); 

with open("/tmp/btxtnc", "r") as file:
	print(file.read())
p.communicate()
```

```python
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

```
hacker@program-interaction~level28:/$ /challenge/embryoio_level28 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : python
- the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] We will now check that that the process is a non-interactive python instance (i.e., an executing python script).
[INFO] The process' executable is /usr/bin/bash.
[INFO] This might be different than expected because of symbolic links (for example, from /usr/bin/python to /usr/bin/python3 to /usr/bin/python3.8).
[INFO] To pass the checks, the executable must be python3.8.
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    Executable must be 'python'. Yours is: bash
```

```python
from pwn import *
import os

p = process(["/challenge/embryoio_level28"], env={})

p.interactive()
```

```python
import subprocess as sp

p = sp.Popen(["/challenge/embryoio_level28"], env={}); 
p.communicate()
```

```python
import subprocess 

p = subprocess.call(["/challenge/embryoio_level28"], env={}); 
```

```
hacker@program-interaction~level28:~$ python embryoio28.py 
```

&nbsp;

## level 29

```
hacker@program-interaction~level29:/$ /challenge/embryoio_level29 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : binary

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure that the process is a custom binary that you created by compiling a C program
[TEST] that you wrote. Make sure your C program has a function called 'pwncollege' in it --- otherwise,
[TEST] it won't pass the checks.
[HINT] If this is a check for the *parent* process, keep in mind that the exec() family of system calls
[HINT] does NOT result in a parent-child relationship. The exec()ed process simply replaces the exec()ing
[HINT] process. Parent-child relationships are created when a process fork()s off a child-copy of itself,
[HINT] and the child-copy can then execve() a process that will be the new child. If we're checking for a
[HINT] parent process, that's how you make that relationship.
[INFO] The executable that we are checking is: /usr/bin/bash.
[HINT] One frequent cause of the executable unexpectedly being a shell or docker-init is that your
[HINT] parent process terminated before this check was run. This happens when your parent process launches
[HINT] the child but does not wait on it! Look into the waitpid() system call to wait on the child!

[HINT] Another frequent cause is the use of system() or popen() to execute the challenge. Both will actually
[HINT] execute a shell that will then execute the challenge, so the parent of the challenge will be that
[HINT] shell, rather than your program. You must use fork() and one of the exec family of functions (execve(),
[HINT] execl(), etc).
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The process must be your own program in your own home directory.
```

```c
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
}

int main () {
	const char filename[100] = "/challenge/embryoio_level29";

	pid_t cpid;

	if (fork() == 0) {
		execve(filename, NULL, NULL);
		exit(0);
	}
	else {
		cpid = wait(NULL);
	}

	return 0;
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

```
hacker@program-interaction~level30:/$ /challenge/embryoio_level30 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : binary
- the challenge will check for a hardcoded password over stdin : apyhlmya

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure that the process is a custom binary that you created by compiling a C program
[TEST] that you wrote. Make sure your C program has a function called 'pwncollege' in it --- otherwise,
[TEST] it won't pass the checks.
[HINT] If this is a check for the *parent* process, keep in mind that the exec() family of system calls
[HINT] does NOT result in a parent-child relationship. The exec()ed process simply replaces the exec()ing
[HINT] process. Parent-child relationships are created when a process fork()s off a child-copy of itself,
[HINT] and the child-copy can then execve() a process that will be the new child. If we're checking for a
[HINT] parent process, that's how you make that relationship.
[INFO] The executable that we are checking is: /usr/bin/bash.
[HINT] One frequent cause of the executable unexpectedly being a shell or docker-init is that your
[HINT] parent process terminated before this check was run. This happens when your parent process launches
[HINT] the child but does not wait on it! Look into the waitpid() system call to wait on the child!

[HINT] Another frequent cause is the use of system() or popen() to execute the challenge. Both will actually
[HINT] execute a shell that will then execute the challenge, so the parent of the challenge will be that
[HINT] shell, rather than your program. You must use fork() and one of the exec family of functions (execve(),
[HINT] execl(), etc).
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The process must be your own program in your own home directory.
```

```c
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
}

int main () {
	const char filename[100] = "/challenge/embryoio_level30";

	pid_t cpid;

	if (fork() == 0) {
		execve(filename, NULL, NULL);
		exit(0);
	}
	else {
		cpid = wait(NULL);
	}

	return 0;
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

```
hacker@program-interaction~level31:/$ /challenge/embryoio_level31 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : binary
- the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:chapeafvrb

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure that the process is a custom binary that you created by compiling a C program
[TEST] that you wrote. Make sure your C program has a function called 'pwncollege' in it --- otherwise,
[TEST] it won't pass the checks.
[HINT] If this is a check for the *parent* process, keep in mind that the exec() family of system calls
[HINT] does NOT result in a parent-child relationship. The exec()ed process simply replaces the exec()ing
[HINT] process. Parent-child relationships are created when a process fork()s off a child-copy of itself,
[HINT] and the child-copy can then execve() a process that will be the new child. If we're checking for a
[HINT] parent process, that's how you make that relationship.
[INFO] The executable that we are checking is: /usr/bin/bash.
[HINT] One frequent cause of the executable unexpectedly being a shell or docker-init is that your
[HINT] parent process terminated before this check was run. This happens when your parent process launches
[HINT] the child but does not wait on it! Look into the waitpid() system call to wait on the child!

[HINT] Another frequent cause is the use of system() or popen() to execute the challenge. Both will actually
[HINT] execute a shell that will then execute the challenge, so the parent of the challenge will be that
[HINT] shell, rather than your program. You must use fork() and one of the exec family of functions (execve(),
[HINT] execl(), etc).
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The process must be your own program in your own home directory.
```

```c
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {
}

int main () {
    const char filename[100] = "/challenge/embryoio_level31";
    
    pid_t cpid;
 
    char *argv[] = {filename, "chapeafvrb", NULL};

    int newfd;
    dup2(0, newfd);

    if (fork() == 0) {
	    execve(filename, argv, NULL);
        exit(0);
    }
    else {
        cpid = wait(NULL);
    }

     return 0;
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

```
hacker@program-interaction~level32:/$ /challenge/embryoio_level32 
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : binary
- the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : mrsqev:oaxcmkzbmf

ONWARDS TO GREATNESS!

[INFO] This challenge will now perform a bunch of checks.
[INFO] If you pass these checks, you will receive the flag.
[TEST] Performing checks on the parent process of this process.
[TEST] Checking to make sure that the process is a custom binary that you created by compiling a C program
[TEST] that you wrote. Make sure your C program has a function called 'pwncollege' in it --- otherwise,
[TEST] it won't pass the checks.
[HINT] If this is a check for the *parent* process, keep in mind that the exec() family of system calls
[HINT] does NOT result in a parent-child relationship. The exec()ed process simply replaces the exec()ing
[HINT] process. Parent-child relationships are created when a process fork()s off a child-copy of itself,
[HINT] and the child-copy can then execve() a process that will be the new child. If we're checking for a
[HINT] parent process, that's how you make that relationship.
[INFO] The executable that we are checking is: /usr/bin/bash.
[HINT] One frequent cause of the executable unexpectedly being a shell or docker-init is that your
[HINT] parent process terminated before this check was run. This happens when your parent process launches
[HINT] the child but does not wait on it! Look into the waitpid() system call to wait on the child!

[HINT] Another frequent cause is the use of system() or popen() to execute the challenge. Both will actually
[HINT] execute a shell that will then execute the challenge, so the parent of the challenge will be that
[HINT] shell, rather than your program. You must use fork() and one of the exec family of functions (execve(),
[HINT] execl(), etc).
[FAIL] You did not satisfy all the execution requirements.
[FAIL] Specifically, you must fix the following issue:
[FAIL]    The process must be your own program in your own home directory.
```

```c
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
