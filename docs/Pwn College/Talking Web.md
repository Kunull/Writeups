---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 4
---

## level 1

> Send an HTTP request using curl

```
hacker@talking-web~level1:/$ curl localhost
```

&nbsp;

## level 2

> Send an HTTP request using nc

`nc` takes URL and port in order to function.

### Method 1

```txt title="Request2"
hacker@talking-web~level2:/$ nc localhost 80
GET / HTTP/1.1

```

We can send HTTP request using the `GET` method.

### Method 2

```txt title="talking_web5.txt"
GET / HTTP/1.1

```

```
hacker@talking-web~level5:~$ cat talking_web5.txt | nc localhost 80
```

&nbsp;

## level 3

> Send an HTTP request using python

```python title="request3.py"
import requests

response = requests.get("http://localhost")
print(response.text)
```

&nbsp;

## level 4

> Set the host header in an HTTP request using curl

The host header allows user to access a site out of multiple sites hosted on the same server.

In order to set the host-header, we need to use the `H` flag.

```
$ curl -v -H 'Host: 3c22a6070842664437f7deb701d0ba73' localhost
```

&nbsp;

## level 5

> Set the host header in an HTTP request using nc.

```txt title="Request.txt"
$ nc localhost 80
GET / HTTP/1.1
Host: 955346154465080a0f6f80ad1abab644
```

&nbsp;

## level 6

> Set the host header in an HTTP request using python

```python
import requests

response = requests.get("http://localhost", headers = {"Host": "d98cadd7add61f28f2f8ab4ff2866426"})
print(response.text)
```

&nbsp;

## level 7

> Set the path in an HTTP request using curl

```
$ curl -v localhost/6b24f3f2803e65ee8a4c7718e3746e9b
```

&nbsp;

## level 8

> Set the path in an HTTP request using nc

```txt title="Request.txt"
$ nc localhost 80
GET /6fa55c0a2c6a06641a0d3b0c7bb52aae HTTP/1.1
```

&nbsp;

## level 9

> Set the path in an HTTP request using python

```python
import requests

response = requests.get("http://localhost/f9e1c5fbc5583f0adc79a10ca148515c")
print(response.text)
```

&nbsp;

## level 10

> URL encode a path in an HTTP request using curl

```
$ curl -v localhost/57663ceb%20cd9c94ed%2F6168ae2b%20da2eccda
```

&nbsp;

## level 11

> URL encode a path in an HTTP request using nc

```txt title="Request.txt"
$ nc localhost 80
GET /b12c4f12%2067266589%2Fd666cda6%20d2af6f45 HTTP/1.1
```

&nbsp;

## level 12

> URL encode a path in an HTTP request using python

```python
import requests

response = requests.get("http://localhost/84c49128%208a299390%2F93d9bfa2%20d858b128")
print(response.text)
```

&nbsp;

## level 13

> Specify an argument in an HTTP request using curl

```
$ curl 'localhost?a=0700717794063c8870f6587ffe9d1f2e'
```

&nbsp;

## level 14

> Specify an argument in an HTTP request using nc

```txt title="Request.txt"
$ nc localhost 80
GET /?a=9cb477c13d0f3467762b96e34723b429 HTTP/1.1
```

&nbsp;

## level 15

> Specify an argument in an HTTP request using python

```python
import requests

response = requests.get("http://localhost", params = {"a": "98b2272feef1197ca5db52112f53171a"})
print(response.text)
```

&nbsp;

## level 16

> Specify multiple arguments in an HTTP request using curl

```
$ curl -v 'localhost?a=183a900965dbaa297b87b8da347b5000&b=755bccd7%20431ba7ab%26e4271ad1%23165b5805'
```

&nbsp;

## level 17

> Specify multiple arguments in an HTTP request using nc

```txt title="Request.txt"
$ nc localhost 80
GET /?a=0d5d14b5c59f30f71f8a4ad183e5594b&b=14ee11ce 7bcd30bb&945e070f#8c4ca511 HTTP/1.1
```

* encode space, &, #

```txt title="Request.txt"
$ nc localhost 80
GET /?a=0d5d14b5c59f30f71f8a4ad183e5594b&b=14ee11ce%207bcd30bb%26945e070f%238c4ca511 HTTP/1.1
```

&nbsp;

## level 18

> Specify multiple arguments in an HTTP request using python

```python
import requests

response = requests.get("http://localhost", params = {"a": "976a35e36b74e0ec9d51e06642819868", "b": "5c6d5670 264acf16&9a8327b8#a1e2f498"})
print(response.text)
```

&nbsp;

## level 19

> Include form data in an HTTP request using curl

```
$ curl localhost -H "Content-Type: application/x-www-form-urlencoded" -d "a=2f326bd3fccd73a0779f0b2d508973b7"
```

&nbsp;

## level 20

> Include form data in an HTTP request using nc

```txt title="Request.txt"
$ nc localhost 80
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

a=efd41ca8a70736bfca72237e98562264
```

&nbsp;

## level 21

> Include form data in an HTTP request using python

```python
import requests

response = requests.post("http://localhost", data = {"a": "48a3ea3467441c043b6bbdaaa892f581"})
print(response.text)
```

&nbsp;

## level 22

> Include form data with multiple fields in an HTTP request using curl

```
$ curl localhost -H "Content-Type: application/x-www-form-urlencoded" -d "a=49d18424ea2da90ef911b176280d2b4f&b=e554316c%20d26a8c93%2637806597%2308446ae2"
```

&nbsp;

## level 23

> Include form data with multiple fields in an HTTP request using nc

```txt title="Request.txt"
$ nc localhost 80
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

a=ac3b1a1c63b69fad533e8978f6a5dff6&b=b573a00d%202ba9bc8a%26a6695f81%233c49eb83
```

&nbsp;

## level 24

> Include form data with multiple fields in an HTTP request using python

```python
import requests

response = requests.post("http://localhost", data = {"a": "d9ca68fd4ebb26ce7bc66ca673af28bd", "b": "3f36fa3c 5d887603&0ca6cc86#9b3ebe7e"})
print(response.text)
```

&nbsp;

## level 25

> Include json data in an HTTP request using curl

```
$ curl -v localhost -H "Content-Type: application/json" -d '{"a": "4ca4028161b46e326dccbd61fd9ca126"}'
```

&nbsp;

## level 26

> Include json data in an HTTP request using nc

```txt title="Request.txt"
$ nc localhost 80
POST / HTTP/1.1
Content-Type: application/json
Content-Length: 41

{"a": "2871410238346d3ef1efa9557c63d396"}
```

&nbsp;

## level 27

> Include json data in an HTTP request using python

```python
import requests

response = requests.post("http://localhost", json = {"a": "4f8799edeeeae6280d2476ff44ec855b"})
print(response.text)
```

&nbsp;

## level 28

> Include complex json data in an HTTP request using curl

```
$ curl -v -H "Content-Type: application/json" localhost -d '{"a": "134feb33f6406e92577a3da1af09d6e1", "b":  {"c": "731530a0", "d": ["aa22dd29", "33a13f37 c90ae96c&fc4db4e3#43ed5bf2"]}}'
```

&nbsp;

## level 29

> Include complex json data in an HTTP request using nc

```txt title="Request.txt"
$ nec localhost 80
POST / HTTP/1.1
Content-Type: application/json
Content-Length: 123

{"a": "3c3fc4d92ea768d2f90a1564901c7151", "b": {"c": "88960a48", "d": ["f8b92795", "59ce8454 77e5423c&e259ebfd#c90f1078"]}}
```

&nbsp;

## level 30

> Include complex json data in an HTTP request using python

```python
import requests

response = requests.post("http://localhost", json = {"a": "c49c2036612db43b827928a815ab4aa3", "b": {'c': '18990378', 'd': ['15a23d60', '5d838d26 b09c0f1b&b57e6ead#7e7021f8']}})
print(response.text)
```

&nbsp;

## level 31

> Follow an HTTP redirect from HTTP response using curl

```
$ curl -v localhost/fe865645cf9d9429f8d3a64bd3624bde
```

&nbsp;

## level 32

> Follow an HTTP redirect from HTTP response using nc

```txt title="Request.txt"
$ nc localhost 80
GET /04f17f0a0c09c5f51d7b4b41227fc991 HTTP/1.1
```

&nbsp;

## level 33

> Follow an HTTP redirect from HTTP response using python

```python
import requests

response = requests.post("http://localhost")
print(response.text)
```

&nbsp;

## level 34

> Include a cookie from HTTP response using curl

```
$ curl -v -H 'Cookie: cookie=6ba66cf208e8af50138db065514ec00c' localhost
```

OR

```
$ curl -L --cookie /tmp/cookie localhost
```

&nbsp;

## level 35

> Include a cookie from HTTP response using nc

```txt title="Request.txt"
$ nc localhost 80
GET / HTTP/1.1
Cookie: cookie=fd64267b1b2798fc6498188109e91cf7
```

&nbsp;

## level 36

> Include a cookie from HTTP response using python

```python
import requests

response = requests.post("http://localhost")
print(response.text)
```

&nbsp;

## level 37

> Make multiple requests in response to stateful HTTP responses using curl

```
$ curl -v -H 'Cookie: session=eyJzdGF0ZSI6MX0.ZIdjyA.Il0n0-3Dc92AGqznlmke0NUGbSM' localhost
```

```
$ curl -v -H 'Cookie: session=eyJzdGF0ZSI6Mn0.ZIdj-g.xNEcHHpWLkuTjDyiyMlOkpJlhHc' localhost
```

```
$ curl -v -H 'Cookie: session=eyJzdGF0ZSI6M30.ZIdkLw.GAPUeUh0rrxafcjsCri18TI506o' localhost
```

OR

```
 curl -L --cookie /tmp/cookie localhost
```

&nbsp;

## level 38

> Make multiple requests in response to stateful HTTP responses using nc

```txt title="Request.txt"
$ nc localhost 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6MX0.ZIdFvA.sHWWKoF8bM1fkGxOrTHbPJrHnXk
```

```txt title="Request.txt"
$ nc localhost 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6Mn0.ZIdGGw.vET_YPzKaN7NNySdDm80v_VRahM
```

```txt title="Request.txt"
$ nc localhost 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6M30.ZIdGTg.7DxhB2c_HvhkfSS5ADGrIgK-eq4
```

&nbsp;

## level 39

> Make multiple requests in response to stateful HTTP responses using python

```python
import requests

response = requests.post("http://localhost")
print(response.text)
```
