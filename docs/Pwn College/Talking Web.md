---
custom_edit_url: null
sidebar_position: 5
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

```
hacker@talking-web~level2:/$ nc localhost 80
GET / HTTP/1.1

```

We can send HTTP request using the `GET` method.

### Method 2

```txt title="talking_web2.txt"
GET / HTTP/1.1

```

```
hacker@talking-web~level5:~$ cat talking_web2.txt | nc localhost 80
```

&nbsp;

## level 3

> Send an HTTP request using python

```python title="talking_web3.py"
import requests

response = requests.get("http://localhost")
print(response.text)
```

```
hacker@talking-web~level5:~$ python talking_web3.py
```

&nbsp;

## level 4

> Set the host header in an HTTP request using curl

The host header allows user to access a site out of multiple sites hosted on the same server.

In order to set the host-header, we need to use the `H` flag.

```
hacker@talking-web~level4:/$ curl -v -H 'Host: 3c22a6070842664437f7deb701d0ba73' localhost
```

&nbsp;

## level 5

> Set the host header in an HTTP request using nc.

### Method 1

```
hacker@talking-web~level5:/$ nc localhost 80
GET / HTTP/1.1
Host: 955346154465080a0f6f80ad1abab644

```

### Method 2

```txt title="talking_web5.txt"
GET / HTTP/1.1
Host: 955346154465080a0f6f80ad1abab644

```

```
hacker@talking-web~level5:~$ cat talking_web5.txt | nc localhost 80
```

&nbsp;

## level 6

> Set the host header in an HTTP request using python

```python title="talking_web6.py"
import requests

response = requests.get("http://localhost", headers = {"Host": "d98cadd7add61f28f2f8ab4ff2866426"})
print(response.text)
```

```
hacker@talking-web~level6:~$ python talking_web6.py
```

&nbsp;

## level 7

> Set the path in an HTTP request using curl

```
hacker@talking-web~level6:/$ curl -v localhost/6b24f3f2803e65ee8a4c7718e3746e9b
```

&nbsp;

## level 8

> Set the path in an HTTP request using nc

### Method 1

```
hacker@talking-web~level8:/$ nc localhost 80
GET /6fa55c0a2c6a06641a0d3b0c7bb52aae HTTP/1.1

```

### Method 2

```txt title="talking_web8.txt"
GET /6fa55c0a2c6a06641a0d3b0c7bb52aae HTTP/1.1

```

```
hacker@talking-web~level8:~$ cat talking_web8.txt | nc localhost 80
```

&nbsp;

## level 9

> Set the path in an HTTP request using python

```python ttile="talking_web.9.py"
import requests

response = requests.get("http://localhost/f9e1c5fbc5583f0adc79a10ca148515c")
print(response.text)
```

```
hacker@talking-web~level9:~$ python talking_web9.py
```

&nbsp;

## level 10

> URL encode a path in an HTTP request using curl

```
hacker@talking-web~level10:/$ curl -v localhost/57663ceb%20cd9c94ed%2F6168ae2b%20da2eccda
```

&nbsp;

## level 11

> URL encode a path in an HTTP request using nc

### Method 1

```
hacker@talking-web~level11:/$ nc localhost 80
GET /b12c4f12%2067266589%2Fd666cda6%20d2af6f45 HTTP/1.1

```

### Method 2

```txt title="talking_web11.txt"
GET /b12c4f12%2067266589%2Fd666cda6%20d2af6f45 HTTP/1.1

```

```
hacker@talking-web~level11:~$ cat talking_web11.txt | nc localhost 80
```

&nbsp;

## level 12

> URL encode a path in an HTTP request using python

```python ttile="talking_web12.py"
import requests

response = requests.get("http://localhost/84c49128%208a299390%2F93d9bfa2%20d858b128")
print(response.text)
```

```
hacker@talking-web~level12:~$ python talking_web12.py
```

&nbsp;

## level 13

> Specify an argument in an HTTP request using curl

```
hacker@talking-web~level13:/$ curl 'localhost?a=0700717794063c8870f6587ffe9d1f2e'
```

&nbsp;

## level 14

> Specify an argument in an HTTP request using nc

### Method 1

```
hacker@talking-web~level14:/$ nc localhost 80
GET /?a=9cb477c13d0f3467762b96e34723b429 HTTP/1.1

```

### Method 2

```txt title="talking_web14.txt"
GET /?a=9cb477c13d0f3467762b96e34723b429 HTTP/1.1

```

```
hacker@talking-web~level14:~$ cat talking_web14.txt | nc localhost 80
```

&nbsp;

## level 15

> Specify an argument in an HTTP request using python

```python title="talking_web15.py"
import requests

response = requests.get("http://localhost", params = {"a": "98b2272feef1197ca5db52112f53171a"})
print(response.text)
```

```
hacker@talking-web~level15:~$ python talking_web15.py
```

&nbsp;

## level 16

> Specify multiple arguments in an HTTP request using curl

```
hacker@talking-web~level15:/$ curl -v 'localhost?a=183a900965dbaa297b87b8da347b5000&b=755bccd7%20431ba7ab%26e4271ad1%23165b5805'
```

&nbsp;

## level 17

> Specify multiple arguments in an HTTP request using nc

Encode space, &, #

| Character | Encoding |
|:-:|:-:|
| space | %20 |
| & | %26 |
| # | %23 |

### Method 1

```txt title="Request.txt"
hacker@talking-web~level14:/$ nc localhost 80
GET /?a=0d5d14b5c59f30f71f8a4ad183e5594b&b=14ee11ce%207bcd30bb%26945e070f%238c4ca511 HTTP/1.1

```

### Method 2

```txt title="talking_web17.txt"
GET /?a=0d5d14b5c59f30f71f8a4ad183e5594b&b=14ee11ce%207bcd30bb%26945e070f%238c4ca511 HTTP/1.1

```

```
hacker@talking-web~level17:~$ cat talking_web17.txt | nc localhost 80
```

&nbsp;

## level 18

> Specify multiple arguments in an HTTP request using python

```python title="talking_web18.py"
import requests

response = requests.get("http://localhost", params = {"a": "976a35e36b74e0ec9d51e06642819868", "b": "5c6d5670 264acf16&9a8327b8#a1e2f498"})
print(response.text)
```

```
hacker@talking-web~level18:~$ python talking_web18.py
```

&nbsp;

## level 19

> Include form data in an HTTP request using curl

```
hacker@talking-web~level19:/$ curl localhost -H "Content-Type: application/x-www-form-urlencoded" -d "a=2f326bd3fccd73a0779f0b2d508973b7"
```

&nbsp;

## level 20

> Include form data in an HTTP request using nc

## Method 1

```
hacker@talking-web~level20:/$ nc localhost 80
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

a=efd41ca8a70736bfca72237e98562264
```

### Method 2

```txt title="talking_web20.txt"
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

a=efd41ca8a70736bfca72237e98562264
```

```
hacker@talking-web~level20:~$ cat talking_web20.txt | nc localhost 80
```

&nbsp;

## level 21

> Include form data in an HTTP request using python

```python title="talking_web21.py"
import requests

response = requests.post("http://localhost", data = {"a": "48a3ea3467441c043b6bbdaaa892f581"})
print(response.text)
```

```python title="talking_web21.py"
hacker@talking-web~level21:~$ python talking_web21.py
```

&nbsp;

## level 22

> Include form data with multiple fields in an HTTP request using curl

```
hacker@talking-web~level21:/$ curl localhost -H "Content-Type: application/x-www-form-urlencoded" -d "a=49d18424ea2da90ef911b176280d2b4f&b=e554316c%20d26a8c93%2637806597%2308446ae2"
```

&nbsp;

## level 23

> Include form data with multiple fields in an HTTP request using nc

### Method 1

```
hacker@talking-web~level23:/$ nc localhost 80
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

a=ac3b1a1c63b69fad533e8978f6a5dff6&b=b573a00d%202ba9bc8a%26a6695f81%233c49eb83
```

### Method 2

```txt title="talking_web23.txt"
POST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 78

a=ac3b1a1c63b69fad533e8978f6a5dff6&b=b573a00d%202ba9bc8a%26a6695f81%233c49eb83
```

```
hacker@talking-web~level23:~$ cat talking_web23.txt | nc localhost 80
```

&nbsp;

## level 24

> Include form data with multiple fields in an HTTP request using python

```python title="talkng_web24.py"
import requests

response = requests.post("http://localhost", data = {"a": "d9ca68fd4ebb26ce7bc66ca673af28bd", "b": "3f36fa3c 5d887603&0ca6cc86#9b3ebe7e"})
print(response.text)
```

```
hacker@talking-web~level24:~$ python talking_web24.py
```

&nbsp;

## level 25

> Include json data in an HTTP request using curl

```
hacker@talking-web~level25:/$ curl -v localhost -H "Content-Type: application/json" -d '{"a": "4ca4028161b46e326dccbd61fd9ca126"}'
```

&nbsp;

## level 26

> Include json data in an HTTP request using nc

### Method 1

```
hacker@talking-web~level23:/$ nc localhost 80
POST / HTTP/1.1
Content-Type: application/json
Content-Length: 41

{"a": "2871410238346d3ef1efa9557c63d396"}
```

### Method 2

```txt title="talking_web26.txt"
POST / HTTP/1.1
Content-Type: application/json
Content-Length: 41

{"a": "2871410238346d3ef1efa9557c63d396"}
```

```
hacker@talking-web~level26:~$ cat talking_web26.txt | nc localhost 80
```

&nbsp;

## level 27

> Include json data in an HTTP request using python

```python title="talking_web27.py"
import requests

response = requests.post("http://localhost", json = {"a": "4f8799edeeeae6280d2476ff44ec855b"})
print(response.text)
```

```
hacker@talking-web~level27:~$ python talking_web27.py
```

&nbsp;

## level 28

> Include complex json data in an HTTP request using curl

```
hacker@talking-web~level28:/$ curl -v -H "Content-Type: application/json" localhost -d '{"a": "134feb33f6406e92577a3da1af09d6e1", "b":  {"c": "731530a0", "d": ["aa22dd29", "33a13f37 c90ae96c&fc4db4e3#43ed5bf2"]}}'
```

&nbsp;

## level 29

> Include complex json data in an HTTP request using nc

### Method 1

```
hacker@talking-web~level29:/$ nc localhost 80
POST / HTTP/1.1
Content-Type: application/json
Content-Length: 123

{"a": "3c3fc4d92ea768d2f90a1564901c7151", "b": {"c": "88960a48", "d": ["f8b92795", "59ce8454 77e5423c&e259ebfd#c90f1078"]}}
```

### Method 2

```txt title="talking_web29.txt"
POST / HTTP/1.1
Content-Type: application/json
Content-Length: 123

{"a": "3c3fc4d92ea768d2f90a1564901c7151", "b": {"c": "88960a48", "d": ["f8b92795", "59ce8454 77e5423c&e259ebfd#c90f1078"]}}
```

```
hacker@talking-web~level29:~$ cat talking_web29.txt | nc localhost 80
```

&nbsp;

## level 30

> Include complex json data in an HTTP request using python

```python title="talking_web30.py"
import requests

response = requests.post("http://localhost", json = {"a": "c49c2036612db43b827928a815ab4aa3", "b": {'c': '18990378', 'd': ['15a23d60', '5d838d26 b09c0f1b&b57e6ead#7e7021f8']}})
print(response.text)
```

```
hacker@talking-web~level30:~$ python talking_web30.py
```

&nbsp;

## level 31

> Follow an HTTP redirect from HTTP response using curl

```
hacker@talking-web~level31:/$ curl -v localhost/fe865645cf9d9429f8d3a64bd3624bde
```

&nbsp;

## level 32

> Follow an HTTP redirect from HTTP response using nc

### Method 1

```
hacker@talking-web~level32:/$ nc localhost 80
GET /04f17f0a0c09c5f51d7b4b41227fc991 HTTP/1.1

```

The server will include the target URI for the redirect in the response.

We have to make another request using the endpoint specified.

```
hacker@talking-web~level32:/$ nc localhost 80
GET /3d825486aeccc071f71c8e941d6cd32f HTTP/1.1

```

### Method 2

```txt title="talking_web32_1.txt"
GET /04f17f0a0c09c5f51d7b4b41227fc991 HTTP/1.1

```

```txt title="talking_web32_2.txt"
GET /3d825486aeccc071f71c8e941d6cd32f HTTP/1.1

```

```
hacker@talking-web~level32:~$ cat talking_web32_1.txt | nc localhost 80; cat talking_web32_2.txt | nc localhost 80
```

&nbsp;

## level 33

> Follow an HTTP redirect from HTTP response using python

```python title="talking_web33.py"
import requests

response = requests.post("http://localhost")
print(response.text)
```

```
hacker@talking-web~level33:~$ python talking_web33.py
```

&nbsp;

## level 34

> Include a cookie from HTTP response using curl

```
hacker@talking-web~level34:/$ curl -v -H 'Cookie: cookie=6ba66cf208e8af50138db065514ec00c' localhost
```

OR

```
hacker@talking-web~level34:/$ curl -L --cookie /tmp/cookie localhost
```

&nbsp;

## level 35

> Include a cookie from HTTP response using nc

### Method 1

```
hacker@talking-web~level35:/$ nc localhost 80
GET / HTTP/1.1
Cookie: cookie=fd64267b1b2798fc6498188109e91cf7

```

### Method 2

```txt title="talking_web35.txt"
GET / HTTP/1.1
Cookie: cookie=fd64267b1b2798fc6498188109e91cf7

```

```
hacker@talking-web~level35:~$ cat talking_web35.txt | nc localhost 80
```

&nbsp;

## level 36

> Include a cookie from HTTP response using python

```python title="talking_web36.py"
import requests

response = requests.post("http://localhost")
print(response.text)
```

```
hacker@talking-web~level36:~$ python talking_web36.py
```

&nbsp;

## level 37

> Make multiple requests in response to stateful HTTP responses using curl

```
hacker@talking-web~level37:/$ curl -v -H 'Cookie: session=eyJzdGF0ZSI6MX0.ZIdjyA.Il0n0-3Dc92AGqznlmke0NUGbSM' localhost
```

```
hacker@talking-web~level37:/$ curl -v -H 'Cookie: session=eyJzdGF0ZSI6Mn0.ZIdj-g.xNEcHHpWLkuTjDyiyMlOkpJlhHc' localhost
```

```
hacker@talking-web~level37:/$ curl -v -H 'Cookie: session=eyJzdGF0ZSI6M30.ZIdkLw.GAPUeUh0rrxafcjsCri18TI506o' localhost
```

OR

```
hacker@talking-web~level37:/$ curl -L --cookie /tmp/cookie localhost
```

&nbsp;

## level 38

> Make multiple requests in response to stateful HTTP responses using nc

### Method 1

```
hacker@talking-web~level38:/$ nc localhost 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6MX0.ZIdFvA.sHWWKoF8bM1fkGxOrTHbPJrHnXk
```

```
hacker@talking-web~level38:/$ nc localhost 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6Mn0.ZIdGGw.vET_YPzKaN7NNySdDm80v_VRahM
```

```
hacker@talking-web~level38:/$ nc localhost 80
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6M30.ZIdGTg.7DxhB2c_HvhkfSS5ADGrIgK-eq4
```

### Method 2

```txt title="talking_web38_1.txt"
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6MX0.ZIdFvA.sHWWKoF8bM1fkGxOrTHbPJrHnXk

```

```txt title="talking_web38_2.txt"
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6Mn0.ZIdGGw.vET_YPzKaN7NNySdDm80v_VRahM

```

```txt title="talking_web38_3.txt"
GET / HTTP/1.1
Cookie: session=eyJzdGF0ZSI6M30.ZIdGTg.7DxhB2c_HvhkfSS5ADGrIgK-eq4

```

```
hacker@talking-web~level38:~$ cat talking_web38_1.txt | nc localhost 80; cat talking_web38_2.txt | nc localhost 80; cat talking_web38_3.txt | nc localhost 80
```

&nbsp;

## level 39

> Make multiple requests in response to stateful HTTP responses using python

```python title="talking_web39.py"
import requests

response = requests.post("http://localhost")
print(response.text)
```

```
hacker@talking-web~level39:~$ python talking_web39.py
```
