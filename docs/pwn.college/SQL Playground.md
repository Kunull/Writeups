---
custom_edit_url: null
---

## level 1

```python title="/challenge/sql"
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()

# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE assets AS SELECT ? as record""", [open("/flag").read().strip()])

# HINT: https://www.sqlite.org/lang_select.html
for _ in range(1):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

```sql
sql> SELECT record FROM assets
Got 1 rows.
- {'record': 'pwn.college{kxLLA-DqLK9Jq6rJWbhdotacK9J.QX5kzN0EDL4ITM0EzW}'}
```

&nbsp;

## level 2

```python title="/challenge/sql"
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()


def random_word(length):
    return "".join(random.sample(string.ascii_letters * 10, length))


flag = open("/flag").read().strip()

# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE dataset AS SELECT 1 as flag_tag, ? as record""", [random_word(len(flag))])
# https://www.sqlite.org/lang_insert.html
for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO dataset VALUES(1, ?)""", [random_word(len(flag))])
db.execute("""INSERT INTO dataset VALUES(?, ?)""", [1337, flag])


for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO dataset VALUES(1, ?)""", [random_word(len(flag))])

# HINT: https://www.sqlite.org/lang_select.html#whereclause
for _ in range(1):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    if len(results) > 1:
        print("You're not allowed to read this many rows!")
        sys.exit(1)
    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

```sql
sql> SELECT record FROM dataset WHERE flag_tag = 1337
Got 1 rows.
- {'record': 'pwn.college{owMG4xVDQbhGyfTA8aHaS-Zu0BN.QXwADO0EDL4ITM0EzW}'}
```

&nbsp;

## level 3

```python title="/challenge/sql"
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()


def random_word(length):
    return "".join(random.sample(string.ascii_letters * 10, length))


flag = open("/flag").read().strip()

# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE payloads AS SELECT 1 as flag_tag, ? as info""", [random_word(len(flag))])
# https://www.sqlite.org/lang_insert.html
for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO payloads VALUES(1, ?)""", [random_word(len(flag))])
db.execute("""INSERT INTO payloads VALUES(?, ?)""", [1337, flag])


for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO payloads VALUES(1, ?)""", [random_word(len(flag))])

# HINT: https://www.sqlite.org/syntax/result-column.html
for _ in range(1):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    if len(results) > 1:
        print("You're not allowed to read this many rows!")
        sys.exit(1)
    if len(results[0].keys()) > 1:
        print("You're not allowed to read this many columns!")
        sys.exit(1)
    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

```sql
sql> SELECT info FROM payloads WHERE flag_tag = 1337
Got 1 rows.
- {'info': 'pwn.college{0EJi-Sd8yxjI1bCczjsGBUYb0jk.QXxADO0EDL4ITM0EzW}'}
```

&nbsp;

## level 4

```python title="/challenge/sql"
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()


def random_word(length):
    return "".join(random.sample(string.ascii_letters * 10, length))


flag = open("/flag").read().strip()

# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE flags AS SELECT 1 as flag_tag, ? as field""", [random_word(len(flag))])
# https://www.sqlite.org/lang_insert.html
for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO flags VALUES(1, ?)""", [random_word(len(flag))])
db.execute("""INSERT INTO flags VALUES(?, ?)""", [random.randrange(1337, 313371337), flag])


for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO flags VALUES(1, ?)""", [random_word(len(flag))])

# HINT: https://www.sqlite.org/lang_expr.html
for _ in range(1):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    if len(results) > 1:
        print("You're not allowed to read this many rows!")
        sys.exit(1)
    if len(results[0].keys()) > 1:
        print("You're not allowed to read this many columns!")
        sys.exit(1)
    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

The following selects any string which has the substring `pwn`. We know that our flag does have this substring, so it should be returned.

```sql
sql> SELECT field FROM flags WHERE field LIKE "%pwn%"
Got 1 rows.
- {'field': 'pwn.college{UyAxrqRvCxX1sOs3wQAYUoXd2QW.QXyADO0EDL4ITM0EzW}'}
```

The following is the exclusionary version.

```sql
sql> SELECT field FROM flags WHERE NOT field NOT LIKE '%pwn%'
Got 1 rows.
- {'field': 'pwn.college{UyAxrqRvCxX1sOs3wQAYUoXd2QW.QXyADO0EDL4ITM0EzW}'}
```

&nbsp;

## level 5

```python title="/challenge/sql
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()


def random_word(length):
    return "".join(random.sample(string.ascii_letters * 10, length))


flag = open("/flag").read().strip()

# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE payloads AS SELECT 'nope' as flag_tag, ? as flag""", [random_word(len(flag))])
# https://www.sqlite.org/lang_insert.html
for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO payloads VALUES('nope', ?)""", [random_word(len(flag))])
db.execute("""INSERT INTO payloads VALUES(?, ?)""", ["yep", flag])


for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO payloads VALUES('nope', ?)""", [random_word(len(flag))])

# HINT: https://www.sqlite.org/lang_expr.html
for _ in range(1):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    if len(results) > 1:
        print("You're not allowed to read this many rows!")
        sys.exit(1)
    if len(results[0].keys()) > 1:
        print("You're not allowed to read this many columns!")
        sys.exit(1)
    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

```sql
sql> SELECT flag FROM payloads WHERE flag_tag = "yep"
Got 1 rows.
- {'flag': 'pwn.college{kL6c0wCx8qJyKwGFfyF9LarOeIW.QXzADO0EDL4ITM0EzW}'}
```

&nbsp;

## level 6

```python title="/challenge/sql"
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()


def random_word(length):
    return "".join(random.sample(string.ascii_letters * 10, length))


flag = open("/flag").read().strip()

# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE secrets AS SELECT ? as content""", [random_word(len(flag))])
# https://www.sqlite.org/lang_insert.html
for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO secrets VALUES(?)""", [random_word(len(flag))])
db.execute("""INSERT INTO secrets VALUES(?)""", [flag])


for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO secrets VALUES(?)""", [random_word(len(flag))])

# HINT: https://www.sqlite.org/lang_corefunc.html#substr
for _ in range(1):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    if len(results) > 1:
        print("You're not allowed to read this many rows!")
        sys.exit(1)
    if len(results[0].keys()) > 1:
        print("You're not allowed to read this many columns!")
        sys.exit(1)
    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

```sql
sql> SELECT content FROM secrets WHERE SUBSTR(content, 1, 3) = "pwn"
Got 1 rows.
- {'content': 'pwn.college{Yh1rYLYBQf1OQc3ex01s0c5IGRQ.QX0ADO0EDL4ITM0EzW}'}
```

```sql
sql> SELECT content FROM secrets WHERE content LIKE "%pwn%"
Got 1 rows.
- {'content': 'pwn.college{Yh1rYLYBQf1OQc3ex01s0c5IGRQ.QX0ADO0EDL4ITM0EzW}'}
```

&nbsp;

## level 7

```python title="/challenge/sql"
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()

# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE archive AS SELECT ? as value""", [open("/flag").read().strip()])

# HINT: https://www.sqlite.org/lang_corefunc.html#substr
for _ in range(1):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    for row in results:
        for k in row.keys():
            if type(row[k]) in (str, bytes) and len(row[k]) > 5:
                print("You're not allowed to read this many characters!")
                sys.exit(1)
    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

```sql
sql> SELECT SUBSTR(value, 1, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 1, 4)': 'pwn.'}
```

```sql
sql> SELECT SUBSTR(value, 5, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 5, 4)': 'coll'}
```

```sql
sql> SELECT SUBSTR(value, 9, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 9, 4)': 'ege{'}
```

```sql
sql> SELECT SUBSTR(value, 13, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 13, 4)': 'ky4U'}
```

```sql
sql> SELECT SUBSTR(value, 17, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 17, 4)': '8r_Q'}
```

```sql
sql> SELECT SUBSTR(value, 21, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 21, 4)': 'aDr5'}
```

```sql
sql> SELECT SUBSTR(value, 25, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 25, 4)': '6IBk'}
```

```sql
sql> SELECT SUBSTR(value, 29, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 29, 4)': '2bPQ'}
```

```sql
sql> SELECT SUBSTR(value, 33, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 33, 4)': 'wqON'}
```

```sql
sql> SELECT SUBSTR(value, 37, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 37, 4)': 'Gi8.'}
```

```sql
sql> SELECT SUBSTR(value, 41, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 41, 4)': 'QX1A'}
```

```sql
sql> SELECT SUBSTR(value, 45, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 45, 4)': 'DO0E'}
```

```sql
sql> SELECT SUBSTR(value, 49, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 49, 4)': 'DL4I'}
```

```sql
sql> SELECT SUBSTR(value, 53, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 53, 4)': 'TM0E'}
```

```sql
sql> SELECT SUBSTR(value, 57, 4) FROM archive WHERE SUBSTR(value, 1, 3) = "pwn"
Got 1 rows.
- {'SUBSTR(value, 57, 4)': 'zW}'}
```

&nbsp;

## level 8

```python title="/challenge/sql"
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()


def random_word(length):
    return "".join(random.sample(string.ascii_letters * 10, length))


flag = open("/flag").read().strip()

# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE logs AS SELECT 1 as flag_tag, ? as field""", [random_word(len(flag))])
# https://www.sqlite.org/lang_insert.html
for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO logs VALUES(1, ?)""", [random_word(len(flag))])
db.execute("""INSERT INTO logs VALUES(?, ?)""", [1337, flag])

for i in range(random.randrange(5, 21)):
    db.execute("""INSERT INTO logs VALUES(1337, ?)""", [random_word(len(flag))])
for i in range(random.randrange(5, 21)):
    db.execute(
        """INSERT INTO logs VALUES(1, ?)""", ["pwn.college{" + random_word(len(flag) - len("pwn.college{}")) + "}"]
    )

for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO logs VALUES(1, ?)""", [random_word(len(flag))])

# HINT: https://www.geeksforgeeks.org/sql-and-and-or-operators/
for _ in range(1):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    if len(results) > 1:
        print("You're not allowed to read this many rows!")
        sys.exit(1)
    if len(results[0].keys()) > 1:
        print("You're not allowed to read this many columns!")
        sys.exit(1)
    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

```sql
sql> SELECT field FROM logs WHERE SUBSTR(field, 1, 3) = "pwn" AND flag_tag = 1337
Got 1 rows.
- {'field': 'pwn.college{QXLaokhF4hnbk8Vy3rzJYkvEAt-.QX2ADO0EDL4ITM0EzW}'}
```

&nbsp;

## level 9

```python title="/challenge/sql"
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()


def random_word(length):
    return "".join(random.sample(string.ascii_letters * 10, length))


flag = open("/flag").read().strip()

# https://www.sqlite.org/lang_createtable.html
db.execute("""CREATE TABLE repository AS SELECT ? as content""", [random_word(len(flag))])
# https://www.sqlite.org/lang_insert.html
for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO repository VALUES(?)""", [random_word(len(flag))])
db.execute("""INSERT INTO repository VALUES(?)""", [flag])

for i in range(random.randrange(5, 21)):
    db.execute("""INSERT INTO repository VALUES(?)""", [random_word(len(flag))])
for i in range(random.randrange(5, 21)):
    db.execute(
        """INSERT INTO repository VALUES(?)""", ["pwn.college{" + random_word(len(flag) - len("pwn.college{}")) + "}"]
    )

for i in range(random.randrange(5, 42)):
    db.execute("""INSERT INTO repository VALUES(?)""", [random_word(len(flag))])

# HINT: https://www.sqlite.org/lang_select.html#limitoffset
for _ in range(1):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    if len(results) > 1:
        print("You're not allowed to read this many rows!")
        sys.exit(1)
    if len(results[0].keys()) > 1:
        print("You're not allowed to read this many columns!")
        sys.exit(1)
    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

```sql
sql> SELECT content FROM repository WHERE SUBSTR(content, 1, 3) = "pwn" LIMIT 1
Got 1 rows.
- {'content': 'pwn.college{QVj2iV7YM-xzyOqZXqnaIAS54Ze.QX3ADO0EDL4ITM0EzW}'}
```

&nbsp;

## level 10

```python title="/challenge/sql"
#!/opt/pwn.college/python

import sys
import string
import random
import sqlite3
import tempfile


# Don't panic about the TemporaryDB class. It simply implements a temporary database
# in which this application can store data. You don't need to understand its internals,
# just that it processes SQL queries using db.execute().
class TemporaryDB:
    def __init__(self):
        self.db_file = tempfile.NamedTemporaryFile("x", suffix=".db")

    def execute(self, sql, parameters=()):
        connection = sqlite3.connect(self.db_file.name)
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()
        result = cursor.execute(sql, parameters)
        connection.commit()
        return result


db = TemporaryDB()

table_name = "".join(random.sample(string.ascii_letters, 8))
db.execute(f"""CREATE TABLE {table_name} AS SELECT ? as solution""", [open("/flag").read().strip()])

# HINT: https://www.sqlite.org/schematab.html
for _ in range(2):
    query = input("sql> ")

    try:
        results = db.execute(query).fetchall()
    except sqlite3.Error as e:
        print("SQL ERROR:", e)
        sys.exit(1)

    if len(results) == 0:
        print("No results returned!")
        sys.exit(0)

    if len(results[0].keys()) > 1:
        print("You're not allowed to read this many columns!")
        sys.exit(1)
    print(f"Got {len(results)} rows.")
    for row in results:
        print(f"- { { k:row[k] for k in row.keys() } }")
```

```sql
sql> SELECT tbl_name FROM sqlite_master
Got 1 rows.
- {'tbl_name': 'pfKDXJgv'}
```

```sql
sql> SELECT solution FROM pfKDXJgv
Got 1 rows.
- {'solution': 'pwn.college{8tkKZYkiGORpytDs-x7j362q7QH.QX4ADO0EDL4ITM0EzW}'}
```
