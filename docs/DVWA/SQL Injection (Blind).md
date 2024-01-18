---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> ### Objective
> Find the version of the SQL database software through a blind SQL attack

## Security Level: Low
> The SQL query uses RAW input that is directly controlled by the attacker. All they need to-do is escape the query and then they are able to execute any SQL query they wish.
> Spoiler: ?id=1' AND sleep 5&Submit=Submit.

![1](https://github.com/Knign/Write-ups/assets/110326359/35af092e-8a50-46b6-a860-7f538f830902)

- Let's check if user ID 1 exists.

![2](https://github.com/Knign/Write-ups/assets/110326359/5224c85d-e815-4adf-a47d-6bea39974ac7)

- We can now provide the following inputs to figure out the number of columns in the table.
```
1' ORDER BY 1#
1' ORDER BY 2# 
1' ORDER BY 3#
```
- When we enter the third input, we get a blank screen. This means that there are two columns in the table.
