---
custom_edit_url: null
sidebar_position: 3
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/54072ed6-c2ad-41c0-a640-597b122f83a7)
</figure>

Let's submit some feedback.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/2e7f9d39-f486-4c9f-b734-8589446312b5)
</figure>

We can proxy this request through Burp Suite and check the `Proxy > HTTP History` tab.

<figure style={{ textAlign: 'center' }}>
![3](https://github.com/Knign/Write-ups/assets/110326359/96513681-65eb-4fdb-93c4-45a3d2dc215b)
</figure>

Let's forward it to the `Repeater` for modification.

Once in the `Repeater` set the `email` parameter to the following and send the request:
```
x%40gmail.com||whoami>/var/www/images/output.txt||
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/1fa1f75f-0f69-4aec-a78b-f2e477c5cc92)
</figure>

The out put of our `whoami` command is now saved in the `/var/www/images/output.txt` file.

Now let's view one of the images through our browser.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/c1571ec8-765b-4769-b868-97154e4d35e6)
</figure>

Let's go to the `Proxy > HTTP History` tab in Burp Suite and view this request.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/a32a2d1a-1a37-40c8-badb-baa096841f0b)
</figure>

After forwarding this request to the `Repeater`, we can set the `filename` parameter to the following:

```
output.txt
```

<figure style={{ textAlign: 'center' }}>
![7](https://github.com/Knign/Write-ups/assets/110326359/fa1ccbc3-2a70-458d-a72e-85b986b1faba)
</figure>

There's the output of our command.

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![8](https://github.com/Knign/Write-ups/assets/110326359/68aa1eb7-ad53-4843-a43d-76ce37bedbf3)
</figure>
