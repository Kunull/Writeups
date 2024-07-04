---
title: DOM XSS in innerHTML sink using source location.search
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 4
---

![1](https://github.com/Knign/Write-ups/assets/110326359/9beeb680-f471-485b-99ee-ae9086cc272f)

Let's insert the following payload in the search field:

```
test_payload
```

We can now open `Left CLick > Inspect` to open the developer tools and search our payload.

![2](https://github.com/Knign/Write-ups/assets/110326359/4821747f-04a3-4c2e-92c8-c66415fac84f)

We can see that our payload has been inserted in the `<span>` tag more specifically, it has been appended to the source of the image.

Right below that we can see a `<script>` tag which includes the script responsible for the DOM manipulation:

```js
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}
var query = (new URLSearchParams(window.location.search)).get('search');
if (query) {
    doSearchQuery(query);
}
```

- The `doSearchQuery` function takes a `query` parameter and sets the inner HTML of an element with the ID `searchMessage` to the query value.
- The `query` variable is assigned the value of the 'search' parameter from the URL using `URLSearchParams`.
- If the 'search' parameter exists in the URL, the `doSearchQuery` function is called with the obtained query.

Now that we know how the DOM manipulation works, we can insert our final payload into the application which will generate an alert.

```html
</span><script>alert("1")</script>
```

![3](https://github.com/Knign/Write-ups/assets/110326359/0e4c9da6-a267-4c52-98fa-a2adbec89c6d)

We have solved the lab.

![4](https://github.com/Knign/Write-ups/assets/110326359/31e1a249-bbd3-42be-910c-4f3a81d1270c)
