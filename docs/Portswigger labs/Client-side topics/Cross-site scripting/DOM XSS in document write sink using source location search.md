---
title: DOM XSS in document.write sink using source location.search
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 3
---

![1](https://github.com/Knign/Write-ups/assets/110326359/18488999-5b2c-446f-8367-078bd42dbae7)

Let's insert the following payload in the search field:

```
test_payload
```

We can now open `Left CLick > Inspect` to open the developer tools and search our payload.

![2](https://github.com/Knign/Write-ups/assets/110326359/e390989d-2349-42c1-b78e-bd24ccceebc1)

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

```html
"><svg onload=alert(1)>
```

![3](https://github.com/Knign/Write-ups/assets/110326359/141878b7-d8f5-4a45-af2c-808f642bec58)

We have solved the lab.

![5](https://github.com/Knign/Write-ups/assets/110326359/d201e7bd-89e4-481e-ae68-e1d3fd7f4062)
