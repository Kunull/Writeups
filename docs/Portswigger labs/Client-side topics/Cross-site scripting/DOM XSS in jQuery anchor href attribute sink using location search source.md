---
title: DOM XSS in jQuery anchor href attribute sink using location.search source
custom_edit_url: null
sidebar_position: 5
---

<figure style={{ textAlign: 'center' }}>
![1](https://github.com/Knign/Write-ups/assets/110326359/8b955d6c-be9d-45e1-9cb5-60f7c8cdecd4)
</figure>

Let's click on the `Submit Feedback` button.

On the `Submit Feedback` page, we can open the developer tools and inspect the `Back` link.

<figure style={{ textAlign: 'center' }}>
![2](https://github.com/Knign/Write-ups/assets/110326359/2a67a322-3a10-4585-b4f9-eb835532be27)
</figure>

We can see that it is an `<a>` tag with the `backLink` ID and `href="/"`. 

Right below it, we can see the script which is responsible for setting it's `href` attribute.

```js
$(function() {
    $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
});
```

- `$(function() {...})`: This is a shorthand for `$(document).ready(function() {...})`, which ensures that the code inside the function is executed when the DOM is fully loaded.
- `$('#backLink')`: Selects the HTML element with the ID 'backLink'.
- `.attr("href", ...)`: Sets the 'href' attribute of the selected element.
- `(new URLSearchParams(window.location.search)).get('returnPath')`: Retrieves the value of the 'returnPath' parameter from the URL using the `URLSearchParams` API.

Now that we know how the script works, we can set the `returnPath` parameter in the URI to the following:

```html
javascript:alert(document.cookie)
```

<figure style={{ textAlign: 'center' }}>
![4](https://github.com/Knign/Write-ups/assets/110326359/84836767-6963-4ebe-bf07-cc4546e1ca0c)
</figure>

Now if we click on the `Back` link, the Javascript that has been inserted in the `href` attribute will be executed.

<figure style={{ textAlign: 'center' }}>
![5](https://github.com/Knign/Write-ups/assets/110326359/5a973b86-2040-4999-b309-8456bb077894)
</figure>

We have solved the lab.

<figure style={{ textAlign: 'center' }}>
![6](https://github.com/Knign/Write-ups/assets/110326359/9309b980-712e-400c-ae54-94f55ab8df75)
</figure>
