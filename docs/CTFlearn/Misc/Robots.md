---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> Where do robots find what pages are on a website?
> Hint:
> > What does disallow tell a robot?
## robots.txt
- A robots.txt file tells search engine crawlers which URLs the crawler can access on your site.

![1 25](https://github.com/Knign/Write-ups/assets/110326359/5e1bfae3-3669-4bf9-838b-3f3b907e5f50)

```
User-agent: *  
Disallow: /70r3hnanldfspufdsoifnlds.html
```
- The `User-agent: *` means this section applies to all robots. 
- The `Disallow: /70r3hnanldfspufdsoifnlds.html` tells the robot that it should that page.
- Let's see why we are not allowed to visit `/70r3hnanldfspufdsoifnlds.html`.

![2 24](https://github.com/Knign/Write-ups/assets/110326359/5966b1dd-40ed-4255-b961-b7f6a7bec99c)

## Flag
```
CTFlearn{r0b0ts_4r3_th3_futur3}
```
