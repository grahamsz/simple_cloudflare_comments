# Simple Cloudflare Comments

This is a proof of concept plugin which enables google cloudflare comments. 

Lots of clean up and better instructions are needed, but see the example folder which shows how this might be deployed. Once you've got the cloudflare bits working, you can add comments to a website with something as simple as 

```
<div id="comments"></div>
<script>fetch('/scc/comments').then(response=> response.text()).then(text=> { document.getElementById('comments').innerHTML = text; if (location.href.includes('#')) location.href=location.href;});</script>
```