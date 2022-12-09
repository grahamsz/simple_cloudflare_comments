# Simple Cloudflare Comments

This is a proof-of-concept plugin that creates a simple comment thread on any static Cloudflare Pages site. This uses Cloudflare's D1 Database Service *which is currently in ALPHA and should not be used on important production sites*.  

I'm using this on [my own site](https://graha.ms) and also have a demo hosted at [https://simple-cloudflare-commentes.pages.dev](https://simple-cloudflare-commentes.pages.dev).


Once you've got the Cloudflare bits working, you can add comments to a website with something as simple as 

```
<div id="comments"></div>
<script>fetch('/scc/comments').then(response=> response.text()).then(text=> { document.getElementById('comments').innerHTML = text; if (location.href.includes('#')) location.href=location.href;});</script>
```

# Installation Instructions

Full set-up instructions can be found [here](https://graha.ms/posts/blog/2022-12-08-setting-up-simple-cloudflare-comments/).