---
layout: default
---

<section class="achievements">
    <span>
        <img src="https://www.hackthebox.eu/badge/image/149523" alt="Hack The Box">
        <a href="https://aspen.eccouncil.org/VerifyBadge?type=certification&a=ZFdiJdMliOxqHmyDSxXOi12gVoEhweEb6uAzCh4EsqI=">
            <img src="/assets/images/CHFI_EC3C17017B4E.png" width="50" alt="chfi" />
            </a>
    </span>
</section>

Welcome to my site where you will find interesting posts, tools, writeups and freak things related to cibersecurity.  
`Enjoy your stay!`
<br />

## Recent posts
{% for post in site.posts limit:5 %}  
  <li><a href="{{ BASE_PATH }}{{ post.url }}">{{ post.title }}</a></li>  
{% endfor %} 
<br />

## Content
*   [Posts](./posts.html)
*   Projects
*   Writeups
*   Tools