# MACHINE – 1 - DC - 192.168.133.100

1.      Rustscan result
```
rustscan 192.168.133.100

Open 192.168.133.100:53
Open 192.168.133.100:88
Open 192.168.133.100:135
Open 192.168.133.100:139
Open 192.168.133.100:389
Open 192.168.133.100:445
Open 192.168.133.100:464
Open 192.168.133.100:593
Open 192.168.133.100:636
Open 192.168.133.100:3269
Open 192.168.133.100:3268
Open 192.168.133.100:3389
Open 192.168.133.100:5985
Open 192.168.133.100:9389
Open 192.168.133.100:49665
Open 192.168.133.100:49666
```

2. Nmap result 
```
┌──(kali㉿kali)-[~/exam]
└─$ nmap -p 53,88,135,139,389,445,464,593,636,3269,3268,3389,5985,9389,49665,49666,49669,49667,49674,49675,49678,49705,57679 -T4 -A 192.168.133.100 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 23:38 EST
Nmap scan report for 192.168.133.100
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-02-22 04:38:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: oscp.exam0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: oscp
|   NetBIOS_Domain_Name: oscp
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: oscp.exam
|   DNS_Computer_Name: dc01.oscp.exam
|   DNS_Tree_Name: oscp.exam
|   Product_Version: 10.0.17763
|_  System_Time: 2024-02-22T04:39:26+00:00
| ssl-cert: Subject: commonName=dc01.oscp.exam
| Not valid before: 2024-02-21T04:06:16
|_Not valid after:  2024-08-22T04:06:16
|_ssl-date: 2024-02-22T04:40:05+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
57679/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-22T04:39:26
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.59 seconds
```


# MACHINE – 2 – MS01 – 192.168.133.101
1. Rustscan result
```
rustscan 192.168.133.101

Open 192.168.133.101:135
Open 192.168.133.101:139
Open 192.168.133.101:445
Open 192.168.133.101:5985
Open 192.168.133.101:8080
Open 192.168.133.101:49664
Open 192.168.133.101:49666
Open 192.168.133.101:49665
Open 192.168.133.101:49667
Open 192.168.133.101:49668
Open 192.168.133.101:49669
```

2. Nmap result
```
┌──(kali㉿kali)-[~/exam]
└─$ nmap -p 135,139,445,5985,8080,49664,49666,49665,49667,49668,49669 -T4 -A 192.168.133.101 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 23:39 EST
Nmap scan report for 192.168.133.101
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8080/tcp  open  http          Jetty 9.4.z-SNAPSHOT
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: -1s
| smb2-time: 
|   date: 2024-02-22T04:40:31
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.15 seconds
```


# MACHINE – 3 – MS02 -192.168.133.102
1. Rustscan result
```
rustscan 192.168.133.102

Open 192.168.133.102:135
Open 192.168.133.102:139
Open 192.168.133.102:445
Open 192.168.133.102:3306
Open 192.168.133.102:5985
Open 192.168.133.102:49664
Open 192.168.133.102:49665
Open 192.168.133.102:49666
Open 192.168.133.102:49667
Open 192.168.133.102:49668
Open 192.168.133.102:49673
```

2. Nmap result
```
┌──(kali㉿kali)-[~/exam]
└─$ nmap -p 135,139,445,3306,5985,49664,49665,49666,49667,49668,49673 -T4 -A 192.168.133.102 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 23:40 EST
Nmap scan report for 192.168.133.102
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-22T04:41:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.72 seconds
```

# MACHINE – 4 – Standalone 1


```
passive off
epsv4 off
```

# MACHINE – 5 – Standalone 2

# MACHINE – 6 – Standalone 3