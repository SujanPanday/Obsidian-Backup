
1. Download the DVWA full package from github and placed in /var/www/html directory. 

~~~bash
┌──(root㉿kali)-[/var/www/html]
└─# git clone http://github.com/digininja/DVWA.git
Cloning into 'DVWA'...
warning: redirecting to https://github.com/digininja/DVWA.git/
remote: Enumerating objects: 4318, done.
remote: Counting objects: 100% (96/96), done.
remote: Compressing objects: 100% (78/78), done.
remote: Total 4318 (delta 31), reused 65 (delta 15), pack-reused 4222
Receiving objects: 100% (4318/4318), 2.14 MiB | 2.76 MiB/s, done.
Resolving deltas: 100% (2031/2031), done.
~~~

2. Give read, write and execute permission to user, group and both for DVWA file. 

~~~bash
┌──(root㉿kali)-[/var/www/html]
└─# chmod -R 777 DVWA
~~~

3. Did not work out few ways so started tryhackme DVWA room. 

4. Tryhackme vpn connection
~~~bash
──(kali㉿kali)-[~/Downloads]
└─$ ls
spandey3.ovpn  xampp-linux-x64-8.2.4-0-installer.run

┌──(kali㉿kali)-[~/Downloads]
└─$ sudo openvpn spandey3.ovpn 
[sudo] password for kali: 
2023-08-16 01:46:54 Note: --cipher is not set. OpenVPN versions before 2.5 defaulted to BF-CBC as fallback when cipher negotiation failed in this case. If you need this fallback please add '--data-ciphers-fallback BF-CBC' to your configuration and/or add BF-CBC to --data-ciphers.
2023-08-16 01:46:54 Note: cipher 'AES-256-CBC' in --data-ciphers is not supported by ovpn-dco, disabling data channel offload.
2023-08-16 01:46:54 OpenVPN 2.6.3 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
2023-08-16 01:46:54 library versions: OpenSSL 3.0.9 30 May 2023, LZO 2.10
2023-08-16 01:46:54 DCO version: N/A

~~~


