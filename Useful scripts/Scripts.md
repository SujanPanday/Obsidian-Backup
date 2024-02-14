Keep the script for future references 

1. Get new ip address
```
kali - dhclient

windows - ipconfig /renew
```

2. To kill busy listening port 
```
sudo lsof -i :<Port number> #list pid 

kill -9 <pid>
```

3. Remote connection 
```

xfreerdp /cert-ignore /compression /auto-reconnect /u:USERNAME /p:PASSWORD /v:IP_ADDRESS

sudo rdesktop -u USERNAME -p PASSWORD -g 90% -r disk:local="/home/kali/Desktop/" IP-ADDRESS

rdesktop -u USERNAME -p PASSWORD -a 16 -P -z -b -g 1280x860 IP_ADDRESS

 xfreerdp /u:USERNAME /p:PASSWORD /cert:ignore /v:IP_ADDRESS /w:2600 /h:1400

xfreerdp +nego +sec-rdp +sec-tls +sec-nla /d: /u: /p: /v:IP_ADDRESS /u:USERNAME /p:PASSWORD /size:1180x708

rdesktop -z -P -x m -u USERNAME -p PASSWORD
```

4. Delete full directory. 
```
rm -r .wine/
```

5. Dependencies packages error solution
```
https://linuxsimply.com/linux-basics/package-management/dependencies/the-following-packages-have-unmet-dependencies/
```

6. File transfer cheatsheet
```
https://ironhackers.es/en/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/
```

7. Hacktricks if running out of ideas. 
```
https://book.hacktricks.xyz/
```

8. Rustscan instead of nmap
```
1. Scan open ports. 
rustscan -a 192.168.187.122 --ulimit 5000

2. Nano and paste open ports - open-ports.txt

3. List down open ports in one line with comma. 
cat open-ports.txt | cut -f1 -d '/' | tr '\n' ','

4. Or straight can scan with nmap
nmap -p$(cat open-ports.txt | cut -f1 -d '/' | tr '\n' ',') -T4 -A $ip 

5. Decrease mtu rate if needed 
ifconfig tun0 mtu 1250

```

9. Allocating IP. 
```
export ip=10.10.10.10
echo $ip
```

10. Alternative for gobuster 
```
feroxbuster -u http://$ip/
```

