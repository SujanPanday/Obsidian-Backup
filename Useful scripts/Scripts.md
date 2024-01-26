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