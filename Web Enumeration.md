1. Install golang
```
https://github.com/Dewalt-arch/pimpmykali

command: sudo ./pimpmykali.sh and then enter 3
```

2. Asset finder - create own script and run 
```
┌──(kali㉿kali)-[~/PNPT]
└─$ cat run.sh      
#!/bin/bash

$url=$1

if [ ! -d "$url" ];then
       mkdir $url
fi

if [ ! -d "$url/recon" ];then 
        mkdir $url/recon
fi

echo "[+] Harvesting subdomains with assetfinder..."
assetfinder $url >> $url/recon/assets.txt
cat $url/recon/assets.txt | grep $1 >> $url/recon/final.txt
rm $url/recon/assets.txt

┌──(kali㉿kali)-[~/PNPT]
└─$ ./run.sh tesla.com
[+] Harvesting subdomains with assetfinder...
```

3. Amass - subdomain finder 
```
┌──(kali㉿kali)-[~/PNPT]
└─$ amass enum -d tesla.com 
```