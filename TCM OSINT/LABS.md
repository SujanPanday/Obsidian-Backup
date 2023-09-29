
## Building an OSINT Lab
VMWare Workstation Player - [https://www.vmware.com/ca/products/workstation-player/workstation-player-evaluation.html](https://www.vmware.com/ca/products/workstation-player/workstation-player-evaluation.html)

VirtualBox - [https://www.virtualbox.org/wiki/Downloads](https://www.virtualbox.org/wiki/Downloads)

TraceLabs OSINT VM - [https://www.tracelabs.org/initiatives/osint-vm](https://www.tracelabs.org/initiatives/osint-vm)

TraceLabs OSINT VM Installation Guide - [https://download.tracelabs.org/Trace-Labs-OSINT-VM-Installation-Guide-v2.pdf](https://download.tracelabs.org/Trace-Labs-OSINT-VM-Installation-Guide-v2.pdf)



## Working with OSINT Tools

#### Image and Location OSINT
```
sudo apt install libimage-exiftool-perl exiftool <img>

exiftool <img>
```

#### Hunting Emails and Breached Data
breach-parse - [https://github.com/hmaverickadams/breach-parse](https://github.com/hmaverickadams/breach-parse)

```
theHarvester -d tesla.com -b google -l 500
./breach-parse.sh @tesla.com tesla.txt 
h8mail -t shark@tesla.com -bc "/opt/breach-parse/BreachCompilation/" -sk
```

#### Username and Account OSINT
```
whatsmyname -u thecybermentor 
sherlock thecybermentor
```

#### Phone Number OSINT
```
phoneinfoga scan -n 14082492815 
phoneinfoga serve -p 8080
```

#### Social Media OSINT
```
pip3 install --upgrade -e git+https://github.com/twintproject/twint.git@origin/master#egg=twint 
pip3 install --upgrade aiohttp_socks
```
Twint - [https://github.com/twintproject/twint](https://github.com/twintproject/twint)

#### Website OSINT
Subfinder - [https://github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)

Assetfinder - [https://github.com/tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder)

httprobe - [https://github.com/tomnomnom/httprobe](https://github.com/tomnomnom/httprobe)

Amass - [https://github.com/OWASP/Amass](https://github.com/OWASP/Amass)

GoWitness - [https://github.com/sensepost/gowitness/wiki/Installation](https://github.com/sensepost/gowitness/wiki/Installation)

```
whois tcm-sec.com 

nano ~/.bashrc 

export GOPATH=$HOME/go 
export GOROOT=/usr/lib/go 
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin 

source ~/.bashrc 

go get -u github.com/tomnomnom/httprobe 
go get -u github.com/tomnomnom/assetfinder GO111MODULE=on 
go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder go get -u github.com/sensepost/gowitness export GO111MODULE=on 
go get -v github.com/OWASP/Amass/v3/... 

subfinder -d tcm-sec.com 
assetfinder tcm-sec.com 
amass enum -d tcm-sec.com 
cat tesla.txt | sort -u | httprobe -s -p https:443 
gowitness file -f ./alive.txt -P ./pics --no-http
```


#### Exploring OSING Frameworks

1. Recon-ng
2. Maltego
3. 