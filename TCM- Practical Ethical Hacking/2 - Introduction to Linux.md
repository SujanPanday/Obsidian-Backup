## SUDO
```
sudo su -
```


## Navigating the file system. 
`pwd` (Print Working Directory):

- - Explanation: Displays the current working directory. 
    - Example: Running `pwd` in the terminal would show the absolute path of the current directory, such as "/home/user/documents".

`cd` (Change Directory):

- - Explanation: Allows you to change the current working directory.
    - Example: Running `cd /home/user/documents` would change the directory to "/home/user/documents".

`cd ..` (Change to Parent Directory):

- - Explanation: Moves up one level in the directory hierarchy.
    - Example: Running `cd ..` in "/home/user/documents" would move to the "/home/user" directory.

`ls` (List Directory Contents):

- - Explanation: Lists the files and directories in the current directory.
    - Example: Running `ls` would display the files and directories in the current directory.

`ls -la` (List Detailed Directory Contents):

- - Explanation: Lists detailed information about files and directories, including hidden files.
    - Example: Running `ls -la` would display a detailed list of files and directories, including hidden files, in the current directory.

`mkdir` (Make Directory):

- - Explanation: Creates a new directory.
    - Example: Running `mkdir new_folder` would create a new directory named "new_folder" in the current directory.

`rmdir` (Remove Directory):

- - Explanation: Removes an empty directory.
    - Example: Running `rmdir empty_folder` would remove the directory named "empty_folder" if it is empty.

`man` (Manual):

- - Explanation: Displays the manual pages for a specified command.
    - Example: Running `man ls` would show the manual pages with detailed information about the `ls` command.

`echo`:

- - Explanation: Displays text or variables as output.
    - Example: Running `echo "Hello, world!"` would output "Hello, world!" in the terminal.

`>` (Output Redirection):

- - Explanation: Redirects the output of a command to a file and overwrites the file if it already exists.
    - Example: Running `echo "Hello" > greeting.txt` would write the text "Hello" to a file named "greeting.txt" or overwrite the file if it exists.

`>>` (Append Output):

- - Explanation: Redirects the output of a command and appends it to a file.
    - Example: Running `echo "World!" >> greeting.txt` would append the text "World!" to the end of the "greeting.txt" file.

`rm` (Remove):

- - Explanation: Deletes files or directories.
    - Example: Running `rm file.txt` would delete the file named "file.txt" from the current directory.

`mv` (Move):

- - Explanation: Moves or renames files and directories.
    - Example: Running `mv file.txt new_directory/file_renamed.txt` would move the file "file.txt" to the "new_directory" and rename it as "file_renamed.txt".

`cp` (Copy):

- - Explanation: Copies files and directories.
    - Example: Running `cp file.txt backup/file_copy.txt` would create a copy of "file.txt" named "file_copy.txt" in the "backup" directory.

`locate`:

- - Explanation: Searches for files and directories in a prebuilt database.
    - Example: Running `locate myfile.txt` would search for the file named "myfile.txt" in the prebuilt database and display its path if found.

`updatedb`:

- - Explanation: Updates the database used by the `locate` command to reflect recent changes in the file system.
    - Example: Running `updatedb` would update the database, allowing the `locate` command to provide up-to-date search results.

`passwd`:

- - Explanation: Allows a user to change their password.
    - Example: Running `passwd` would prompt the user to enter their current password and then set a new password.


## User and Privileges 
`chmod` (Change Mode):

- - Explanation: Changes the permissions of a file or directory.
    - Example: Running `chmod +x script.sh` would add the execute permission to the file "script.sh", allowing it to be executed as a script.

`adduser`:

- - Explanation: Creates a new user account.
    - Example: Running `adduser john` would create a new user account with the username "john" and prompt for additional user information.

`su` (Switch User):

- - Explanation: Allows a user to switch to another user account.
    - Example: Running `su jane` would switch to the user account "jane" after entering the password for that account.

`/etc/sudoers`:

- - Explanation: Displays the content of the "/etc/sudoers" file, which contains configuration information for the `sudo` command.
    - Example: Running `/etc/sudoers` would display the configuration directives for `sudo` access and permissions.

`sudo -l`:

- - Explanation: Lists the commands a user is allowed to run with `sudo` privileges.
    - Example: Running `sudo -l` would display the commands and permissions available to the current user with `sudo` access.

![[Pasted image 20230921145800.png]]


## Common Network Commands
`ip a`:

- - Explanation: Displays the network interfaces and their associated IP addresses.
    - Example: Running `ip a` would show information about network interfaces, including their IP addresses, MAC addresses, and other details.

`ifconfig`:

- - Explanation: Displays the configuration and status of network interfaces.
    - Example: Running `ifconfig` would show the configuration details, including IP addresses, MAC addresses, and other information for active network interfaces.

`iwconfig`:

- - Explanation: Displays the configuration and status of wireless network interfaces.
    - Example: Running `iwconfig` would show the configuration details, such as wireless signal strength, frequency, and encryption information, for active wireless interfaces.

`ip n`:

- - Explanation: Displays the Neighbor Table, which contains the IP-to-MAC address mappings for devices in the local network.
    - Example: Running `ip n` would show the IP and MAC addresses of devices that have recently communicated with the current device.

`arp -a`:

- - Explanation: Displays the ARP (Address Resolution Protocol) cache, which maps IP addresses to MAC addresses.
    - Example: Running `arp -a` would show the IP and MAC addresses of devices that have been resolved recently by the ARP protocol.

`ip r`:

- - Explanation: Displays the routing table, which contains information about network routes.
    - Example: Running `ip r` would show the routing table, including destination networks, gateway IP addresses, and network interfaces.

`route`:

- - Explanation: Displays or manipulates the IP routing table.
    - Example: Running `route` would display the routing table, similar to the `ip r` command.

`ping`:

- - Explanation: Sends ICMP echo requests to a specified IP address to check network connectivity and measure round-trip time.
    - Example: Running `ping 8.8.8.8` would send ICMP echo requests to the IP address "8.8.8.8" (Google's DNS server) and display the round-trip time and packet loss statistics.


## Viewing, creating and editing files. 

echo "hello" > hey.txt:

Explanation: Creates a new file named "hey.txt" with the content "hello" and overwrites the file if it already exists.
Example: Running echo "hello" > hey.txt would create a file named "hey.txt" and write the word "hello" into it.
echo "hello again" >> hey.txt:

Explanation: Appends the content "hello again" to an existing file named "hey.txt" or creates a new file if it doesn't exist.
Example: Running echo "hello again" >> hey.txt would append the text "hello again" to the end of the "hey.txt" file.
touch newfile.txt:

Explanation: Creates a new empty file named "newfile.txt" or updates the timestamp of an existing file to the current time.
Example: Running touch newfile.txt would create an empty file named "newfile.txt" if it doesn't exist or update its timestamp if it already exists.
nano newfile.txt:

Explanation: Opens the text editor Nano and allows you to create or edit the content of a file named "newfile.txt".
Example: Running nano newfile.txt would open the Nano editor, where you can enter or modify text in the "newfile.txt" file.
mousepad newfile.txt:

Explanation: Opens the Mousepad text editor and allows you to create or edit the content of a file named "newfile.txt".
Example: Running mousepad newfile.txt would open the Mousepad editor, where you can enter or modify text in the "newfile.txt" file.

## Starting and stopping services

`sudo service apache2 start`:

- - Explanation: Starts the Apache web server service.
    - Example: Running `sudo service apache2 start` would initiate the Apache web server and make it available for serving web pages.

`sudo service apache2 stop`:

- - Explanation: Stops the Apache web server service.
    - Example: Running `sudo service apache2 stop` would halt the running Apache web server, shutting down any active web page serving.

`python3 -m http.server 80`:

- - Explanation: Starts a simple HTTP server using Python on port 80.
    - Example: Running `python3 -m http.server 80` would start a basic HTTP server on port 80, allowing you to serve files from the current directory.

`sudo systemctl enable ssh`:

- - Explanation: Enables the SSH (Secure Shell) service to start automatically on system boot.
    - Example: Running `sudo systemctl enable ssh` would configure the system to start the SSH service during system startup.

`sudo systemctl disable ssh`:

- - Explanation: Disables the SSH service from starting automatically on system boot.
    - Example: Running `sudo systemctl disable ssh` would prevent the SSH service from starting automatically during system startup.



## Installing and updating tools

`sudo apt update && sudo apt upgrade`:

- - Explanation: Updates the package lists and upgrades installed packages on a Debian-based Linux system using the APT package manager.
    - Example: Running `sudo apt update && sudo apt upgrade` would update the package lists to retrieve information about available updates, and then upgrade the installed packages to their latest versions.

`sudo apt install cron-daemon-common`:

- - Explanation: Installs the "cron-daemon-common" package using APT. Cron is a time-based job scheduler in Linux systems, and the "cron-daemon-common" package provides common files and utilities for the cron daemon.
    - Example: Running `sudo apt install cron-daemon-common` would download and install the "cron-daemon-common" package on the system.

`sudo git clone [https://github.com/Dewalt-arch/pimpmykali.git](https://github.com/Dewalt-arch/pimpmykali.git)`:

- - Explanation: Clones a Git repository from the specified URL using the Git version control system.
    - Example: Running `sudo git clone [https://github.com/Dewalt-arch/pimpmykali.git](https://github.com/Dewalt-arch/pimpmykali.git)` would clone the repository from the given URL and create a local copy of the repository's files and version history.


## Scripting with bash

```
                                                                                                     
┌──(kali㉿kali)-[~]
└─$ ping 192.168.179.128
PING 192.168.179.128 (192.168.179.128) 56(84) bytes of data.
64 bytes from 192.168.179.128: icmp_seq=1 ttl=64 time=0.017 ms
64 bytes from 192.168.179.128: icmp_seq=2 ttl=64 time=0.082 ms
64 bytes from 192.168.179.128: icmp_seq=3 ttl=64 time=0.024 ms
^Z
zsh: suspended  ping 192.168.179.128
                                                                                                     
┌──(kali㉿kali)-[~]
└─$ ping 192.168.179.128 -c 3 > ip.txt
                                                                                                     
┌──(kali㉿kali)-[~]
└─$ cat ip.txt 
PING 192.168.179.128 (192.168.179.128) 56(84) bytes of data.
64 bytes from 192.168.179.128: icmp_seq=1 ttl=64 time=0.050 ms
64 bytes from 192.168.179.128: icmp_seq=2 ttl=64 time=0.031 ms
64 bytes from 192.168.179.128: icmp_seq=3 ttl=64 time=0.072 ms

--- 192.168.179.128 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2037ms
rtt min/avg/max/mdev = 0.031/0.051/0.072/0.016 ms
                                                                                                     
┌──(kali㉿kali)-[~]
└─$ cat ip.txt | grep "64 bytes"
64 bytes from 192.168.179.128: icmp_seq=1 ttl=64 time=0.050 ms
64 bytes from 192.168.179.128: icmp_seq=2 ttl=64 time=0.031 ms
64 bytes from 192.168.179.128: icmp_seq=3 ttl=64 time=0.072 ms
                                                                                                     
┌──(kali㉿kali)-[~]
└─$ cat ip.txt | grep "64 bytes" | cut -d " " -f 4 
192.168.179.128:
192.168.179.128:
192.168.179.128:
                                                                                                     
┌──(kali㉿kali)-[~]
└─$ cat ip.txt | grep "64 bytes" | cut -d " " -f 5 
icmp_seq=1
icmp_seq=2
icmp_seq=3
                                                                                                     
┌──(kali㉿kali)-[~]
└─$ cat ip.txt | grep "64 bytes" | cut -d " " -f 4 | tr -d ":"
192.168.179.128
192.168.179.128
192.168.179.128

┌──(kali㉿kali)-[~]
└─$ touch ipsweep.sh

┌──(kali㉿kali)-[~]
└─$ nano ipsweep.sh
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cat ipsweep.sh 
#!/bin/bash

for ip in  `seq 1 254`; do
ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done

./ipsweep.sh 192.168.179
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ ./ipsweep.sh 192.168.179
192.168.179.1
192.168.179.2
192.168.179.128
192.168.179.2
192.168.179.1
192.168.179.128
^Z
zsh: suspended  ./ipsweep.sh 192.168.179
                                              


┌──(kali㉿kali)-[~]
└─$ cat ipsweep.sh
#!/bin/bash

if [ "$1" == "" ]
then
echo "You forgot an IP address!"
echo "Syntax: ./ipsweep.sh 192.168.179"

else
for ip in  `seq 1 254`; do
ping -c 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done
fi

┌──(kali㉿kali)-[~]
└─$ ./ipsweep.sh            
You forgot an IP address!
Syntax: ./ipsweep.sh 192.168.179
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ ./ipsweep.sh 192.168.179
192.168.179.2
192.168.179.1
192.168.179.128
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ ./ipsweep.sh 192.168.179
192.168.179.2
192.168.179.1
192.168.179.128
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ ./ipsweep.sh 192.168.179 > ips.txt
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ for ip in $(cat ip.txt); do nmap $ip; done --it does nmap for all ip in that list. 

```