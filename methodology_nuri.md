# Table of Content
- [General](#general)
  - [Important Locations](#important-locations)
- [Web Attacks](#web-attacks)
- [Windows Privilege Escalation](#windows-privilege-escalation)
  - [Manual Enumeration](#manual-enumeration)
  - [Service Binary Hijacking](#service-binary-hijacking)
  - [Service DLL Hijacking](#service-dll-hijacking)
  - [Unquoted Service Paths](#unquoted-service-paths)
  - [Scheduled Tasks](#scheduled-tasks)
  - [SeImpersonatePrivilege](#seimpersonateprivilege)


# General
## Important Locations
- Windows
  ```bash
  C:/Users/Administrator/NTUser.dat
  ```
- Linux
  ```bash
  /etc/passwd
  /etc/shadow
  /etc/aliases
  ```


# Windows Privilege Escalation

## Manual Enumeration

```bash
#User information&hostname
whoami /priv
whoami /groups
whoami /all
hostname

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

#Active network
netstat -ano

#Installed Applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

#Running processes
Get-Process

#Powershell History
type C:\Users\sathvik\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

```

## Service Binary Hijacking
```bash
```

## Service DLL Hijacking
```bash
```

## Scheduled Tasks
```bash
```

## Unquoted Service Paths
```bash
```
