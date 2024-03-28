# Checklist
- [ ] Run systeminfo 
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

