1. On linux usernames can be case sensitive
2. failing to enumerate user folders properly (didnt see the hidden file that was intended path)
3. getting stuck with wrong version of mimikatz that was not working on my target system
4. not enumerating snmp properly: snmpwalk -v2c -c public {RHOST} nsExtendObjects
5. not seeing the output of a binary that was the intended path, because it didnt show in evil-winrm (but would show over other shells like impacket psexec or ConPtyShell). When possible make an msvenom payload and get a better shell
6. you can upload and download with evil-winrm, the command expects full paths
7. forgetting to do “token::elevate” and failing to get lsadump contents on mimikats when all other commands would work
8. not finding an exploit because it wasnt on exploit-db.. always google and search github for exploits too
9. forgetting to try default credentials, always google for them, try admin:admin, username:username etc
10. if you find new credentials try them on every service you know. You find new service try every credential you have.
11. also remember to spray all combinations to test for credential re-use
12. when spraying with cme, also remember to do domain (-d lab.local) and local (--local-auth)
13. If you escalate, re-enumerate: forgot to look at powershell history after escalation
14. this one is dumb af.. failed to enumerate properly because mistyped or forgot port number on my ffuf command. This happened a few times
15. In web enumeration, failed to enumerate with extentions and didn’t find a .pdf that was the intended path. When there are only a few ports open, or all other options exhausted
16. Had LFI and didnt look for default ssh key files (there are more possible files than id_rsa)
17. there’s some weirdness with crackmapexec rdp where sometimes it doesn’t report a correct credential. also try impacket-rdp_check
18. had domain creds and forgot to enumerate share contents. do --shares with crackmapexec or try smbclient/smbmap
19. used wrong hashcat mode :’( check https://hashcat.net/wiki/doku.php?id=example_hashes
20. Saw a suspicious binary on a windows target tried to run it and moved on; it was actually running on a schedule and I didn’t think to try and replace it with a reverse shell.
21. After getting a foothold, didn’t realize there was a port that wasn’t accessible from outside
22. Didn’t try an exploit because the version on the description was newer than mine
23. Search uncommon setguid
