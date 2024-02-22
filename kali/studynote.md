[Firewall](#firewall)
[File System](#file-system)

## Firewall

```bash
1. List configuration
# iptables -nL
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination     

2. Add a configuration: Block TCP/80
# iptables -A INPUT -p tcp --dport 80 -j DROP

3. List all config and delete configuration
# iptables -L --line-numbers
# iptables -D INPUT 1

4. Save configuration(rules 확장자 상관없음)
# iptables-save > 20240222.rules

5. Restore using saved file
# iptables-restore < 20240222.rules

```


## File System
```bash
# Show currently mounted disks
lsblk

# Show usage of disk
df

```
