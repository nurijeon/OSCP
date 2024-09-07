Check SPF
sfp: domain owners to specify which mail servers are authorized to send emails on behalf of their domain.

nslookup
```bash
nslookup -type=txt shodan.io | grep -i spf
```

dig
```bash
dig TXT shodan.io | grep -i spf
```
