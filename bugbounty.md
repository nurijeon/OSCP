# RUN NMAP Safely
nmap -A -F -T1 10.10.x.x -v
-F: top 100 ports

# FUZZ for Directory
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://tenet.htb/FUZZ -p 1
-p: delay by 1s

# SHODAN
Crawls every single machine that's connected to the internet
Software vulnerability
Find new CVE and report it

```bash
shodan count wordpress 1.4.7
shodan download wpfile "wordpress 1.4.7"
gunzip wordpressfile.json.gz

shodan host 10.x.x.x
```

#
