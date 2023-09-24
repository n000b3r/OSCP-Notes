# Lame

### Scanning

<figure><img src="../../.gitbook/assets/image (31).png" alt=""><figcaption><p>Ports 21,22,139,445,3632 are up</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (206).png" alt=""><figcaption><p>Nmap aggressive scan part 1</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (92).png" alt=""><figcaption><p>Nmap aggressive scan part 2</p></figcaption></figure>

### Enumerating FTP

<figure><img src="../../.gitbook/assets/image (42).png" alt=""><figcaption><p>Anonymous FTP login allowed</p></figcaption></figure>

From the above Nmap scan results, it is evident that anonymous FTP login is allowed on the host.

Using the credentials (anonymous:), I managed to anonymously log into FTP server.

<figure><img src="../../.gitbook/assets/image (243).png" alt=""><figcaption><p>Successful Anonymous login</p></figcaption></figure>



### Exploiting SMB

<figure><img src="../../.gitbook/assets/image (266).png" alt=""><figcaption><p>Nmap results for SMB</p></figcaption></figure>

Searching the Samba version online, I found that it could be vulnerable to [CVE-2007-2447](https://github.com/amriunix/CVE-2007-2447).

After cloning the git repository, I set up a Netcat listener on port 4444 and ran the usermap\_script.py against the SMB server.&#x20;

<figure><img src="../../.gitbook/assets/image (256).png" alt=""><figcaption><p>Obtaining a root shell</p></figcaption></figure>

As seen from the above screenshot, I obtained a root shell from the listening netcat host.

<figure><img src="../../.gitbook/assets/image (208).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (251).png" alt=""><figcaption></figcaption></figure>

After stabilizing the shell, I obtained both user and root flags

User flag: 2cf83f41a92929ac635b7aafe5f54448

Root flag: 0c52c534d9d73482e7da0423cf4cf43b

### Exploiting Distccd

<figure><img src="../../.gitbook/assets/image (255).png" alt=""><figcaption><p>Nmap scan results for port 3632</p></figcaption></figure>

Searching for the Distccd v1 exploits, I came across [CVE-2004-2687](https://gist.github.com/DarkCoderSc/4dbf6229a93e75c3bdf6b467e67a9855).

Next, I downloaded the exploit and set up a netcat listener on port 4446. Afterwards, I ran the distccd\_rce\_CVE-2004-2687.py exploit script.

<figure><img src="../../.gitbook/assets/image (65).png" alt=""><figcaption><p>Obtained user shell</p></figcaption></figure>

From the above screenshot, I managed to obtain a user shell and was able to view the user flag.

<figure><img src="../../.gitbook/assets/image (264).png" alt=""><figcaption><p>user.txt</p></figcaption></figure>

### Privilege Escalation

I transferred linpeas.sh to the victim's machine by setting up a python SimpleHTTPServer and using wget to obtain the file from the attacker's machine.

<figure><img src="../../.gitbook/assets/image (293).png" alt=""><figcaption><p>Transferring linpeas.sh</p></figcaption></figure>

Next, I used the `chmod +x linpeas.sh` to enable execute privileges for the user. Next, I ran linpeas.sh.

<figure><img src="../../.gitbook/assets/image (297).png" alt=""><figcaption><p>Running linpeas.sh</p></figcaption></figure>

&#x20;

<figure><img src="../../.gitbook/assets/image (223).png" alt=""><figcaption></figcaption></figure>



From the output, Nmap has SUID bit set.

Searching it on GTFObins, I found that interactive mode on Nmap could be used to execute privileged shell commands.

<figure><img src="../../.gitbook/assets/image (283).png" alt=""><figcaption><p>GTFObins nmap</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (77).png" alt=""><figcaption><p>Nmap interactive root shell</p></figcaption></figure>

From above, I managed to spawn a root shell using Nmap when the SUID bit is set.&#x20;

Lastly, I have obtained the root flag: 0c52c534d9d73482e7da0423cf4cf43b
