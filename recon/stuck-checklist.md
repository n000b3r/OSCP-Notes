# Stuck Checklist

<details>

<summary>Foothold</summary>

* Reset the box and try running exploit again

- Enumerate all ports (including UDP)
  * Banner grabbing: `nc -v <Victim IP> <Port>`
  * Google/[HackTricks ](https://book.hacktricks.xyz/welcome/readme)each service version
  * Manually probe each service/ Input location/ URL path
  * Testing out with default creds or common creds (admin:admin)
  * `autorecon <target>`
- Password Reuse (try with previously obtained passwords)
- Try login with (`admin:<name of box>`, `<name of box>:<name of box>`)
- Brute-Force all login (with rockyou.txt)
- Trying to access the port using a browser (http\[s]://\<Victim IP>)
- Is the port a rabbit hole or actually exploitable?

</details>

<details>

<summary>Web Server</summary>

* `/robots.txt`, `/sitemap.xml, /CHANGELOG`
* Manually probe each input point with Burp (for Code Injection(`2*2`), SQLi (test numerous payloads like `' OR 1=1 LIMIT 1-- -`, LFI, XSS)&#x20;
* Try both https://\<victim> and http://\<victim>
* `nikto -host http://<victim>`
* Directory busting using different wordlists (lowercase or not?), different extensions
* Dirbusting with other tools with their default wordlists
* Subdomain enumeration?
* Use Burp to see response header
* Is `/cgi-bin` writable --> shellshock?
* Check source code of pages (look for comments)

- For LFI,
  * What Services are Running? (Eg: Filezilla FTP, SSH, Apache)
    * Guess File Locations (Eg: config files, SSH keys, password files)

</details>

<details>

<summary>PrivEsc</summary>

* Check netw connections (`netstat -ano`, `ss -antlp`)
  * Port Forward internal services (Eg: MySQL on port 3306)
* Manually check for installed apps
* Check Powershell history file (`PS C:> cd $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\`)
  * $env:APPDATA --> `C:\Users\WQ\AppData\Roaming`
  * Full File path --> `C:\Users\WQ\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`
* Check PATH (user & system paths)
* Read config files for Services (Eg: wp-config.php, FileZilla Server.xml)
* Kernel Exploits

</details>

<details>

<summary>Using a particular tool (eg: scp, ssh)</summary>

* Google Error message
* Try git@host with ssh private key --> use private key to clone gitlab repo?

- Are you connecting to a legacy SSH/SCP service ?
  * SSH: `-o KexAlgorithms=diffie-hellman-group14-sha1 -oHostKeyAlgorithms=+ssh-dss`
  * SCP : `-O`

</details>

<details>

<summary>AD</summary>

* Impacket-secretsdump for all domain users and local admin and spray their passwords/hashes on all domain hosts using nxc
* If got file upload restrictions --> use Evil-WinRM's download/upload functionality
* If victim unable to reach attacker --> Setup reverse port forward to remote server
* If unable to PrivEsc --> think about lateral movement (To IIS user, kerberoasting)
* Login to all users, may have interesting executables
* For lateral movement --> Try PsExec, Evil-WinRM, RDP, SSH
* Bruteforce passwords against found usernames
* Mimikatz no output --> use secretsdump
* If see backup of windows folder/ windows.old --> means SAM Dump
* Look for credentials in powershell history (`PS C:> cd $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\)`

</details>

<details>

<summary>Cheatsheet for Reference</summary>

[https://blog.aghanim.net/?page\_id=1809](https://blog.aghanim.net/?page_id=1809)

[https://gitlab.com/lagarian.smith/oscp-cheat-sheet/-/blob/master/OSCP\_Notes.md](https://gitlab.com/lagarian.smith/oscp-cheat-sheet/-/blob/master/OSCP_Notes.md#port-25-smtp)

[https://www.otacanonline.com/oscp-methodology](https://www.otacanonline.com/oscp-methodology)

[https://johntuyen.com/personal/2019/05/25/personal-oscpcheatsheet.html#exploit-chain](https://johntuyen.com/personal/2019/05/25/personal-oscpcheatsheet.html#exploit-chain)

[https://notchxor.github.io/oscp-notes/0-basics/1-network-basics/](https://notchxor.github.io/oscp-notes/0-basics/1-network-basics/)

[https://mqt.gitbook.io/oscp-notes/](https://mqt.gitbook.io/oscp-notes/)

[https://notes.offsec-journey.com/system-hacking/pivot](https://notes.offsec-journey.com/system-hacking/pivot)



AD:

[https://blog.aghanim.net/?p=2078](https://blog.aghanim.net/?p=2078)

</details>
