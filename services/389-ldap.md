# (389) LDAP

<details>

<summary>ldapsearch</summary>

```bash
# Get all users
ldapsearch -x -H ldap://<IP> -D '<Domain>\<User>' -w '<Password>' -b 'DC=security,DC=local'

# Get all users and cleanup output
ldapsearch -x -H ldap://<IP> -D '<Domain>\<User>' -w '<Password>' -b 'DC=security,DC=local' | grep userPrincipalName | sed 's/userPrincipalName: //'

# Without credentials
ldapsearch -x -H ldap://<IP> -b 'DC=security,DC=local'
ldapsearch -x -H ldap://<IP> -b 'DC=security,DC=local' | grep userPrincipalName | sed 's/userPrincipalName: //'
```

</details>

<details>

<summary>nxc</summary>

```bash
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host> --admin-count
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --asreproast ASREPROAST
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --groups
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --kerberoasting KERBEROASTING
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --password-not-required
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --trusted-for-delegation
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host>  --users

# Modules
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host> -M get-desc-users
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host> -M laps
nxc ldap <IP> -u <User> -p <Password> --kdcHost <Host> -M ldap-signing
```

</details>

<details>

<summary>ldapdomaindump</summary>

```bash
# With Credentials
ldapdomaindump -u security.local\\<User> -p '<Password>' ldap://<IP>

# Without credentials
ldapdomaindump ldap://<IP>
```

</details>
