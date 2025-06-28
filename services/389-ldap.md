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

<pre class="language-bash"><code class="lang-bash">nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host> --admin-count
nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host>  --asreproast ASREPROAST
nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host>  --groups

nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host>  --kerberoasting KERBEROASTING
<strong>nxc ldap dc1.scrm.local -u ksimpson -p ksimpson -d scrm.local -k --kerberoasting hash
</strong>
nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host>  --password-not-required
nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host>  --trusted-for-delegation
nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host>  --users

# Modules
nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host> -M get-desc-users
nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host> -M laps
nxc ldap &#x3C;IP> -u &#x3C;User> -p &#x3C;Password> --kdcHost &#x3C;Host> -M ldap-signing
</code></pre>

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
