# SMB Share

<details>

<summary>Powershell Method</summary>

On Sender:

```
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
net share PublicShare=C:\temp /GRANT:Everyone,FULL
```

On Receiver:

```
copy \\appsrv01\PublicShare\mimikatz.exe .
```

</details>

<details>

<summary>GUI Method</summary>

* Right click --> New --> Folder --> name it
  * ![](../.gitbook/assets/image.png)\

* Right click folder --> Properties --> Sharing --> Advanced Sharing --> Share this folder --> Permissions
  *

      <figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>


  *

      <figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

      <figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>


  * Set SMB Share permissions (Full Control --> allow for all)
    *

        <figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>


    *

        <figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

</details>
