# Create new SSH root user

### Create new root user

<pre class="language-bash"><code class="lang-bash"><strong>useradd bill
</strong></code></pre>

```
passwd bill
```

```bash
usermod -aG sudo bill
```

### Ensure that SSH config allows root login

```
vim /etc/ssh/sshd_config
```

* Ensure that  _`PermitRootLogin yes`_

### Restart SSH Server

#### RedHat

```
service sshd restart
```

#### Ubuntu

```
sudo systemctl restart ssh
```
