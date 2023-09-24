---
description: Allows anonymous access, write permissions
---

# Vsftpd

```bash
apt-get install vsftpd 
```

Edit `/etc/vsftpd.conf` to the following:

<pre class="language-bash"><code class="lang-bash"><strong>anonymous_enable=YES
</strong>local_enable=NO
write_enable=YES
anon_upload_enable=YES
anon_mkdir_write_enable=YES
dirmessage_enable=YES
xferlog_enable=YES
connect_from_port_20=YES
listen=YES
anon_umask=022
anon_other_write_enable=YES
anon_root=/var/ftp/
no_anon_password=YES
pasv_min_port=40000
pasv_max_port=50000
allow_writeable_chroot=YES

</code></pre>

```bash
chmod a-w /var/ftp
```

Remove all writing privileges (from any group).

```bash
chmod 777 /var/ftp/pub
```

```bash
systemctl start vsftpd
systemctl status vsftpd
```

