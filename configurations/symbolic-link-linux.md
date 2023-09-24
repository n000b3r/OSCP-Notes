# Symbolic Link (Linux)

### Check PATH

```
echo $PATH
```

{% hint style="info" %}
Placing binaries in PATH allows us to call it easily
{% endhint %}

### Creating Symbolic Link

```bash
ln -s /home/kali/Downloads/smb_version.sh /usr/bin/smb_version
```

{% hint style="info" %}
If `ln: failed to create symbolic link '/usr/bin/smb_version': File exists` error occurs, `rm /usr/bin/smb_version`
{% endhint %}

Now, the binary is in PATH, allowing us to call it

```bash
┌──(root㉿kali)-[/]
└─# smb_version              
Usage: ./smbver.sh RHOST {RPORT}
```
