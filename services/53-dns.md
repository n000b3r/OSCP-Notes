# (53) DNS

<details>

<summary>Reverse DNS Lookup</summary>

### Using Nslookup

```bash
nslookup
> server 10.10.10.13
#Default server: 10.10.10.13
#Address: 10.10.10.13#53
> 10.10.10.13
#;; communications error to 10.10.10.13#53: timed out
#13.10.10.10.in-addr.arpa	name = ns1.cronos.htb.
```

</details>

<details>

<summary>Zone Transfer</summary>

<pre class="language-bash"><code class="lang-bash">dig @10.10.10.13 AXFR cronos.htb
#; &#x3C;&#x3C;>> DiG 9.18.12-1-Debian &#x3C;&#x3C;>> @10.10.10.13 AXFR cronos.htb
#; (1 server found)
#;; global options: +cmd
#cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
#cronos.htb.		604800	IN	NS	ns1.cronos.htb.
#cronos.htb.		604800	IN	A	10.10.10.13
#admin.cronos.htb.	604800	IN	A	10.10.10.13
#ns1.cronos.htb.		604800	IN	A	10.10.10.13
#www.cronos.htb.		604800	IN	A	10.10.10.13
#cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
#;; Query time: 167 msec
#;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
<strong>#;; WHEN: Tue May 09 23:07:08 EDT 2023
</strong></code></pre>

</details>

<details>

<summary>Subdomain Enumeration</summary>

```bash
gobuster dns -d cronos.htb -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt 
```

```bash
ffuf -u http://shoppy.htb/ -H "Host: FUZZ.shoppy.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw <no. of words for default page>
```

### Add any subdomain you've found into `/etc/hosts`

```
10.10.57.54 dev.cmess.htm
```

</details>
