# Scanning

<details>

<summary>Nmap</summary>

```shell
nmap -p- -T5 <ip>
nmap -p 22,25,80 -A <ip>
```

```bash
nmap -p- --min-rate 5000 <ip>
```

```bash
nmap -sn 192.168.102.0/24 -T4 -oN discovery.nmap
nmap -iL output.txt -T4 -sV -sC -p- -Pn -n --open -A -oN version.nmap
```

```bash
nmap -sU -p- --min-rate 5000 <ip>
```

* Conduct a full UDP port scan (may be all `open|filtered`) because open ports rarely respond to empty probes. No response --> open port or dropped by firewall.

```bash
nmap -A -sV -sC -sU 10.11.1.111 --script=*enum --top-ports 20
```

* When version scanning is enabled with -sV (or -A), it will send UDP probes to every `open|filtered` port. If any of the probes elicit a response from an `open|filtered`port, the state is changed to open.

```bash
nmap script=vuln 192.168.193.211
```

* Nmap scripts location `/usr/share/nmap/scripts/`

</details>

<details>

<summary>Nmap Proxychains</summary>

```bash
proxychains nmap --top-ports=20 -sT -Pn 10.5.5.20
```

* SOCKS proxies require a TCP connection to be made and thus a half-open or SYN scan cannot be used with ProxyChains

Scans thru Socks proxy

```sh
nmap --proxies socks4://proxy-ip:8080 target-ip
```

</details>

<details>

<summary>Nmap Static Binary</summary>

### Full Port Scan

```bash
nmap -p- --min-parallelism 10 -P0 10.2.2.31
```

</details>

<details>

<summary>Portscan.sh</summary>

```bash
#!/bin/bash
host=10.5.5.11
for port in {1..65535}; do
    timeout .1 bash -c "echo >/dev/tcp/$host/$port" &&
        echo "port $port is open"
done
echo "Done"
```

</details>

<details>

<summary>Ping Sweep</summary>

#### Linux&#x20;

```bash
for i in {1..254} ;do (ping -c 1 172.21.10.$i | grep "bytes from" &) ;done
```

#### Windows

```bash
for /L %i in (1,1,255) do @ping -n 1 -w 200 172.21.10.%i > nul && echo 192.168.1.%i is up.
```

</details>

<details>

<summary>Port Knock</summary>

### Look at /etc/knockd.conf (Port Knock configurations)

```bash
www-data@nineveh:/home/amrois$ cat /etc/knockd.conf 
[options]
 logfile = /var/log/knockd.log
 interface = ens160

[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn

```

### Using Nmap for port knocking

```
┌──(root㉿kali)-[/home/…/htb/10.10.10.43/_nineveh.png.extracted/secret]
└─# for i in 571 290 911; do
for> nmap -Pn --host-timeout 100 --max-retries 0 -p $i 10.10.10.43 >/dev/null 

for> done; ssh -i nineveh.priv amrois@10.10.10.43

The authenticity of host '10.10.10.43 (10.10.10.43)' can't be established.
ED25519 key fingerprint is SHA256:kxSpgxC8gaU9OypTJXFLmc/2HKEmnDMIjzkkUiGLyuI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.43' (ED25519) to the list of known hosts.
Ubuntu 16.04.2 LTS
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

288 packages can be updated.
207 updates are security updates.


You have mail.
Last login: Mon Jul  3 00:19:59 2017 from 192.168.0.14
amrois@nineveh:~$ whoami
amrois

```

</details>

<details>

<summary>Autorecon</summary>

```bash
autorecon <target>
```

```bash
proxychains -q autorecon 10.1.1.65 --proxychains
```

</details>

<details>

<summary>Through Squid Proxy</summary>

```bash
python3 spose.py --proxy http://192.168.163.189:3128 --target 192.168.163.189
```

</details>
