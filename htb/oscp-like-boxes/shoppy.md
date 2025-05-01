# Shoppy

### Scanning

Firstly, I started off with a full port scan on the target.&#x20;

<figure><img src="../../.gitbook/assets/image (286).png" alt=""><figcaption><p>Fig 1. Nmap full port scan</p></figcaption></figure>

From figure 1, it is evident that ports 22,80 and 9093 were open. Next, I ran an aggressive Nmap scan on all those open ports.

<figure><img src="../../.gitbook/assets/image (26).png" alt=""><figcaption><p>Fig 2. Nmap aggressive scan part 1</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (204).png" alt=""><figcaption><p>Fig 3. Nmap aggressive scan part 2</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (228).png" alt=""><figcaption><p>Fig 4. Nmap aggressive scan part 3</p></figcaption></figure>

### Enumerating HTTP

From Fig 2, the target is likely to be a debain machine that runs a Nginx server. From the HTTP title shown in Fig 2, it suggests that we should add an entry for`shoppy.htb` to our `/etc/hosts` file with the corresponding IP address to be able to access this domain in our browser.

<figure><img src="../../.gitbook/assets/image (210).png" alt=""><figcaption><p>Fig 5. Adding domain to /etc/hosts</p></figcaption></figure>

Afterwards, I opened up `/etc/hosts` file and added in the target IP as well as the domain name `shoppy.htb`.

<figure><img src="../../.gitbook/assets/image (281).png" alt=""><figcaption><p>Fig 6. Landing page</p></figcaption></figure>

Heading over to `shoppy.htb`, I was greeted by a large countdown timer for the supposed launch of Shoppy Beta.

I ran dirsearch in the background to uncover subdirectories and I found the login page at `/login`.

<figure><img src="../../.gitbook/assets/image (274).png" alt=""><figcaption><p>Fig 7. Dirsearch results</p></figcaption></figure>

Heading over to the `/login` page, I was greeted by a simple login screen asking for my Username and Password.

<figure><img src="../../.gitbook/assets/image (276).png" alt=""><figcaption><p>Fig 8. Admin login page</p></figcaption></figure>

Upon trying the default "admin:admin" credentials, I was redirected to `/login?error=WrongCredentials`.

<figure><img src="../../.gitbook/assets/image (68).png" alt=""><figcaption><p>Fig 9. Wrong credentials</p></figcaption></figure>

The following burpsuite request and response depicts the scenario where incorrect credentials were used.

<figure><img src="../../.gitbook/assets/image (88).png" alt=""><figcaption><p>Fig 10. Burpsuite request and response for incorrect credentials</p></figcaption></figure>

Fig 11 shows a simple test for the presence of SQLi in the login page by appending a single quote after the username string. However, as seen in the Response, the web server does not give us a valid response back.

<figure><img src="../../.gitbook/assets/image (207).png" alt=""><figcaption><p>Fig 11. No response when SQLi</p></figcaption></figure>

After facing a roadblock when testing for the presence of SQLi, I enumerated further, trying to uncover the underlying framework that built this web app. By going to a non-existent subdirectory, I was greeted by a "Cannot GET /subdirectory\_nam&#x65;_"_ message.&#x20;

<figure><img src="../../.gitbook/assets/image (285).png" alt=""><figcaption><p>Fig 12. Error message when browsing non-existent subdirectories</p></figcaption></figure>

Searching for the error message online, I was able to find that it most likely belongs to a Node.js web app.

<figure><img src="../../.gitbook/assets/image (216).png" alt=""><figcaption><p>Fig 13. Google Search for error message</p></figcaption></figure>

Since most node.js web apps are powered by MongoDB, our SQLi needs to be tweaked for the NoSQL syntax.

The `Content-Type: x-www-form-urlencoded` can be changed to `Content-Type: application/json` and the post parameters could be passed as a JSON object.

<figure><img src="../../.gitbook/assets/image (269).png" alt=""><figcaption><p>Fig 14. Change Content-Type to application/json</p></figcaption></figure>

By omitting the `password` field, I obtained the following error message in Fig 15. From the error logs, it is evident that the the user `jaeger` was present on the target.

<figure><img src="../../.gitbook/assets/image (211).png" alt=""><figcaption><p>Fig 15. User named jaeger</p></figcaption></figure>

Viewing for a Mongo SQLi [here](https://book.hacktricks.xyz/pentesting-web/nosql-injection#sql-mongo), I found the payload `' || 1==1`

<figure><img src="../../.gitbook/assets/image (66).png" alt=""><figcaption><p>Fig 16. Mongodb SQLi</p></figcaption></figure>

Taking reference to the above payload and contextualizing it, I used the payload `admin'||'1'='1` . From the burpsuite's response, I was able to authenticate into the admin console.

<figure><img src="../../.gitbook/assets/image (54).png" alt=""><figcaption><p>Fig 16. Successful SQLi</p></figcaption></figure>

Trying out the SQLi on the webpage itself, I managed to login.

<figure><img src="../../.gitbook/assets/image (27).png" alt=""><figcaption><p>Fig 17: Trying out SQLi </p></figcaption></figure>

Fig 18 shows the admin console of the Shoppy web app. The `search for users` functionality on the top right caught my attention.

<figure><img src="../../.gitbook/assets/image (45).png" alt=""><figcaption><p>Fig 18. Logged in to admin console</p></figcaption></figure>

Clicking on it and keying in `admin`, I obtained the database entry belonging that of the admin.

<figure><img src="../../.gitbook/assets/image (267).png" alt=""><figcaption><p>Fig 19. Search "admin" and export details</p></figcaption></figure>

I decided to enumerate the database further in hopes of dumping all the records. I used the command `admin'||'1'=='1 to view all records of the Shoppy App.`

<figure><img src="../../.gitbook/assets/image (271).png" alt=""><figcaption><p>Fig 20. Search for all users</p></figcaption></figure>

Now, I obtained the password hash of 2 users, namely the admin and the josh user.

<figure><img src="../../.gitbook/assets/image (86).png" alt=""><figcaption><p>Fig 21. Database dump</p></figcaption></figure>

Using Crackstation, I managed to crack Josh's hash to be `remebermethisway`. Howerver, I was unable to login to the SSH server using`josh:remembermethisway.`

<figure><img src="../../.gitbook/assets/image (268).png" alt=""><figcaption><p>Fig 22. Josh's password cracked</p></figcaption></figure>

Next, I decided to conduct further enumeration particularly on uncovering the subdomains on `shoppy.htb`. I used the ffuf command `ffuf -u http://shoppy.htb/ -H "Host: FUZZ.shoppy.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fw 5`

<figure><img src="../../.gitbook/assets/image (263).png" alt=""><figcaption><p>Fig 23. Enumerating subdomains</p></figcaption></figure>

From the figure above, I found the subdomain `mattermost`, which is an open-source, self-hostable online chat service that is mainly used internally within an organization.

<figure><img src="../../.gitbook/assets/image (282).png" alt=""><figcaption><p>Fig 24. Add subdomain to /etc/hosts</p></figcaption></figure>

Using Josh's credentials, I was able to login to his mattermost account. Viewing the `Deploy Machine` channel, I found the following.

<figure><img src="../../.gitbook/assets/image (240).png" alt=""><figcaption><p>Fig 25. Jaeger credentials</p></figcaption></figure>

After obtaining jaeger's credentials, I then proceeded to login to the SSH server and was able to obtain `user.txt`.

<figure><img src="../../.gitbook/assets/image (238).png" alt=""><figcaption><p>Fig 26. Obtained user flag</p></figcaption></figure>

### Privilege Escalation

Checking the `sudo -l` for jaeger, I can see that he was able to run `/home/deploy/password-manager` as the user `deploy`.

<figure><img src="../../.gitbook/assets/image (253).png" alt=""><figcaption><p>Fig 27. Jaeger able to run password-manager as user deploy</p></figcaption></figure>

Viewing the permissions inside the directory `/home/deploy`, I was not able to view the `creds.txt` and `password-manager.cpp` files.

<figure><img src="../../.gitbook/assets/image (226).png" alt=""><figcaption><p>Fig 28. Permissions for files in /home/deploy</p></figcaption></figure>

Let's run the `/home/deploy/password-manager` file as the user `deploy`. It seems that I need the master password in order to view the passwords inside the Josh password manager.

<figure><img src="../../.gitbook/assets/image (237).png" alt=""><figcaption><p>Fig 29. Running password-manager</p></figcaption></figure>

Using `strings` command and specifying the encoding as little endian, I obtained the string `Sample`.

<figure><img src="../../.gitbook/assets/image (215).png" alt=""><figcaption><p>Fig 30. Strings with little endian format</p></figcaption></figure>

Keying in `Sample` as the master password, I was able to obtain the credentials for the user `deploy`.

<figure><img src="../../.gitbook/assets/image (10) (1) (1) (1) (1) (1).png" alt=""><figcaption><p>Fig 31. Obtained deploy creds</p></figcaption></figure>

Switching to user `deploy` , I realised that it is not able to run `sudo` on the target machine.

<figure><img src="../../.gitbook/assets/image (44).png" alt=""><figcaption><p>Fig 32. Unable to run sudo on deploy</p></figcaption></figure>

Checking the `id` on `deploy`, we can see that it is in the `docker` group.

<figure><img src="../../.gitbook/assets/image (272).png" alt=""><figcaption><p>Fig 33. Deploy part of docker group</p></figcaption></figure>

I was then able to use docker to obtain root privileges and got `root.txt` file.

<figure><img src="../../.gitbook/assets/image (239).png" alt=""><figcaption><p>Fig 34. Docker privilege Escalation</p></figcaption></figure>
