# Squashed

### Scanning

Firstly, I started off with a full port scan on the host `10.10.11.191` using the command `nmap -p- 10.10.11.191 -T5`.

<figure><img src="../../.gitbook/assets/image (233).png" alt=""><figcaption><p>Fig 1. Nmap full port scan</p></figcaption></figure>

As seen from figure 1, ports 22, 80, 111, 2049, 35099, 46369, 48809, 54277 were open.

Next, I used the command `nmap -p 22,80,111,2049,35099,46369,48809,54277 -A 10.10.11.191 -T5` to conduct an aggressive scan.

<figure><img src="../../.gitbook/assets/image (221).png" alt=""><figcaption><p>Fig 2. Nmap aggressive scan part 1</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (244).png" alt=""><figcaption><p>Fig 3. Nmap aggressive scan part 2</p></figcaption></figure>

From fig 2 and 3, SSH, HTTP and NFS were open on the system.

### Enumerating HTTP&#x20;

Heading to the webpage, I was greeted by a furniture company's landing page.&#x20;

<figure><img src="../../.gitbook/assets/image (290).png" alt=""><figcaption><p>Fig 4. Furniture shop landing page</p></figcaption></figure>

Next, I ran a `dirsearch` scan to uncover interesting directories or files but found nothing particularly interesting.

<figure><img src="../../.gitbook/assets/image (273).png" alt=""><figcaption><p>Fig 5. Dirsearch results</p></figcaption></figure>

### Enumerating NFS

NFS is a server/client system enabling users to share files and directories across a network and allowing those shares to be mounted locally. While both useful and versatile, NFS has no protocol for authorization or authentication, making it a common pitfall for misconfiguration and therefore exploitation.

To start off, I ran the command `showmount -e 10.10.11.191` to list any available shares on the target machine.

<figure><img src="../../.gitbook/assets/image (63).png" alt=""><figcaption><p>Fig 6. List of available NFS shares</p></figcaption></figure>

We can see two globally accessible file-shares, as indicated by the star. We can have a look at their contents by mounting the directories.

The directories can be mounted using the commands `mount -t nfs 10.10.11.191:/home/ross /home/kali/Documents/htb/squashed/mapped -o nolock` and `mount -t nfs 10.10.11.191:/var/www/html /home/kali/Documents/htb/squashed/mapped_www -o nolock`

<figure><img src="../../.gitbook/assets/image (294).png" alt=""><figcaption><p>Fig 7. Mounting /home/ross share</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (254).png" alt=""><figcaption><p>Fig 8. Mounting /var/www/html share</p></figcaption></figure>

Using the command `ls -ld` I was able to view the permissions for the 2 shares. For the `mapped` directory which maps to the `/home/ross` directory, it is owned by the UID 1001 and belongs to the group with the ID 1001. For the `mapped_www` directory which maps to the `/var/www/html` directory, it is owned by the UID 2017, and belongs to the group with the ID of www-data.

<figure><img src="../../.gitbook/assets/image (13).png" alt=""><figcaption><p>Fig 9. File permissions</p></figcaption></figure>

### Exploit: NFS Imitation

<figure><img src="../../.gitbook/assets/image (51).png" alt=""><figcaption><p>Fig 10. Creating user dummy</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (236).png" alt=""><figcaption><p>Fig 11. Creating user dummy2</p></figcaption></figure>

Switching to the user `dummy`, I was able to view the /var/www/html share.

<figure><img src="../../.gitbook/assets/image (225).png" alt=""><figcaption><p>Fig 12. Viewing /var/www/html share</p></figcaption></figure>

Next, I copied the Pentestmonkey's php-reverse-shell.php file from `/usr/share/webshells/php/php-reverse-shell.php`.&#x20;

<figure><img src="../../.gitbook/assets/image (298).png" alt=""><figcaption><p>Fig 13. Copied PHP reverse shell</p></figcaption></figure>

Browsing over to the site `http://10.10.11.191/php-reverse-shell.php`, I was able to obtain a reverse shell.

<figure><img src="../../.gitbook/assets/image (249).png" alt=""><figcaption><p>Fig 14. Received reverse shell</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (23).png" alt=""><figcaption><p>Fig 15. Obtained user flag</p></figcaption></figure>

### Privilege Escalation

Switching to the user `dummy2`, I was able to view the /home/ross share.

<figure><img src="../../.gitbook/assets/image (245).png" alt=""><figcaption><p>Fig 16. Viewing /home/ross share</p></figcaption></figure>

There's a `Passwords.kdbx` file but I was unable to run keepass2john successfully.

<figure><img src="../../.gitbook/assets/image (231).png" alt=""><figcaption><p>Fig 17. Keepass2john failed</p></figcaption></figure>

Using the command `ls -la`, I was able to see that `.Xauthority` file was present. The presence of `.Xauthority` and `.xsession` files in the home directory indicate that a display might be configured, with ross potentially already authenticated.&#x20;

<figure><img src="../../.gitbook/assets/image (284).png" alt=""><figcaption><p>Fig 18. .Xauthority file present</p></figcaption></figure>

This theory is further supported by the fact that the display manager LightDM is found in the /etc/passwd file.

<figure><img src="../../.gitbook/assets/image (277).png" alt=""><figcaption><p>Fig 19. LightDM is present</p></figcaption></figure>

The `.Xauthority` file is used to store credentials in the form of cookies used by xauth when authenticating X sessions. When a session is started, the cookie is then used to authenticate the subsequent connections to that specific display.&#x20;

<figure><img src="../../.gitbook/assets/image (227).png" alt=""><figcaption><p>Fig 20. Base64 encode .Xauthority file</p></figcaption></figure>

After encoding the `.Xauthority` file, I used the command `echo "AQAADHNxdWFzaGVkLmh0YgABMAASTUlULU1BR0lDLUNPT0tJRS0xABDP+dRpKdO/F+qG/DgGII9u" | base64 -d > /tmp/.Xauthority` to save the `.Xauthority` file in the `/tmp` folder.

Next, I set the XAUTHORITY environmental variable to the newly created `.Xauthority` file.

Then, I issued the command `w` to know which display ross is using.

Lastly, I used the command `xwd -root -screen -silent -display :0 > /tmp/screen.xwd` to take a screenshot.

<figure><img src="../../.gitbook/assets/image (259).png" alt=""><figcaption><p>Fig 21. Save .Xauthority file on alex</p></figcaption></figure>

Moving on, I set up a Python HTTP server on alex to transfer the files over to the attacker's machine.

<figure><img src="../../.gitbook/assets/image (270).png" alt=""><figcaption><p>Fig 22. Python HTTP server</p></figcaption></figure>

I managed to download the screenshot using `wget`.

<figure><img src="../../.gitbook/assets/image (279).png" alt=""><figcaption><p>Fig 23. Downloading the screenshot</p></figcaption></figure>

Since the screenshot is in the xwd extension, I used ImageMagick's convert tool to convert it to a `jpg` file.

<figure><img src="../../.gitbook/assets/image (229).png" alt=""><figcaption><p>Fig 24. Converting to jpg file</p></figcaption></figure>

Upon opening, I was able to view the root's password in cleartext.

<figure><img src="../../.gitbook/assets/image (246).png" alt=""><figcaption><p>Fig 25. Password in cleartext</p></figcaption></figure>

Switching over to the root account, I was able to obtain the root flag :)

<figure><img src="../../.gitbook/assets/image (212).png" alt=""><figcaption><p>Fig 26: Root flag</p></figcaption></figure>
