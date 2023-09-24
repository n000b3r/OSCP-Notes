# Adding SSH key to Victim

### On Attacker

* Create SSH key:
  * Private key location: `/home/kali/.ssh/id_rsa`&#x20;
  * Public key location: `/home/kali/.ssh/id_rsa.pub`

```bash
ssh-keygen
```

```bash
chmod 600 /home/kali/.ssh/id_rsa
```

### On Victim

* Transfer the `/home/kali/.ssh/id_rsa.pub` to authorized\_keys file
  * Locations:
    * &#x20;`/home/user/.ssh/authorized_keys`
    * `/root/.ssh/authorized_keys`

### Logging in

```bash
$ ssh -i /home/kali/id_rsa user@host
```
