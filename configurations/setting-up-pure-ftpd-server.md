# Setting up Pure-FTPD server

### Install pure-ftpd&#x20;

```bash
apt-get install pure-ftpd
```

### Create ftpgroup

```bash
groupadd ftpgroup
```

### Create ftpuser

```bash
useradd -g ftpgroup -d /dev/null -s /etc ftpuser
```

### Create a FTP directory

```bash
mkdir /ftphome
```

### Creating a user&#x20;

```bash
pure-pw useradd bob -u ftpuser -g ftpgroup -d /ftphome/
```

### Updating the FTP Database

```bash
pure-pw mkdb
```

### Change the user and group ownership for the FTP directory

```bash
chown -R ftpuser:ftpgroup /ftphome
```

### Restarting FTP server

```bash
systemctl restart pure-ftpd
```

### Troubleshooting

### List the users in the database

```bash
pure-pw list
```

### Show specific user

```bash
pure-pw show bob
```
