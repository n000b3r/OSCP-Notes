# (3306) MYSQL

<details>

<summary>Opening .bak files</summary>

```
sqlitebrowser user.bak
```

</details>

<details>

<summary>MYSQL Login</summary>

```
mysql -h <ip of sql server> -P <port> -u <username> -p'password' <database name>
```

Use mssqldump if mysql is not available

```bash
mysqldump -u theseus -p --all-databases > out.sql 
```

</details>
