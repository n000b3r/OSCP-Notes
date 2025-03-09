# Managing users on Windows

### Creating Users on Windows

<details>

<summary>Local Admin</summary>

### Create user named bill and pass as the password

```bash
net user bill pass /add
```

### Put bill into the local administrators group

```bash
net localgroup administrators bill /add
```

</details>

<details>

<summary>Domain Admin (Add User to Domain)</summary>

### Create user named bill and complex password

```bash
net user bill P@ssw0rd123! /ADD /DOMAIN
```

### Put user into Domain Admins group

```bash
net group "Domain Admins" bill /ADD /DOMAIN
```

</details>

### Changing/Resetting Passwords

<details>

<summary>Domain</summary>

```bash
net user jan P@ssw0rd123 /domain
```

</details>

### Managing Users in Groups

<details>

<summary>Domain</summary>

### Adding Users

```bash
net group "Management Department" stephanie /add /domain
```

### Deleting Users

```bash
net groups "Management Department" stephanie /del /domain
```

</details>
