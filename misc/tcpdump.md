---
description: >-
  Useful when unable to proceed further in a network/domain -> sniff for
  sensitive credentials
---

# Tcpdump

```bash
# Sniff for all traffic
tcpdump -i <network name> -w file.pca

# Sniff for FTP traffic
tcpdump -s0 -i <network name> port ftp
```
