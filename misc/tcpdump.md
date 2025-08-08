---
description: >-
  Useful when unable to proceed further in a network/domain -> sniff for
  sensitive credentials
---

# Tcpdump

```bash
# Determine the network interface name
ifconfig

# Sniff for all traffic
tcpdump -i <network name> -w file.pca

# Sniff for FTP traffic (-s0 captures the entire packet, not just the default first 96 bytes)
tcpdump -s0 -i <network name> port ftp
```
