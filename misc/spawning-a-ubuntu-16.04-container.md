---
description: For building Kernel Exploits
---

# Spawning a Ubuntu 16.04 Container

### Starting the container:

```
systemd-nspawn -M lazy
```

{% hint style="info" %}
lazy is the machine name in this case
{% endhint %}

### Transfer files from Kali to container

Put files in `/var/lib/machines/lazy/root`

Link: [https://github.com/X0RW3LL/XenSpawn](https://github.com/X0RW3LL/XenSpawn)
