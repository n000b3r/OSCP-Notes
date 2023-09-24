# Fixing ModuleNotFoundError after Linux Update

### Error

```bash
┌──(2022.04.30 | 12:41:53)──[~/hacking/thm/holo]
└─$ sudo $(which autorecon) --dirbuster.tool feroxbuster -t ./ips.txt 
Traceback (most recent call last):
File "/home/tac0shell/.local/bin/autorecon", line 5, in
from autorecon.main import main
ModuleNotFoundError: No module named 'autorecon'
```

* Was able to use it before the `apt-get update && apt-get upgrade`

### Solution

* Python3 was upgraded to a new version and broke the module’s dependency to the older version your pipx modules were using.

```bash
rm -rf ~/.local/pipx
```

```bash
pipx install git+https://github.com/Tib3rius/AutoRecon.git
```
