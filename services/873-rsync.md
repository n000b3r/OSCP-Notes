# (873) RSYNC

Rsync is a fast and extraordinarily versatile file copying tool. It is famous for its delta-transfer algorithm, which reduces the amount of data by sending only the differences between the source files and existing destination files.

<details>

<summary>Commands</summary>

List the shares available on the target IP

```bash
rsync --list-only {target_IP}::
```

List the files in the directory called public

```bash
rsync --list-only {target_IP}::public
```

Copy/sync this file to our local machine

```bash
rsync {target_IP}::public/flag.txt flag.txt
```

</details>
