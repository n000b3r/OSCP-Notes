# Gitlab

<details>

<summary>Explore Public GitLab Repo</summary>

[http://dev01/explore](http://dev01/explore)

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Git Clone Repo With SSH Private Key</summary>

```bash
# Test Connection Using Private Key
ssh -i marian.pri git@dev01

# Git Clone "Monitor" Repo
GIT_SSH_COMMAND='ssh -i marian.pri -o IdentitiesOnly=yes' git clone git@dev01.cowmotors.com:msimpson/monitor.git
```

</details>
