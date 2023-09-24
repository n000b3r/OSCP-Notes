# (119) NNTP

* NNTP servers push and pull news articles to and from other NNTP servers over port 119.
* Allows news reading and writing to the server.

<details>

<summary>Enumerating news server</summary>

```bash
nc -nvC 10.11.1.72 119
```

```
HELP
```

```
LIST
```

</details>
