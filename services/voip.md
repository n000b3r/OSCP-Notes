# VoIP

<details>

<summary>Sipdigestleak</summary>

Allows attacker to get a digest response from a phone and use it to guess the password via a brute-force attack

```bash
git clone https://github.com/Pepelux/sippts.git 
python3 sipdigestleak.py -i 192.168.206.156
```

</details>

<details>

<summary>Decode raw file</summary>

Find the stream and encoding from WebUI

```bash
sox -t raw -r 8000 -v 4 -c 1 -e mu-law 2138.raw out.wav
```

* Stream is 8000Hz
* Encoder is G.711

</details>
