# Burpsuite (HTTPS Config)

### Burpsuite Post requests

<figure><img src="../.gitbook/assets/image (6) (1) (1).png" alt=""><figcaption><p>x-www-form-urlencoded</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (250).png" alt=""><figcaption><p>json post request</p></figcaption></figure>

### Generate Burpsuite Certificate to capture HTTPS traffic

Without CA cert, unable to capture HTTPS traffic as shown below.

<figure><img src="../.gitbook/assets/image (232).png" alt=""><figcaption></figcaption></figure>

Proxy --> Options --> Regenerate CA certificate

<figure><img src="../.gitbook/assets/image (275).png" alt=""><figcaption></figcaption></figure>

Restart Burpsuite

Use browser to go to http://burp and click CA Certificate

<figure><img src="../.gitbook/assets/image (261).png" alt=""><figcaption><p>Go to http://burp</p></figcaption></figure>

<figure><img src="../.gitbook/assets/image (265).png" alt=""><figcaption><p>CA cert downloaded</p></figcaption></figure>

about:preferences#privacy --> View certificates

<figure><img src="../.gitbook/assets/image (58).png" alt=""><figcaption></figcaption></figure>



<figure><img src="../.gitbook/assets/image (230).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (262).png" alt=""><figcaption></figcaption></figure>

Refresh HTTPS site and burp proxy will be working!
