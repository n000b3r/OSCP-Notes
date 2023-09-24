# Config File Locations

<details>

<summary>Wordpress</summary>

```bash
/var/www/html/wordpress/wp-config.php
/srv/http/wp-config.php
```

</details>

<details>

<summary>PHPMyAdmin</summary>

```bash
/etc/phpmysadmin/config-db.php
```

</details>

<details>

<summary>Subrion CMS Database Config File</summary>

```bash
www-data@exfiltrated:/$ cat /var/www/html/subrion/includes/config.inc.php
<?php
/*
 * Subrion Open Source CMS 4.2.1
 * Config file generated on 10 June 2021 12:04:54
 */

define('INTELLI_CONNECT', 'mysqli');
define('INTELLI_DBHOST', 'localhost');
define('INTELLI_DBUSER', 'subrionuser');
define('INTELLI_DBPASS', 'target100');
define('INTELLI_DBNAME', 'subrion');
define('INTELLI_DBPORT', '3306');
define('INTELLI_DBPREFIX', 'sbr421_');

define('IA_SALT', '#5A7C224B51');

// debug mode: 0 - disabled, 1 - enabled
define('INTELLI_DEBUG', 0);
```

</details>

<details>

<summary>AutoRecon</summary>

```bash
/root/.local/pipx/venvs/autorecon/lib/python3.11/site-packages/autorecon/config.toml
```

</details>

<details>

<summary>Dirsearch</summary>

```bash
/etc/dirsearch/default.conf
```

</details>
