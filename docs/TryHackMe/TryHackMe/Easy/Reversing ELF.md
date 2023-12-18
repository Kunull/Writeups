# Task 1: Crackme1
## What is the flag?
- We have to add execute permissions to the file.
```
$ sudo chmod 777 crackme1 
```
- We can now read the flag.
```
$ ./crackme1             
flag{not_that_kind_of_elf}
```
## Answer
```
flag{not_that_kind_of_elf}
```
#
# Task 2: Crackme2
## What is the super secret password ?
- This executable asks for a password as an argument.
```
$ ./crackme2 
Usage: ./crackme2 password
```
- We can use the `strings` utility to dump all the strings which are four characters or longer.
```
$ strings crackme2                   
Usage: %s password
super_secret_password
Access denied.
Access granted.
;*2$"(
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.9) 5.4.0 20160609
crtstuff.c
__JCR_LIST__
deregister_tm_clones
__do_global_dtors_aux
completed.7209
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
conditional1.c
giveFlag
```
## Answer
```
super_secret_password
```
##
## What is the flag ?
- Let's get the flag using the password.
```
$ ./crackme2 super_secret_password                       
Access granted.
flag{if_i_submit_this_flag_then_i_will_get_points}
```
## Answer
```
flag{if_i_submit_this_flag_then_i_will_get_points}
```
#
# Task 3: Crackme3
## What is the flag?
- This one asks for a password as well.
```
$ ./crackme3                      
Usage: ./crackme3 PASSWORD
```
- Let's get the password using the `strings` utility.
```
$ strings crackme3       
Usage: %s PASSWORD
malloc failed
ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==
Correct password!
Come on, even my aunt Mildred got this one!
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
```
- The password is Base64 encoded. We can say that because of the `==` at the end of the string.
- We can decode it using the `base64` utility. 
```
$ echo "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==" | base64 -d
f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5   
```
## Answer
```
f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5
```
# 
# Task 4: Crackme4
## What is the password ?