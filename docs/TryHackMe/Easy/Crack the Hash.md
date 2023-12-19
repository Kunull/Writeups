# Task 1: Level 1
## Question
> 48bb6e862e54f2a795ffc4e541caed4d
- Before we crack the hash we have to find its type.
- Using `hash-identifier` we can identify the possible hash type.
```
$ hash-identifier 48bb6e862e54f2a795ffc4e541caed4d        
--------------------------------------------------

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```
- Let's save the hash to a file.
```
$ echo "48bb6e862e54f2a795ffc4e541caed4d" > hash1.txt
```
- Now we have to find the hash-mode for a MD5 hash.
![[1 94.png]]
- We are now ready to crack the hash using `hashcat`.
```
$ hashcat -a 0 -m 0 hash1.txt /usr/share/wordlists/rockyou.txt 

48bb6e862e54f2a795ffc4e541caed4d:easy  
```
- We can also crack the hash using `john`.
```
$ john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash1.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE2 4x3])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
easy             (?)     
1g 0:00:00:00 DONE (2023-12-08 21:44) 5.000g/s 862080p/s 862080c/s 862080C/s erinbear..eagames
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```
## Answer
```
easy
```

## Question
> CBFDAC6008F9CAB4083784CBD1874F76618D2A97
- Let's identify the hash type using `hash-identifier`.
```
$ hash-identifier CBFDAC6008F9CAB4083784CBD1874F76618D2A97
--------------------------------------------------

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))
```
- The mode for SHA-1 in `hashcat` is `100`.
![[2 93.png]]
```
$ hashcat-a 0 -m 100 hash2.txt /usr/share/wordlists/rockyou.txt              

cbfdac6008f9cab4083784cbd1874f76618d2a97:password123 
```
- We can crack the hash now using the `Raw-SHA1` format for `john`.
```
$ john --format=Raw-SHA1 --wordlist=/usr/share/wordlists/rockyou.txt hash2.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 128/128 SSE2 4x])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (?)     
1g 0:00:00:00 DONE (2023-12-08 21:49) 7.142g/s 9885p/s 9885c/s 9885C/s liberty..password123
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed. 
```
## Answer
```
password123
```

## Question
> 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032
- We can crack the hash using `hash-identifier`.
```
$ hash-identifier 1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032
--------------------------------------------------

Possible Hashs:
[+] SHA-256
[+] Haval-256
```
- Let's save it to a file.
```
$ echo "1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032" > hash3.txt
```
- The mode for SHA-256 in `hashcat` is `1400`.
![[3 73.png]]
```
$ hashcat -a 0 -m 1400 hash3.txt /usr/share/wordlists/rockyou.txt

1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032:letmein
```
- The format for `john` will be `Raw-SHA256`.
```
$ john --format=Raw-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt hash3.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=3
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (?)     
1g 0:00:00:00 DONE (2023-12-08 21:53) 16.66g/s 409600p/s 409600c/s 409600C/s 123456..280789
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed. 
```
## Answer
```
letmein
```

## Question
> $2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom
- `hash-identifier` is not able to identify the type of this hash.
- We will have to use another tool called Hash Analyzer.
![[4 58.png]]
- The hash-mode for Bcrypt is `3200`.
- We know that the password is four characters long, so let's filter the `rockyou.txt` file.
```
$ egrep -x '.{1,4}' /usr/share/wordlists/rockyou.txt > filtered.txt
```
- We can now use this filtered list to crack the hash.
```
$ hashcat -a 0 -m 3200 hash4.txt filtered.txt -w 4 -S

$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom:bleh
```
## Answer
```
bleh
```

## Question
> 279412f945939ba78ce0758d3fd83daa
- Let's identify the type using Hash Analyzer.
![[6 31.png]]
- This time let's use CrackStation to crack the hash.
![[8 21.png]]
## Answer
```
Eternity22
```

# Task 2: Level 2
## Question
> Hash: F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85
- Let's use `hash-identifier` to get the hash type.
```
$ hash-identifier F09EDCB1FCEFC6DFB23DC3505A882655FF77375ED8AA2D1C13F640FCCC2D0C85
--------------------------------------------------

Possible Hashs:
[+] SHA-256
[+] Haval-256
```
- Since we know that the mode for SHA-256 is `1400`, let's just try that first.
```
$ hashcat -a 0 -m 1400 hash6.txt /usr/share/wordlists/rockyou.txt

f09edcb1fcefc6dfb23dc3505a882655ff77375ed8aa2d1c13f640fccc2d0c85:paule
```
## Answer
```
paule
```

## Question
> Hash: 1DFECA0C002AE40B8619ECF94819CC1B
- CrackStation gives us the password.
![[9 16.png]]
## Answer
```
n63umy8lkf4i
```

## Question
> Hash: $6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.
> Salt: aReallyHardSalt
- The `$6$` tells us that this is a SHAcrypt512 hash the mode for which is `1800`.
![[10 13.png]]
- This time we have to filter for passwords that are six characters long.
```
$ egrep -x '.{1,6}' /usr/share/wordlists/rockyou.txt > filtered.txt
```
- Let's run `hashcat` with the correct mode.
```
$ hashcat -m 1800 hash7.txt filtered.txt -w 4 -S

$6$aReallyHardSalt$6WKUTqzq.UQQmrm0p/T7MPpMbGNnzXPMAXi4bJMl9be.cfi3/qxIf.hsGpS41BqMhSrHVXgMpdjS6xeKZAs02.:waka99
```
## Answer
```
waka99
```
## Question
> Hash: e5d8870e5bdd26602cab8dbe07a942c8669e56d6
> Salt: tryhackme
- Let's identify the hash using `hash-identifier`.
```
$ hash-identifier e5d8870e5bdd26602cab8dbe07a942c8669e56d6                                                                
--------------------------------------------------

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))
```
- For SHA-1, the mode we will be using is `160`.
```
$ hashcat -a 0 -m 160 'e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme' /usr/share/wordlists/rockyou.txt

e5d8870e5bdd26602cab8dbe07a942c8669e56d6:tryhackme:481616481616
```
## Answer
```
481616481616
```