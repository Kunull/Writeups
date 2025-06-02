---
custom_edit_url: null
sidebar_position: 4
---

> Mommy told me to make a passcode based login system.\
> My first trial C implementation compiled without any error!\
> Well, there were some compiler warnings, but who cares about that?

## File properties

```
passcode@ubuntu:~$ file ./passcode
passcode: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=e24d23d6babbfa731aaae3d50c6bb1c37dc9b0af, for GNU/Linux 3.2.0, not stripped
```

## Source code

```c title="passcode.c"
#include <stdio.h>
#include <stdlib.h>

void login(){
    int passcode1;
    int passcode2;

    printf("enter passcode1 : ");
    scanf("%d", passcode1);
    fflush(stdin);

    // ha! mommy told me that 32bit is vulnerable to bruteforcing :)
    printf("enter passcode2 : ");
        scanf("%d", passcode2);

    printf("checking...\n");
    if(passcode1==123456 && passcode2==13371337){
        printf("Login OK!\n");
    setregid(getegid(), getegid());
        system("/bin/cat flag");
    }
    else{
        printf("Login Failed!\n");
        exit(0);
    }
}

void welcome(){
    char name[100];
    printf("enter you name : ");
    scanf("%100s", name);
    printf("Welcome %s!\n", name);
}

int main(){
    printf("Toddler's Secure Login System 1.1 beta.\n");

    welcome();
    login();

    // something after login...
    printf("Now I can safely trust you that you have credential :)\n");
    return 0;
}
```
