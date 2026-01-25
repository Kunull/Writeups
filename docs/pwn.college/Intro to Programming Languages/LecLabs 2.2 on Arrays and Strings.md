---
custom_edit_url: null
sidebar_position: 3
slug: /pwn-college/intro-to-programming-languages/leclabs-2.2
---

## Lab 2.2.2.0 - Print C-String by Character

### Code
```c title="main.c" showLineNumbers
/** CODE: add the include for printf */
#include <stdio.h>

/** CODE: declare and define print_string, which takes a c-string as an argument using [] 
 *          loop through the string until reaching a null terminator
 *          print each character 1 at a time          
*/
void print_string (char str[]) {
    for (int i = 0; str[i] != '\0'; i++) {
        printf("%c", str[i]);
    }
}

/** CODE: define main function with int argc and char *argv[] so that it get access the command args 
 *          loop through the arguments
 *              print "arg <FORMATTER>:"  
 *              call print_string function
 *              print a newline
 *          return that everything is ok
*/
int main (int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        printf("arg %d: ", i);
        print_string(argv[i]);
        printf("\n");
    }
}
```

### Tests
#### System tests

```json title="system_tests/stest22.20.1.json" showLineNumbers
{
    "args": [ "Cure"],
    "input": [],
    "output": ["Cure"],
    "target": "main.bin",
    "name": "Test if program is printing out all the provided arguments.",
    "description": "This test verifies the program prints out all the provided arguments"
}
```

```json title="system_tests/stest22.20.1.json" showLineNumbers
{
    "args": [ "Turning", "Turning", "blue", "All", "over", "the", "windows", "and", "the", "floors", "Fires", "outside", "in", "the", "sky", "Look", "as", "perfect", "as", "cats" ],
    "input": ["99","a"],
    "output": ["Turning", "Turning", "blue", "All", "over", "the", "windows", "and", "the", "floors", "Fires", "outside", "in", "the", "sky", "Look", "as", "perfect", "as", "cats" ],
    "target": "main.bin",
    "name": "Test if program is printing out all the provided arguments.",
    "description": "This test verifies the program prints out all the provided arguments"=
}
```

#### User tests

```json title="user_tests/utest22.20.1.json" showLineNumbers
{
    "args": ["argument_1", "argument_2"],
    "input": [""],
    "output": [
        "arg 1: argument_1",
        "arg 2: argument_2"
    ],
    "nameOfModelGoodTest": "Test for <testfilename> to Pass by printing out the supplied arguments",
    "descriptionOfModelGoodTest": "A properly working test case should pass when executing modelGood. ",
    "nameOfModelBadTest": "Test for ./modelBad22.20.1.bin to fail because it will not print the arguments values, it will print X instead ",
    "descriptionOfModelBadTest": "A properly working test case should fail when executing a modelBad designed to fail the test case. So, passing the test means that the result above should not be found."
}
```

```
hacker@22-lela-arrays-strings~lab-2-2-2-0-print-c-string-by-character:~/cse240/labw/lab22/01$ gcc main.c -g -o main.bin
```

```
hacker@22-lela-arrays-strings~lab-2-2-2-0-print-c-string-by-character:~/cse240/labw/lab22/01$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab22/01/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 23654f00ed164c7bf497b0647f99fe9a
['/home/hacker/cse240/labw/lab22/01/user_tests/utest22.20.1.json']
---------------[  User Tests  ]---------------
User utest22.20.1: target_path: /challenge/modelBad22.20.1.bin
✔ PASS  - Test for ./modelBad22.20.1.bin to fail because it will not print the arguments values, it will print X instead  ran in 0.01s
User utest22.20.1: target_path: /challenge/modelGood.bin
✔ PASS  - Test for modelGood.bin to Pass by printing out the supplied arguments ran in 0.01s
User utest22.20.1: target_path: /home/hacker/cse240/labw/lab22/01/main.bin
✔ PASS  - Test for main.bin to Pass by printing out the supplied arguments ran in 0.01s

---------------[ System Tests ]---------------
System stest22.20.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out all the provided arguments. ran in 0.01s
System stest22.20.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out all the provided arguments. ran in 0.01s

All 5 Tests Passed 
Congrats, here's your flag
pwn.college{M2NG3i4WRT1y4p1MIZAu_pEBMm6.QX4QTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.2.2.1 - Debugging with Seg Faults

### Code

```c title="main.c" showLineNumbers

```

Corrected code:

```c title="main.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SIZE 100

typedef struct Score{
    char name[MAX_SIZE];
    int score;
} Score; 

long size = 0;
Score scores[4] = {{"level1",88}, {"level2", 99}, {"level3", 100}, {"level4", 100}};

void print_grades(Score scores[], int size) {    
    
    for(int i = 0; i < size; i++) {                                     
        printf("%s %d\n", scores[i].name, scores[i].score);
    }
    
}

int sum_scores(Score scores[], int size) {    
    int sum = 0;
    for(int i = 0; i < size; i++) {                                     
        sum = sum + scores[i].score;
    }
    return sum;
}

int main(int argc, char* argv[]) {
    
    if (argc < 2) {
        printf("Please provide a title\nUsage: %s 'Title'\n", argv[0]);
        return 0;
    }
        
    char size = sizeof(scores)/sizeof(scores[0]);                           // only works on arrays when the size is known at compile time
    int scoresum = sum_scores(scores, size);
    
    printf("Title: %s\n", argv[1]);
    print_grades(scores, size);
    printf("----------------\n");
    printf("Sum: %d\n", scoresum);    

    return 0;
}
```

### Tests
#### System tests

```json title="system_tests/stest22.21.1.json" showLineNumbers
{
    "args": ["Grades Title 1"],
    "input": [],
    "output_type": "regex",
    "output": ["level1","level2 [0-9]+","level3", "level4 100"],
    "target": "main.bin",
    "name": "Test for Printed Values",
    "description": "This test verifies the program prints out the expected values Level1 88, Level2 99, Level3 100, and Level4 100."
}
```

```json title="system_tests/stest22.21.2.json" showLineNumbers
{
    "args": ["Grades Title 2"],
    "input": [],
    "output_type": "regex",
    "output": ["Sum.*387"],
    "target": "main.bin",
    "name": "Test the summed value",
    "description": "This test verifies the program calculates the sum correctly."
}
```

#### User Tests

```json title="user_tests/utest22.21.1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": [
        "level1 88",
        "level2 99"
    ],
    "nameOfModelGoodTest": "Test for <testfilename> to Pass with the scores being printed out properly",
    "descriptionOfModelGoodTest": "A properly working test case should pass when executing modelGood. ",
    "nameOfModelBadTest": "Test for ./modelBad22.21.1.bin to fail because it will not print the grades correctly ",
    "descriptionOfModelBadTest": "A properly working test case should fail when executing a modelBad because this version of the modelBad is designed to fail this test case. So, passing the test means that given the inputs the expected output will not match the actual output."
}
```

```json title="user_tests/utest22.21.1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": [
        "Sum: 387"
    ],
    "nameOfModelGoodTest": "Test for <testfilename> to Pass by printing out the sum of the grades",
    "descriptionOfModelGoodTest": "A properly working test case should pass when executing modelGood. ",
    "nameOfModelBadTest": "Test for ./modelBad22.21.2.bin to fail because it will not print out the proper sum for the grades ",
    "descriptionOfModelBadTest": "A properly working test case should fail when executing a modelBad because this version of the modelBad is designed to fail this test case. So, passing the test means that given the inputs the expected output will not match the actual output."
}
```

```
hacker@22-lela-arrays-strings~lab-2-2-2-1-debugging-with-seg-faults:~/cse240/labw/lab22/02$ gcc main.c -g -o main.bin
```

```
hacker@22-lela-arrays-strings~lab-2-2-2-1-debugging-with-seg-faults:~/cse240/labw/lab22/02$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab22/02/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of bd0b7cc154400fd1be424b65fe0e646f
['/home/hacker/cse240/labw/lab22/02/user_tests/utest22.21.1.json', '/home/hacker/cse240/labw/lab22/02/user_tests/utest22.21.2.json']
---------------[  User Tests  ]---------------
User utest22.21.1: target_path: /challenge/modelBad22.21.1.bin
✔ PASS  - Test for ./modelBad22.21.1.bin to fail because it will not print the grades correctly  ran in 0.01s
User utest22.21.1: target_path: /challenge/modelGood.bin
✔ PASS  - Test for modelGood.bin to Pass with the scores being printed out properly ran in 0.01s
User utest22.21.1: target_path: /home/hacker/cse240/labw/lab22/02/main.bin
✔ PASS  - Test for main.bin to Pass with the scores being printed out properly ran in 0.01s
User utest22.21.2: target_path: /challenge/modelBad22.21.2.bin
✔ PASS  - Test for ./modelBad22.21.2.bin to fail because it will not print out the proper sum for the grades  ran in 0.01s
User utest22.21.2: target_path: /challenge/modelGood.bin
✔ PASS  - Test for modelGood.bin to Pass by printing out the sum of the grades ran in 0.01s
User utest22.21.2: target_path: /home/hacker/cse240/labw/lab22/02/main.bin
✔ PASS  - Test for main.bin to Pass by printing out the sum of the grades ran in 0.01s

---------------[ System Tests ]---------------
System stest22.21.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test for Printed Values ran in 0.01s
System stest22.21.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test the summed value ran in 0.01s

All 8 Tests Passed 
Congrats, here's your flag
pwn.college{c9JDhfjL9E3EXI-eZ4ceVKIi3x7.QX5QTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.2.4.1 - LeeT CaSe

### Code

```c title="main.c" showLineNumbers

/** CODE: add necessary includes stdio.h and ctype.h */
#include <stdio.h>
#include <ctype.h>

/** CODE: create leet_print, it takes in a c-string as an argument 
 *          convert all consonants to uppercase, you can use toupper from the library ctype.h
 *          print out the results of the conversion
*/
void leet_print (char line[]) {

    int i = 0;

    while (line[i] != '\0'){
        
        if (line[i] != 'a' && line[i] != 'e' && line[i] != 'i' && line[i] != 'o' && line[i] != 'u') {
            line[i] = toupper(line[i]);
        }

        i++;
    }

    printf("%s", line);
}

/** CODE: define main with argc and argv 
 *          check if 1 argument was provided, the filename
 *          Open the file
 *          use fgets and a while loop to loop through the file
 *              pass each line to leet_print
 *              print new line
*/
int main (int argc, char* argv[]) {

    char line[256];

    if (argc < 2) {
        printf("Usage: %s <file_name>\n", argv[0]);
        return 1;
    }
    
    FILE *file_ptr = fopen(argv[1], "r");

    while (fgets(line, sizeof(line), file_ptr) != NULL) {
        leet_print(line); 
    }

    printf("\n");
    
    return 0;
}
```

### Tests
#### System tests

```json title="system_tests/stest22.41.1.json" showLinenNumbers
{
    "args": [ "/challenge/system_tests/input22.41.1.dat"],
    "input": [],
    "output": ["MaDD"],
    "target": "main.bin",
    "name": "Test if program is printing out all the provided arguments.",
    "description": "This test verifies the program prints out all the provided arguments"
}
```

```json title="system_tests/stest22.41.2.json" showLinenNumbers
{
    "args": ["/challenge/system_tests/input22.41.2.dat"],
    "input": [],
    "caseSensitive": true,
    "output": ["WhY", "BLeND", "iN", "WHeN", "You", "CaN", "STaND", "ouT", "LiKE", "a", "UNiCoRN", "iN", "a", "FieLD", "oF", "HoRSeS?", "eMBRaCe", "THe", "WeiRDNeSS", "MY", "FRieND!"],
    "target": "main.bin",
    "name": "Test if program is printing out all the provided arguments.",
    "description": "This test verifies the program prints out all the provided arguments"
}
```

#### User tests

```json title="user_tests/utest22.41.1.json" showLinenNumbers
{
    "args": ["/home/hacker/cse240/labw/lab22/03/test_file.txt"],
    "input": [""],
    "output": ["TeST iNPuT"],
    "nameOfModelGoodTest": "Test for <testfilename> to Pass by printing out the input from the file with its consonants capitialized",
    "descriptionOfModelGoodTest": "A properly working test case should pass when executing modelGood. ",
    "nameOfModelBadTest": "Test for ./modelBad22.41.1.bin to fail because it will not print the arguments correctly, instead of capitlizing all consonants it will turn them all into an 'X' instead. ",
    "descriptionOfModelBadTest": "A properly working test case should fail when executing a modelBad designed to fail the test case. So, passing the test means that the result above should not be found."
}
```

```
hacker@22-lela-arrays-strings~lab-2-2-4-1-leet-case:~/cse240/labw/lab22/03$ echo "test input" > test_file.txt
```

```
hacker@22-lela-arrays-strings~lab-2-2-4-1-leet-case:~/cse240/labw/lab22/03$ gcc main.c -g -o main.bin
```

```
hacker@22-lela-arrays-strings~lab-2-2-4-1-leet-case:~/cse240/labw/lab22/03$ /challenge/tester 
Build: ✔ PASS - 0.06s
Copied /home/hacker/cse240/labw/lab22/03/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 2abbaa6d8a538540f32d3f0fd423380a
['/home/hacker/cse240/labw/lab22/03/user_tests/utest22.41.1.json']
---------------[  User Tests  ]---------------
User utest22.41.1: target_path: /challenge/modelBad22.41.1.bin
✔ PASS  - Test for ./modelBad22.41.1.bin to fail because it will not print the arguments correctly, instead of capitlizing all consonants it will turn them all into an 'X' instead.  ran in 0.01s
User utest22.41.1: target_path: /challenge/modelGood.bin
✔ PASS  - Test for modelGood.bin to Pass by printing out the input from the file with its consonants capitialized ran in 0.01s
User utest22.41.1: target_path: /home/hacker/cse240/labw/lab22/03/main.bin
✔ PASS  - Test for main.bin to Pass by printing out the input from the file with its consonants capitialized ran in 0.01s

---------------[ System Tests ]---------------
System stest22.41.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out all the provided arguments. ran in 0.01s
System stest22.41.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out all the provided arguments. ran in 0.01s

All 5 Tests Passed 
Congrats, here's your flag
pwn.college{csoYiMpiKaCm48C01ghv4iAvG4Y.QXwUTO3EDL4ITM0EzW}
```

&nbsp;

## EzLabs 2.2.5.1 - String Length (strlen)

### Code

```c title="main.c" showLineNumbers

#include<string.h>
#include<stdio.h>

int main(){
    char str[] = "This is the way.";
    // CODE: replace XXXXX with the str variable and YYYYY by reading the text of the printf's format string argument
    printf("The length of '%s' is %lu characters long.\n", str , strlen(str) );
}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["The length of 'This is the way.' is 16 characters long."],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the string and it's length"

}
```

```
hacker@22-lela-arrays-strings~ezlab-2-2-5-1-string-length-strlen:~/cse240/labw/lab22/04$ gcc main.c -g -o main.bin
```

```
hacker@22-lela-arrays-strings~ezlab-2-2-5-1-string-length-strlen:~/cse240/labw/lab22/04$ /challenge/tester 
Build: ✔ PASS - 0.06s
Copied /home/hacker/cse240/labw/lab22/04/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of ea51c2da258c4a12df1548a208ee7594
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 1 Tests Passed 
Congrats, here's your flag
pwn.college{oHjpgM_CG3B7OaCM2IH_62AJXlI.QXxUTO3EDL4ITM0EzW}
```

&nbsp;

## EzLabs 2.2.5.2 - String Concatenate (strcat)
### Code
```c title="main.c" showLineNumbers

#include<string.h>
#include<stdio.h>

int main(){
    char str1[] = "Think of concatenation as giving strings a big hug, ";
    char str2[] = "bringing them together to form one happy, unified string!";
    char result[strlen(str1)+strlen(str2)];

    // CODE: Initialize result to empty string (hint: set first character of c-string to null terminator)
    result[0] = '\0';
    
    // CODE: concatenate str1 to result
    strcat(result, str1);

    // CODE: concatenate str2 to result 
    strcat(result, str2);
        
    printf("%s\n", result );
    
    char str3[] = "ENDSTART";
    char endresult[100] = ""; // this one is initialized for you
    
    // CODE: concatenate the entire str3 variable to endresult
    strcat(endresult, str3);

    // CODE: add a space to endresult
    strcat(endresult, " ");

    // CODE: concatenate the first 4 characters of str3 to the end of endresult
    strncat(endresult, str3, 4);

    // should print out "END START ENDS"
    printf("%s\n", endresult);
}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": [
                "Think of concatenation as giving strings a big hug, bringing them together to form one happy, unified string!",
                "ENDSTART ENDS"
            ],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the results of the strcat function."

}
```

```
hacker@22-lela-arrays-strings~ezlab-2-2-5-2-string-concatenate-strcat:~/cse240/labw/lab22/05$ gcc main.c -g -o main.bin
```

```
hacker@22-lela-arrays-strings~ezlab-2-2-5-2-string-concatenate-strcat:~/cse240/labw/lab22/05$ /challenge/tester 
Build: ✔ PASS - 0.06s
Copied /home/hacker/cse240/labw/lab22/05/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 2fbff1cfdfbee09d5c6ec4209a5e0a60
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 1 Tests Passed 
Congrats, here's your flag
pwn.college{8iWE-9IV1KsfmQqsxj9OxxHeYfe.QX1UTO3EDL4ITM0EzW}
```

&nbsp;

## EzLabs 2.2.5.3 - String Compare (strcmp)
### Code

```c title="main.c" showLineNumbers
#include<string.h>
#include<stdio.h>

int main(){
    char str1[] = "String1";
    char str4[] = "String4";
    
    // CODE: Replace XXXXX with string compare of str1 to str1
    int strcmp_11_result = strcmp(str1, str1);
    printf("Compare str1 to str1 == %d\n" , strcmp_11_result );
    // CODE: Replace YYYYY with string compare of str1 to str4
    int strcmp_14_result = strcmp(str1, str4);
    printf("Compare str1 to str4 == %d\n" , strcmp_14_result);

    printf("Interesting, the difference betweeen ");
    printf("str1[6] = %c and str4[6] = %c of %d ", str1[6], str4[6], str1[6]-str4[6]);
    // CODE: Replace YYYYY with string compare of str1 to str4
    printf("is the same as strcmp(str1,str4) of %d\n", strcmp_14_result);    
}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["Compare str1 to str1 == 0","Compare str1 to str4 == -3","Interesting, the difference betweeen str1[6] = 1 and str4[6] = 4 of -3 is the same as strcmp(str1,str4) of -3"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the results of the strcmp function."
}
```

```
hacker@22-lela-arrays-strings~ezlab-2-2-5-3-string-compare-strcmp:~/cse240/labw/lab22/06$ gcc main.c -g -o main.bin
```

```
hacker@22-lela-arrays-strings~ezlab-2-2-5-3-string-compare-strcmp:~/cse240/labw/lab22/06$ /challenge/tester 
Build: ✔ PASS - 0.06s
Copied /home/hacker/cse240/labw/lab22/06/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 1c925b07db932d9429e36c1936ee6e6a
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 1 Tests Passed 
Congrats, here's your flag
pwn.college{UByGoAGWpAJicnhB-OrBkUb0z89.QX0UTO3EDL4ITM0EzW}
```

&nbsp;

## EzLabs 2.2.5.4 - String Copy (strcpy/strncpy)
### Code

```c title="main.c" showLineNumbers

#include<string.h>
#include<stdio.h>

int main(){
    char dest[100] = "";
    // Fun fact: strcpy stands for "string copy" and is used to copy one string to another!
    // But be careful: it doesn't check for buffer overflows!
    char src1[] = "strcpy: because sometimes you just gotta live dangerously.";
        
    // CODE: copy the entire src1 to dest
    strcpy(dest, src1);

    printf("%s\n", dest);

    char src2[] = "strncpy: the safety scissors of C string functions, but still sharp enough to cause problems.";
    
    // CODE: copy the first 50 characters of src2 to dest
    strncpy(dest, src2, 50);

    // strncpy copies exactly the requested number of characters, which means it does not include the null termintor at index 55.
    // CODE: set character at index 50 to be '\0'
    dest[50] = '\0';

    printf("%s", dest);
    printf(".\n");
    
    return 0;
}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["strcpy: because sometimes you just gotta live dangerously."],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the results of the strcpy function."
}
```

```json title="2.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["strncpy: the safety scissors of C string functions."],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the results of the strncpy function."
}
```

```json title="3.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["strncpy: the safety scissors of C string functions."],
    "unexpectedOutput": ["cause problems"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program does not print out the cut-off part of the src2 string."
}
```

```
hacker@22-lela-arrays-strings~ezlab-2-2-5-4-string-copy-strcpystrncpy:~/cse240/labw/lab22/07$ gcc main.c -g -o main.bin
```

```
hacker@22-lela-arrays-strings~ezlab-2-2-5-4-string-copy-strcpystrncpy:~/cse240/labw/lab22/07$ /challenge/tester 
Build: ✔ PASS - 0.06s
Copied /home/hacker/cse240/labw/lab22/07/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of ff4b0bfdb19dd6e8be89fbb78285396e
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 3 Tests Passed 
Congrats, here's your flag
pwn.college{QidGYscQRDA4npZ2f-GVkU9UrsK.QX2UTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.2.5.6 - String Highlighter
### Code

```c title="main.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define MAX_LINE_LEN 1024
#define MAX_WORD_LEN 100

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    char *filename = argv[1];
    char keyword[MAX_WORD_LEN];

    printf("Enter keyword to highlight: ");
    
    /**
     * CODE: Read a keyword from the user to highlight in the text file.
     */
    scanf("%s", keyword); 
    
    FILE *file;
    /** CODE: open the file  */
    file = fopen(filename, "r");
    
    if (!file) {
        printf("Error opening file\n");
        return 1;
    }

    char line[MAX_LINE_LEN];

    /** CODE: Loop through each line of the file using fgets */
    while (fgets(line, MAX_LINE_LEN, file) != NULL) {

        char result[MAX_LINE_LEN * 2] = "";  // reset for each line
        char word[MAX_WORD_LEN] = "";

        int i = 0, j = 0;

        if (line[strlen(line) - 1] == '\n') {
            line[strlen(line) - 1] = '\0';
        }

        /** CODE: 
         * Loop through the line character by character and extract each word:
         *   - If the current character is a whitespace, copy it directly to result
         *   - If it's part of a word, extract the word (use an array to build it)
         *     - If it matches the keyword, append **word** to result
         *     - Else, append the word as-is
         */
        while (line[i] != '\0') {
            if (line[i] != ' ') {
                word[j] = line[i];
                j++;
            } 
            else {
                word[j] = '\0';

                if (strcmp(word, keyword) == 0) {
                    strcat(result, "**");
                    strcat(result, word);
                    strcat(result, "**");
                }
                else {
                    strcat(result, word);
                }

                j = 0;
                strcpy(word, " ");
                strcat(result, " ");
            }
            i++;
        }

        if (j > 0) {
            word[j] = '\0';

            if (strcmp(word, keyword) == 0) {
                strcat(result, "**");
                strcat(result, word);
                strcat(result, "**");
            }
            else {
                strcat(result, word);
            }
        }

        /** CODE: print the result */
        printf("%s", result);
    }

    /** CODE: close the file */
    return 0;
}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": [ "/challenge/system_tests/input22.56.1.dat"],
    "input": ["cat"],
    "output": ["**cat**"],
    "target": "main.bin",
    "name": "Tests highlighting when one word is input.",
    "description": "This test verifies the program highlights when only a single word is provided in the file."
}
```

```json title="2.json" showLineNumbers
{
    "args": ["/challenge/system_tests/input22.56.2.dat"],
    "input": ["unicorn"],
    "caseSensitive": true,
    "output": ["why blend in when you can stand out like a **unicorn** in a field of horses embrace the weirdness my friend"],
    "target": "main.bin",
    "name": "Tests highlighting of a word in list of multiple words.",
    "description": "This test verifies the program highlights a word that is present in a longer sentence, ensuring that the highlighting works correctly even when the word is part of a larger context."
}
```

```json title="3.json" showLineNumbers
{
    "args": ["/challenge/system_tests/input22.56.3.dat"],
    "input": ["cat"],
    "caseSensitive": true,
    "output": ["the **cat** in the hat throws a rat at your **cat**"],
    "target": "main.bin",
    "name": "Tests highlighting of multiple words in list of multiple words.",
    "description": "This test verifies the program highlights multiple words that are present in the list of words."
}
```

```
hacker@22-lela-arrays-strings~lab-2-2-5-6-string-highlighter:~/cse240/labw/lab22/08$ gcc main.c -g -o main.bin
```

```
hacker@22-lela-arrays-strings~lab-2-2-5-6-string-highlighter:~/cse240/labw/lab22/08$ /challenge/tester 
Build: ✔ PASS - 0.09s
Copied /home/hacker/cse240/labw/lab22/08/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of d5699aa1599368b61477bae4164facef
[]
---------------[ System Tests ]---------------
System stest22.56.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Tests highlighting when one word is input. ran in 0.01s
System stest22.56.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Tests highlighting of a word in list of multiple words. ran in 0.01s
System stest22.56.3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Tests highlighting of multiple words in list of multiple words. ran in 0.01s

All 3 Tests Passed 
Congrats, here's your flag
pwn.college{AP2HYVD98KBQX7cPsBHTyN6INHF.QX3UTO3EDL4ITM0EzW}
```