---
custom_edit_url: null
sidebar_position: 5
slug: /pwn-college/intro-to-programming-languages/leclabs-2.3
---

## Lab 2.3.1.0 - Print Non-Printable Characters

### Code

```c title="main.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>

/** CODE: contains_non_printable(const char *str)  
 *          checks each character in the string 
 *          if character is not printable then return true
 *          if all characters are printable return false
*/
bool contains_non_printable(const char *str) {
   
    int i = 0;

    while (str[i] != '\0') {
        
        if (isprint((unsigned char)str[i]) == 0) {
            return true;
        }

        i++;
    } 

    return false;
}

/** CODE:  print_non_printable_hex(const char *str) 
 *          checks each character in the string
 *          if printable then print character
 *          else use printf("\033[31m\\x%02X\033[0m"
*/
void print_non_printable_hex(const char *str) {

    int i = 0;

    while (str[i] != '\0') {

        unsigned char c = (unsigned char)str[i];

        if (isprint(c)) {
            printf("%c", c);
        } else {
            printf("\033[31m\\x%02X\033[0m", c);
        }

        i++;
    }
}

/**  CODE: main 
 *          if no argument is provided then printf("Usage: %s <string>\n", argv[0]); and return 1
 *          Check if contains_non_printable is true
 *              then call print_non_printable_hex 
 *              else print string as is          
*/
int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: %s <string>\n", argv[0]); 
        return 1;
    }

    bool is_non_printable = contains_non_printable(argv[1]);

    if (is_non_printable == false) {
        printf("%s", argv[1]);
    }
    else {
        print_non_printable_hex(argv[1]);
    }

    return 0;
}
```

### Tests
#### System tests

Too many.

```
hacker@23-lela-pointers~lab-2-3-1-0-print-non-printable-chars:~/cse240/labw/lab23/01$ gcc main.c -g -o main.bin
```

```
hacker@23-lela-pointers~lab-2-3-1-0-print-non-printable-chars:~/cse240/labw/lab23/01$ /challenge/tester 
Build: ✔ PASS - 0.08s
Copied /home/hacker/cse240/labw/lab23/01/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 54151869a5601106aaf5eee80f927f78
[]
---------------[ System Tests ]---------------
System stest5.1.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program prints out provided string. ran in 0.01s
System stest5.1.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program prints out the non-printable character. ran in 0.01s
System stest5.1.3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program prints out usage message with no args. ran in 0.01s
System stest5.1.4: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program prints out the non-printable character. ran in 0.01s

All 4 Tests Passed 
Congrats, here's your flag
pwn.college{kblS0S0HDo8mSXNCZRjskzkupkK.QX4UTO3EDL4ITM0EzW}
```

&nbsp;

## EzLabs 2.3.2.1 - Character Pointers

### Code

```c title="main.c" showLineNumbers
#include<stdio.h>

int main(){
    char cVal1 = 'X';
    char cVal2 = 'Y';
    
    char *cPtr1 = NULL;
    char *cPtr2 = NULL; 
    
    // CODE: set cPtr1 equal to address of cVal1
    cPtr1 = &cVal1;

    // CODE: set cPtr2 equal to address of cVal2
    cPtr2 = &cVal2;

    printf("*cPtr1=%c\n",*cPtr1);
    printf("*cPtr2=%c\n",*cPtr2);

    // CODE: set value of *cPtr2 to 'M'
    *cPtr2 = 'M';

    printf("*cPtr2=%c\n",*cPtr2);

}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["*cPtr1=X","*cPtr2=Y","*cPtr2=M"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the 3 characters X, Y, and M."

}
```

```
hacker@23-lela-pointers~ezlab-2-3-2-1-character-pointers:~/cse240/labw/lab23/02$ gcc main.c -g -o main.bin
```

```
hacker@23-lela-pointers~ezlab-2-3-2-1-character-pointers:~/cse240/labw/lab23/02$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab23/02/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of ce76e8fbd7e6a0c26845f24352950360
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 1 Tests Passed 
Congrats, here's your flag
pwn.college{wdFOofXDqI07I-4g3fNRfAlZrN8.QX5UTO3EDL4ITM0EzW}
```

&nbsp;

## EzLabs 2.3.2.1 - C-String Pointers

### Code

```c title="main.c" showLineNumbers
#include<string.h>
#include<stdio.h>

int main(int argc, char *argv[]){

    char str[200] = "";
    // this if protects against a seg fault when no argument is provided
    if (argc < 2){ 
        printf("Usage: %s 'your string' \n", argv[0] );
        return 1;
    }
    strncpy(str, argv[1], 199);
    char * strPtr;

    strPtr = str;

    while (*strPtr != '\0'){
        // CODE: print char using *strPtr followed by newline 
        printf("%c\n", *strPtr);

        // CODE: print string using %s and strPtr (no * used, %s dereferences for us) followed by newline 
        printf("%s\n", strPtr);

        // CODE: increment strPtr's value by 1
        strPtr += 1;
    }
    

    return 0;
}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": ["tester"],
    "input": [""],
    "output": ["t","tester","e","ester","s","ster","t","ter","e","er","r","r"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the character of the string tester and all of its substrings."
}
```

```json title="2.json" showLineNumbers
{
    "args": ["dragon"],
    "input": [""],
    "output": ["d", "dragon", "r", "ragon", "a", "agon", "g", "gon", "o", "on", "n", "n"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the character of the string dragon and all of its substrings."
}
```

```
hacker@23-lela-pointers~ezlab-2-3-2-1-c-string-pointers:~/cse240/labw/lab23/03$ gcc main.c -g -o main.bin
```

```
/chahacker@23-lela-pointers~ezlab-2-3-2-1-c-string-pointers:~/cse240/labw/lab23/03$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab23/03/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 75092f230afc98a628a727a825837a62
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 2 Tests Passed 
Congrats, here's your flag
pwn.college{8GMzCWeRQwwemopcUpl8nWZZmJg.QXwYTO3EDL4ITM0EzW}
```

&nbsp;

## EzLabs 2.3.3.1 - Finding str in str (strstr)

### Code

```c title="main.c" showLineNumbers
#include<stdio.h>
#include<string.h>

int main(int argc, char * argv[]){
    char haystack[] = "Using strstr in C is like playing hide and seek with your strings, except strstr is that one friend who always knows exactly where you're hiding!";
    char needle[200] = "";
    
    // this if protects against a seg fault when no argument is provided
    if (argc < 2){ 
        printf("Usage: %s 'your string' \n", argv[0] );
        return 1;
    }
    printf("Original String: \"%s\"\n", haystack);
    strcpy(needle, argv[1]);
    
    // CODE: create a variable named result that's 
    //       a char pointer
    char *result;
    
    // CODE: use strstr to find the needle in the haystack
    //       set it equal to result;
    result = strstr(haystack, needle);

    if (result == NULL){
        printf("\"%s\" was not found\n", needle);
    } else {
        // using ^ to show where the needle was found in the string
        printf("Marker          >>");
        int offset = 0;
        // CODE: calculate the offset of the result in the haystack (hint: subtract haystack from result)
        offset = result - haystack; 
        
        // CODE: print out the number of spaces to the left of the needle (aka the offset)
        //       loop through from 0 to offset and print a space for each iteration
        for (int i = 0; i < offset; i++) {
            printf("%c", ' ');
        }
        
        // print the marker
        for (int i = 0; i < strlen(needle); i++) {
            printf("^");
        }

        printf("\n");

        // CODE: replace XXXXXX with the result variable 
        printf("Found \"%s\" starting at index %d\nreturned string is \"%s\"", needle, offset, result);
    }
    printf("\n");
    return 0;
}
```

### Tests

#### System tests

```json title="1.json" showLineNumbers
{
    "args": ["playing"],
    "input": [""],
    "output": [
                "Original String: \"Using strstr in C is like playing hide and seek with your strings, except strstr is that one friend who always knows exactly where you're hiding!\"",
                "Marker          >>                          ^^^^^^^",
                "Found \"playing\" starting at index 26",
                "returned string is \"playing hide and seek with your strings, except strstr is that one friend who always knows exactly where you're hiding!\""
            ],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program finds the argument in the string."
}
```

```json title="2.json" showLineNumbers
{
    "args": ["friend"],
    "input": [""],
    "output": [
        "Original String: \"Using strstr in C is like playing hide and seek with your strings, except strstr is that one friend who always knows exactly where you're hiding!\"",
        "Marker          >>                                                                                             ^^^^^^",
        "Found \"friend\" starting at index 93",
        "returned string is \"friend who always knows exactly where you're hiding!\""
    ],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program finds friend in the string."
}
```

```
hacker@23-lela-pointers~ezlab-2-3-3-1-find-str-in-str-strstr:~/cse240/labw/lab23/04$ gcc main.c -g -o main.bin
```

```
hacker@23-lela-pointers~ezlab-2-3-3-1-find-str-in-str-strstr:~/cse240/labw/lab23/04$ /challenge/tester 
Build: ✔ PASS - 0.08s
Copied /home/hacker/cse240/labw/lab23/04/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of ad7b8b18546bb7bdd0fae9e4f0d8ca68
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 2 Tests Passed 
Congrats, here's your flag
pwn.college{MjEud9LPN01XbUe_58HbIVfjHPi.QXxYTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.3.3.1 - Find Word Count

### Code

```c title="main.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include <ctype.h>

// Maximum length for a line
#define MAX_LINE_LENGTH 1024


/** CODE: int count_occurrences(char *line, char *word) 
 *          This function counts the number of times a word appears in a line and returns that count 
 *          Consider using strstr and pointers to loop through the input similar to the way strtok works
 * */
int count_occurrences(char *line, char *word) {
    int count = 0;
    int len = strlen(word);
    char *pos = line;

    if (len == 0) { 
        return 0;
    }

    while ((pos = strstr(pos, word)) != NULL) {

        if ((pos == line || !isalpha(pos[-1])) &&
            (!isalpha(pos[len]))) {
            count++;
        }

        pos += len;   
    }

    return count;
}


int main (int argc, char *argv[]) {
    
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <filename> <word>\n", argv[0]);
        return 1;
    }

    char *filename = argv[1];   // arg 1 is the filename
    char *word = argv[2];       // arg 2 is the word to count 
    char line[MAX_LINE_LENGTH]; 
    int total_occurrences = 0;

    /** CODE: openthe file and set a file pointer  */
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }
    
    /** CODE: Read the file line by line using fgets*/
    while (fgets(line, MAX_LINE_LENGTH, file) != NULL) {
        total_occurrences += count_occurrences(line, word);
    }
    
    printf("The word '%s' occurs %d times in the file.\n", word, total_occurrences);

    /** CODE: close the file */
    fclose(file);    

    return 0;
}

```

### Tests
#### System tests

Too many.

```
hacker@23-lela-pointers~lab-2-3-3-1-find-word-count:~/cse240/labw/lab23/05$ gcc main.c -g -o main.bin
```

```
hacker@23-lela-pointers~lab-2-3-3-1-find-word-count:~/cse240/labw/lab23/05$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab23/05/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 216e89327571d5fbf833a6895a83d601
[]
---------------[ System Tests ]---------------
System stest5.3.1: target_path: /challenge/system_tests/main.bin
The execution ran for too long for main.bin
Usually, a timeout indicates a problem with the program failing to exit on receipt of an exit command. 
Verify that your program is exiting correctly and that the test case 'stest5.3.1' is entering the exit command
Another issue that can cause this behavior is when the program fails to clear the buffer (check user inputs)
        Command          : /challenge/system_tests/main.bin /challenge/system_tests/input5.3.1.dat light
        Input Data:      :'\n'
hacker@23-lela-pointers~lab-2-3-3-1-find-word-count:~/cse240/labw/lab23/05$ gcc main.c -g -o main.bin
hacker@23-lela-pointers~lab-2-3-3-1-find-word-count:~/cse240/labw/lab23/05$ /challenge/tester 
Build: ✔ PASS - 0.07s
A previous running process /challenge/system_tests/main.bin has been terminated.
Copied /home/hacker/cse240/labw/lab23/05/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 2835253ee1651e3eb85bc0717ebc9c40
[]
---------------[ System Tests ]---------------
System stest5.3.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program finds light twice in the file. ran in 0.01s
System stest5.3.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program finds book twice in the file. ran in 0.01s
System stest5.3.3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program finds 'power' three times in the file. ran in 0.01s

All 3 Tests Passed 
Congrats, here's your flag
pwn.college{kQeC6AHj9q3qBVQQoQKv8g9czqq.QX2YzN3EDL4ITM0EzW}
```

&nbsp;

## EzLabs 2.3.3.2 - Get tokens (strtok)
### Code

```c title="main.c" showLineNumbers
#include<stdio.h>
#include<string.h>

int main(int argc, char * argv[]){
    char delimiter[5] = " ";
    char haystack[200]; 
    // this if protects against a seg fault when no argument is provided
    if (argc < 2){ 
        printf("Usage: %s 'your string' \n", argv[0] );
        return 1;
    }
    strcpy(haystack, argv[1]);
    
    // CODE: create a variable named str_result that's 
    //       a char pointer
    char *str_result = "";
        
    // CODE: use strtok with haystack and delimiter and return into str_result;
    str_result = strtok(haystack, delimiter);

    while (str_result != NULL){
        // CODE: print the current word then a new line
        // CODE: use strtok the first parameter as NULL and the delimiter as the second
        printf("%s\n", str_result);
        str_result = strtok(NULL, delimiter);
    }

}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": ["Using strtok in C is like having a string-slicing ninja that can chop your sentences into pieces-but first you must provide the delimiter katana!"],
    "input": [""],
    "output": ["Using", "strtok", "in", "C", "is", "like", "having", "a", "string-slicing", "ninja", "that", "can", "chop", "your", "sentences", "into", "pieces-but", "first", "you", "must", "provide", "the", "delimiter", "katana!"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program finds the argument in the string."
}
```

```json title="2.json" showLineNumbers
{
    "args": ["Like a hound on the trail, with a nose oh so keen, It sniffs out that char, if you know what I mean."],
    "input": [""],
    "output": ["Like", "a", "hound", "on", "the", "trail,", "with", "a", "nose", "oh", "so", "keen,", "It", "sniffs", "out", "that", "char,", "if", "you", "know", "what", "I", "mean." ],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program finds friend in the string."
}
```

```
hacker@23-lela-pointers~ezlab-2-3-3-2-get-tokens-strtok:~/cse240/labw/lab23/06$ gcc main.c -g -o main.bin
```

```
hacker@23-lela-pointers~ezlab-2-3-3-2-get-tokens-strtok:~/cse240/labw/lab23/06$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab23/06/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 43824c4316b4fc102fb45de118fe80e0
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 2 Tests Passed 
Congrats, here's your flag
pwn.college{4URhL58-TxYcGwybKHiLY46lvCE.QXyYTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.3.3.2 - Word Count

### Code
```c title="main.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_INPUT 1000
#define MAX_WORDS 100
#define MAX_WORD_LENGTH 50

/** CODE: to_lowercase(char *str) 
 *          loops through the string and changes all values to lowercase
*/
void to_lowercase(char *str) {
    int i = 0;

    while (str[i] != '\0') {
        str[i] = tolower(str[i]);
        i++;
    }
}

/** CODE: find_word(char words[][MAX_WORD_LENGTH], int size, char *word) 
 *          search through all the words already found and see if a match occurs
 *          if a match is found return the index of the match
 *          if no match is found then return -1    
*/

int find_word(char words[][MAX_WORD_LENGTH], int size, char *word) {
    
    for (int i = 0; i < size; i++) {
        if (strcmp(words[i], word) == 0) {
           return i; 
        }
    }
    return -1;
}

/** CODE: main 
 *          prompt for user to enter a sentence
 *          receive standard input using fgets into the input variable
 *          if the last character of input is a newline, then remove it
 *          use strtok to tokenize the input based on spaces (" ")
 *          while strtok finds a new word continue to loop through the words in the sentence
 *              call find_words
 *              if the return is -1 
 *                  copy the word to the words array and set the count = 1
 *              if the return is not -1
 *                  increase the counter at the found index
 *          print out all the counts for each word
*/
int main (int argc, char* argv[]) {
    char input[MAX_INPUT];
    char found_words[MAX_WORDS][MAX_WORD_LENGTH];
    int counts[MAX_WORDS] = {0};
    int word_count = 0;
    char *token;
    
    /** CODE: here */
    printf("Enter the sentence.\n");
    fgets(input, MAX_INPUT, stdin);

    if (input[strlen(input) - 1] == '\n') {
        input[strlen(input) - 1] = '\0';
    }

    to_lowercase(input);

    token = strtok(input, " ");

    while (token != NULL) {
        int index = find_word(found_words, word_count, token);
        if (index == -1) {
            strcpy(found_words[word_count], token);
            counts[word_count] = 1;
            word_count++;
        }
        else {
            counts[index]++;
        }

        token = strtok(NULL, " ");
    }

    printf("Word counts:\n");
    for (int i = 0; i < word_count; i++) {
        printf("%s: %d\n", found_words[i], counts[i]);
    }

    return 0;
}
```

### Tests
#### User tests

```json title="1.json" showLineNumbers
{
    "input": ["This is too fun is it not"],
    "output": [
        "this: 1",
        "is: 2",
        "too: 1",
        "fun: 1",
        "it: 1",
        "not: 1"
    ],
    "nameOfModelGoodTest": "Test for <testfilename> to Pass with words provided in input being tallied correctly",
    "descriptionOfModelGoodTest": "A properly working test case should pass when executing modelGood. ",
    "nameOfModelBadTest": "Test for ./modelBad23.32.1.bin to fail because it will create the correct tallies for the words. ",
    "descriptionOfModelBadTest": "A properly working test case should fail when executing a modelBad because this version of the modelBad is designed to fail this test case. So, passing the test means that given the inputs the expected output will not match the actual output."
}
```

### System tests
Too many.

```
hacker@23-lela-pointers~lab-2-3-3-2-word-count:~/cse240/labw/lab23/07$ gcc main.c -g -o main.bin
```

```
hacker@23-lela-pointers~lab-2-3-3-2-word-count:~/cse240/labw/lab23/07$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab23/07/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of a380e9c525d70418a00b3a3e5f2a6ba4
['/home/hacker/cse240/labw/lab23/07/user_tests/utest23.32.1.json']
---------------[  User Tests  ]---------------
User utest23.32.1: target_path: /challenge/modelBad23.32.1.bin
✔ PASS  - Test for ./modelBad23.32.1.bin to fail because it will create the correct tallies for the words.  ran in 0.01s
User utest23.32.1: target_path: /challenge/modelGood.bin
✔ PASS  - Test for modelGood.bin to Pass with words provided in input being tallied correctly ran in 0.01s
User utest23.32.1: target_path: /home/hacker/cse240/labw/lab23/07/main.bin
✔ PASS  - Test for main.bin to Pass with words provided in input being tallied correctly ran in 0.01s

---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test for the counts for the above input ran in 0.01s
System stest2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test input for the expected counts  ran in 0.01s

All 5 Tests Passed 
Congrats, here's your flag
pwn.college{UxSLzKjOEcl_lrrnl376q6xLLfF.QX4YzN3EDL4ITM0EzW}
```