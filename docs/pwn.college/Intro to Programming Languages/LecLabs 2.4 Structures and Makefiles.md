---
custom_edit_url: null
sidebar_position: 7
slug: /pwn-college/intro-to-programming-languages/leclabs-2.4
---

## EzLab 2.4.1.1 - Using a struct

### Code
```c title="main.c" showLineNumber
#include<stdio.h>

// CODE: create a struct named Person with name[50], age, and height.
struct Person {
    char name[50];
    int age;
    int height;
};

int main() {

    // CODE: declare and define a variable of type struct Person 
    //       make it equal to {"Bob", 24, 72}

    struct Person person = {
        "Bob",
        24,
        72
    };

    // CODE: fill in the XXXXX, YYYYY, ZZZZZ according to the print statement.
    printf("Name  : %s\n", person.name);
    printf("Age   : %d\n", person.age);
    printf("Height: %d\n", person.height);

    return 0;
}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["Name  : Bob","Age   : 24","Height: 72"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints out the person's data."

}
```

```
hacker@24-lela-struct-make~ezlab-2-4-1-1-using-a-struct:~/cse240/labw/lab24/01$ gcc main.c -g -o main.bin
```

```
hacker@24-lela-struct-make~ezlab-2-4-1-1-using-a-struct:~/cse240/labw/lab24/01$ /challenge/tester 
Build: ✔ PASS - 0.06s
Copied /home/hacker/cse240/labw/lab24/01/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of bb23fde0c265169d173cdd9ffb66b951
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 1 Tests Passed 
Congrats, here's your flag
pwn.college{knnVvHADxTt8YLVOEaRhs71TnTB.QXzYTO3EDL4ITM0EzW}
```

&nbsp;

## EzLab 2.4.1.4 - Struct from string

### Code

```c title="main.c" showLineNumbers
#include<stdio.h>
#include<string.h>

// CODE: create a struct named Vehicle with name[50] and year
typedef struct Vehicle {
    char name[50];
    int year;
} Vehicle;

int main(int argc, char * argv[]){

    // CODE: create a variable named vehicle of type struct Vehicle
    Vehicle vehicle;

    char * item;
    char line[100] = "";
    if (argc < 2 || strstr(argv[1],",") == 0){
        strcpy(line, "Jeep CJ7,1999");
    } else {
        strcpy(line, argv[1]);
    }
    
    // CODE: strtok use "," as the delimiter and set result to item
    item = strtok(line, ",");
    
    // CODE: copy result to vehicle 
    strcpy(vehicle.name, item);
    
    // CODE: use strtok to get next item 
    item = strtok(NULL, ",");
    
    // CODE: Using sscanf to save to year, replace XXXXX, don't forget the &
    sscanf(item, "%d", &vehicle.year);
    
    // CODE: replace YYYYY and ZZZZZ with the proper fields. 
    printf("Name: %s\n", vehicle.name);
    printf("Year: %d\n", vehicle.year);

    return 0;
}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["Name: Jeep CJ7","Year: 1999"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints out Jeep data when no argument is supplied."
}
```

```json title="2.json" showLineNumbers
{
    "args": ["Nissan Sentra,1993"],
    "input": [""],
    "output": ["Name: Nissan Sentra","Year: 1993"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints out Nissan data when provided as an argument."
}
```

```
hacker@24-lela-struct-make~ezlab-2-4-1-4-struct-from-string:~/cse240/labw/lab24/02$ gcc main.c -g -o main.bin
```

```
hacker@24-lela-struct-make~ezlab-2-4-1-4-struct-from-string:~/cse240/labw/lab24/02$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab24/02/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 63b7a5a3cc952db4c7a4540edd4b9c60
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 2 Tests Passed 
Congrats, here's your flag
pwn.college{0jHLICtNTP_AN1Wubk_kQr9DYg_.QX3YTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.4.1.5 - Songs List

### Code

```c title="main.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_GENRE_LENGTH 30
#define MAX_ARTIST_LENGTH 50
#define MAX_TITLE_LENGTH 100

typedef struct Song {
    char genre[MAX_GENRE_LENGTH];
    char artist[MAX_ARTIST_LENGTH];
    char title[MAX_TITLE_LENGTH];
} Song;

/** CODE: remove_char_from_end(char * str, char char_to_remove)
 *          Removes char_to_remove from the end of a c-string if it exists 
 * */
void remove_char_from_end(char * str, char char_to_remove){

    if (str[strlen(str) - 1] == char_to_remove) {
        str[strlen(str) - 1] = '\0';
    }
    
}

/**  CODE: Song* read_songs_from_file(const char *filename, int *count)  
 *          Open file using provided filename
 *          Allocate initial memory for songs, capacity = 10, don't forget sizeof()  
                Memory Address      | Data (Song Struct)
                --------------------|---------------------------------------------------------
                0x1000              | Song 1
                0x1000 - 0x101D     |   genre (30 bytes)
                0x101E - 0x1049     |   artist (50 bytes)
                0x104A - 0x10D3     |   title (100 bytes)
                --------------------|---------------------------------------------------------
                0x10D4              | Song 2
                0x10D4 - 0x10F1     |   genre (30 bytes)
                0x10F2 - 0x111D     |   artist (50 bytes)
                0x111E - 0x11A7     |   title (100 bytes)
                --------------------|---------------------------------------------------------
                ...
 *          While getline  (using getline, which auto allocates on the heap any size of input)
 *              if +++BEGIN check if song_index is >= capacity, then allocate more space for list, next use memset to set all the strings to 0
 *              Clean up line using remove_char_from_end
 *              If genre: artist: title: in line then 
 *                  Copy the value to the structure using strncpy
 *                  Add null terminator to the end of the field b/c strncpy does not guarantee null termination when value is longer than genre's max size
 *          Set count pointer equal to song_index + 1 
 *          Close file and free line
 *          
 *              
*/
Song* read_songs_from_file(const char *filename, int *count) {
    FILE *file = NULL;

    char *line = NULL;
    size_t len = 0;

    int capacity = 10;
    
    Song *songs = malloc(capacity * sizeof(Song));

    int song_index = -1;
    
    file = fopen(filename, "r");

    // syntax: getline(buffer, len buffer var, file pointer) returns -1 when at EOF
    while ( (getline(&line, &len, file)) != -1 ) {

        if ((strstr(line, "+++ BEGIN")) != NULL) {
            song_index++;
            if(song_index >= capacity) {
                capacity *= 2;
                songs = realloc(songs, capacity * sizeof(Song));
            }
            continue;
        }

        if (song_index >= 0) {

            char* value;

            remove_char_from_end(line, '\n');
            remove_char_from_end(line, ',');

            if ( (value = strstr(line, "genre")) != NULL) {
                strcpy(songs[song_index].genre, value + strlen("genre:")); 
            }

            if ( (value = strstr(line, "artist")) != NULL) {
                strcpy(songs[song_index].artist, value + strlen("artist:")); 
            }

            if ( (value = strstr(line, "title")) != NULL) {
                strcpy(songs[song_index].title, value + strlen("title:")); 
            }
        }

    }

    free(line);
    *count = song_index + 1; 
    return songs;
}


int main(int argc, char * argv[]) {
    int song_count = 0;
    if (argc < 2){
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    Song *songs;
    /** CODE: call read_songs_from_file set result to songs */
    songs = read_songs_from_file(argv[1], &song_count);
    
    printf("Read %d songs from file:\n", song_count);

    /** CODE: print every five songs from the array */
    for (int i = 0; i < song_count; i = i+5) {
        printf("Genre: %s, Artist: %s, Title: %s\n", songs[i].genre, songs[i].artist, songs[i].title);
    }

    /** CODE: free songs */
    
    return 0;
}
```

### Tests
#### System tests

Too many.

```
hacker@24-lela-struct-make~lab-2-4-1-5-songs-list:~/cse240/labw/lab24/03$ gcc main.c -g -o main.bin
```

```
hacker@24-lela-struct-make~lab-2-4-1-5-songs-list:~/cse240/labw/lab24/03$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab24/03/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 773c90b40c06748da71254a14f95f220
[]
---------------[ System Tests ]---------------
System stest4: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program does not print out the third song "needy". ran in 0.01s
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program read in all the songs. ran in 0.01s
System stest5: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program does not print out too much data. ran in 0.01s
System stest2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program prints out first song by Ariana Grande. ran in 0.01s
System stest3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program does not print out All My Rowdy Friends. ran in 0.01s

All 5 Tests Passed 
Congrats, here's your flag
pwn.college{sCbSrYXQfwO68ShoRgx7UdzblPc.QX0YTO3EDL4ITM0EzW}
```

&nbsp;

## EzLab 2.4.2.1 - C Preprocessor

### Code

```c title="main.c" showLineNumbers
#include<stdio.h>

int main(){

    // CODE: add an ifdef, or if defined, for MACRO_VAR_1
    //       When the code is compiled we will use -DMACRO_VAR_1=99
    #ifdef MACRO_VAR_1
   
        // CODE: replace XXXXXX with MACRO_VAR_1
        printf("MACRO_VAR_1 %d\n", MACRO_VAR_1);

    // CODE: end the if 
    #endif

    // CODE: define a macro variable called MACRO_VAR_2 
    //       make it equal to 88 (no equal sign is used)
    #define MACRO_VAR_2 88
    
    // CODE: replace YYYYY with MACRO_VAR_2
    printf("MACRO_VAR_2 %d\n", MACRO_VAR_2);

    return 0;
}
```

```
hacker@24-lela-struct-make~ezlab-2-4-2-1-c-preprocessor:~/cse240/labw/lab24/04$ gcc main.c -g -o main.bin
```

```
hacker@24-lela-struct-make~ezlab-2-4-2-1-c-preprocessor:~/cse240/labw/lab24/04$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab24/04/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of f933c9904dc5bf8c87be3bcd0787a89c
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
Build: ✔ PASS - 0.07s
System stest2: target_path: /challenge/system_tests/altmain2.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 2 Tests Passed 
Congrats, here's your flag
pwn.college{gnDGUIaxBRG021fEElYJOlLDjn_.QX4YTO3EDL4ITM0EzW}
```

&nbsp;

## EzLab 2.4.2.6 - Makefile

### Code

```c title="main.c" showLineNumbers
#include<stdio.h>
#include "printer.h"
#include "other.h"

/**
 * 1. Modify printer.h and add a header guard
 * 2. Add the missing lines to the Makefile by following the instructions in the comments.
 */

int main(){
    struct Person person = {"Tom", 53};
    print_the_info(person);
    printf("info printed\n");
}
```

```c title="printer.c" showLineNumbers
#include "printer.h"
#include <stdio.h>

void print_the_info(struct Person person){
    printf("This is the info:\n\tName: %s \n\tAge :%d\n",person.name, person.age);
}
```

```c title="printer.h" showLineNumbers
// CODE: add header guards
#ifndef PRINTER_H
#define PRINTER_H

struct Person{
    char name[50];
    int age;
};

void print_the_info(struct Person person);

// CODE: end header guard's if 
#endif 
```

```c title="other.h" showLineNumbers
#include "printer.h"
```

```make title="Makefile" showLineNumbers
# Default rule
all: main.bin

# Step 1
# Find the targets and dependencies using the gcc command below
main.o: main.c printer.h
	gcc -c main.c -o main.o

# Step 2
# Copy the rule for main.o and dependencies from the output of the gcc command above 
# Create a gcc command to compile main.o
# 	The compile statement must use -c to create an object file (intermediate file) gcc -c main.c 
# 	Must indent the gcc command using a tab character
#   Can explicitly use the -o option to name the output file main.o
printer.o: printer.c printer.h
	gcc -c printer.c -o printer.o

# Step 3 
# Create the rule for printer.o and depencencies from the output of the -MM gcc command above
# Create a gcc command to compile printer.o
#	Use -c to create the object file and use the printer.c as the source file
# 	Must indent the gcc command using a tab 
main.bin: main.o printer.o
	gcc main.o printer.o -o main.bin
	
# Step 4
# Rule to link the object files and create the executable main.bin
# main.bin is dependent on (:) main.o and printer.o 
# Insert a tab and use gcc to compile 
#     Instead of source code we use the intermediate files main.o and printer.o as input
#     Output of the binary will be main.bin (use -o to name the output binary file) 
	gcc -c main.o printer.o -o main.bin

# Rule to clean up the directory
clean:
	rm -f main.bin main.o printer.o
```

```
hacker@24-lela-struct-make~ezlab-2-4-2-6-makefiles:~/cse240/labw/lab24/05$ make Makefile 
make: Nothing to be done for 'Makefile'.
````

````
hacker@24-lela-struct-make~ezlab-2-4-2-6-makefiles:~/cse240/labw/lab24/05$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab24/05/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 981100ccb0636acfb9182af994b0e9b7
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 1 Tests Passed 
Congrats, here's your flag
pwn.college{gcX5l30UAM3NDyT9LyqFgmT9y_8.QX5YTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.4.2.6 - Make Songs

### Code

```c title="main.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "songs.h"


int main(int argc, char * argv[]) {
    int song_count = 0;
    if (argc < 2){
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    Song *songs;
    /** CODE: call read_songs_from_file set result to songs */
    songs = read_songs_from_file(argv[1], &song_count);
    
    printf("Read %d songs from file:\n", song_count);

    /** CODE: print every five songs from the array */
    for (int i = 0; i < song_count; i = i+5) {
        printf("Genre: %s, Artist: %s, Title: %s\n", songs[i].genre, songs[i].artist, songs[i].title);
    }

    /** CODE: free songs */
    
    return 0;
}
```

```c title="utils.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include "utils.h"

/** CODE: remove_char_from_end(char * str, char char_to_remove)
 *          Removes char_to_remove from the end of a c-string if it exists 
 * */

void remove_char_from_end(char * str, char char_to_remove){

    if (str[strlen(str) - 1] == char_to_remove) {
        str[strlen(str) - 1] = '\0';
    }   
}
```

```c title="utils.h" showLineNumbers
#ifndef UTILS_H
#define UTILS_H

void remove_char_from_end(char * str, char char_to_remove);

#endif
```

```c title="songs.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "songs.h"
#include "utils.h"

/**  CODE: Song* read_songs_from_file(const char *filename, int *count)  
 *          Open file using provided filename
 *          Allocate initial memory for songs, capacity = 10, don't forget sizeof()  
                Memory Address      | Data (Song Struct)
                --------------------|---------------------------------------------------------
                0x1000              | Song 1
                0x1000 - 0x101D     |   genre (30 bytes)
                0x101E - 0x1049     |   artist (50 bytes)
                0x104A - 0x10D3     |   title (100 bytes)
                --------------------|---------------------------------------------------------
                0x10D4              | Song 2
                0x10D4 - 0x10F1     |   genre (30 bytes)
                0x10F2 - 0x111D     |   artist (50 bytes)
                0x111E - 0x11A7     |   title (100 bytes)
                --------------------|---------------------------------------------------------
                ...
 *          While getline  (using getline, which auto allocates on the heap any size of input)
 *              if +++BEGIN check if song_index is >= capacity, then allocate more space for list, next use memset to set all the strings to 0
 *              Clean up line using remove_char_from_end
 *              If genre: artist: title: in line then 
 *                  Copy the value to the structure using strncpy
 *                  Add null terminator to the end of the field b/c strncpy does not guarantee null termination when value is longer than genre's max size
 *          Set count pointer equal to song_index + 1 
 *          Close file and free line
 *          
 *              
*/

Song* read_songs_from_file(const char *filename, int *count) {
    FILE *file = NULL;

    char *line = NULL;
    size_t len = 0;

    int capacity = 10;
    
    Song *songs = malloc(capacity * sizeof(Song));

    int song_index = -1;
    
    file = fopen(filename, "r");

    // syntax: getline(buffer, len buffer var, file pointer) returns -1 when at EOF
    while ( (getline(&line, &len, file)) != -1 ) {

        if ((strstr(line, "+++ BEGIN")) != NULL) {
            song_index++;
            if(song_index >= capacity) {
                capacity *= 2;
                songs = realloc(songs, capacity * sizeof(Song));
            }
            continue;
        }

        if (song_index >= 0) {

            char* value;

            remove_char_from_end(line, '\n');
            remove_char_from_end(line, ',');

            if ( (value = strstr(line, "genre")) != NULL) {
                strcpy(songs[song_index].genre, value + strlen("genre:")); 
            }

            if ( (value = strstr(line, "artist")) != NULL) {
                strcpy(songs[song_index].artist, value + strlen("artist:")); 
            }

            if ( (value = strstr(line, "title")) != NULL) {
                strcpy(songs[song_index].title, value + strlen("title:")); 
            }
        }

    }

    free(line);
    *count = song_index + 1; 
    return songs;
}
```

```c title="songs.h" showLineNumbers
#ifndef SONGS_H
#define SONGS_H

#define MAX_GENRE_LENGTH 30
#define MAX_ARTIST_LENGTH 50
#define MAX_TITLE_LENGTH 100

typedef struct Song {
    char genre[MAX_GENRE_LENGTH];
    char artist[MAX_ARTIST_LENGTH];
    char title[MAX_TITLE_LENGTH];
} Song;

Song* read_songs_from_file(const char *filename, int *count);

#endif
```

```
hacker@24-lela-struct-make~lab-2-4-2-6-make-songs:~/cse240/labw/lab24/06$ make Makefile 
make: Nothing to be done for 'Makefile'.
```

```
hacker@24-lela-struct-make~lab-2-4-2-6-make-songs:~/cse240/labw/lab24/06$ /challenge/tester 
Build: ✔ PASS - 0.09s
Copied /home/hacker/cse240/labw/lab24/06/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of f773586679356f93462d8d8ef471d75a
[]
---------------[ System Tests ]---------------
System stest2415.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program read in all the songs. ran in 0.01s
System stest2415.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program prints out first song by Ariana Grande. ran in 0.01s
System stest2415.3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program does not print out All My Rowdy Friends. ran in 0.01s
System stest2415.4: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program does not print out the third song "needy". ran in 0.01s
System stest2415.5: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program does not print out too much data. ran in 0.01s
System stest2426.1: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify main.c includes "songs.h" ran in 0.01s
System stest2426.2: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify main.c does not contain "typdef struct" or "MAX_" ran in 0.01s
System stest2426.3: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify Makefile contains songs.o dependency information. ran in 0.01s
System stest2426.4: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify Makefile contains utils dependency information. ran in 0.01s
System stest2426.5: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify utils.h contains remove_char_from_end declaration. ran in 0.01s

All 10 Tests Passed 
Congrats, here's your flag
pwn.college{oCWurKDiy2Z9knSvFIAHDLuQuDd.QX1YTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.4.2.6 - Make Songs

### Code


````c title="main.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "songs.h"


int main(int argc, char * argv[]) {
    int song_count = 0;
    if (argc < 2){
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    Song *songs;
    /** CODE: call read_songs_from_file set result to songs */
    songs = read_songs_from_file(argv[1], &song_count);
    
    printf("Read %d songs from file:\n", song_count);

    /** CODE: print every five songs from the array */
    for (int i = 0; i < song_count; i = i+5) {
        printf("Genre: %s, Artist: %s, Title: %s\n", songs[i].genre, songs[i].artist, songs[i].title);
    }

    /** CODE: free songs */
    
    return 0;
}
````

```c title="songs.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "songs.h"
#include "utils.h"

/**  CODE: Song* read_songs_from_file(const char *filename, int *count)  
 *          Open file using provided filename
 *          Allocate initial memory for songs, capacity = 10, don't forget sizeof()  
                Memory Address      | Data (Song Struct)
                --------------------|---------------------------------------------------------
                0x1000              | Song 1
                0x1000 - 0x101D     |   genre (30 bytes)
                0x101E - 0x1049     |   artist (50 bytes)
                0x104A - 0x10D3     |   title (100 bytes)
                --------------------|---------------------------------------------------------
                0x10D4              | Song 2
                0x10D4 - 0x10F1     |   genre (30 bytes)
                0x10F2 - 0x111D     |   artist (50 bytes)
                0x111E - 0x11A7     |   title (100 bytes)
                --------------------|---------------------------------------------------------
                ...
 *          While getline  (using getline, which auto allocates on the heap any size of input)
 *              if +++BEGIN check if song_index is >= capacity, then allocate more space for list, next use memset to set all the strings to 0
 *              Clean up line using remove_char_from_end
 *              If genre: artist: title: in line then 
 *                  Copy the value to the structure using strncpy
 *                  Add null terminator to the end of the field b/c strncpy does not guarantee null termination when value is longer than genre's max size
 *          Set count pointer equal to song_index + 1 
 *          Close file and free line
 *          
 *              
*/

Song* read_songs_from_file(const char *filename, int *count) {
    FILE *file = NULL;

    char *line = NULL;
    size_t len = 0;

    int capacity = 10;
    
    Song *songs = malloc(capacity * sizeof(Song));

    int song_index = -1;
    
    file = fopen(filename, "r");

    // syntax: getline(buffer, len buffer var, file pointer) returns -1 when at EOF
    while ( (getline(&line, &len, file)) != -1 ) {

        if ((strstr(line, "+++ BEGIN")) != NULL) {
            song_index++;
            if(song_index >= capacity) {
                capacity *= 2;
                songs = realloc(songs, capacity * sizeof(Song));
            }
            continue;
        }

        if (song_index >= 0) {

            char* value;

            remove_char_from_end(line, '\n');
            remove_char_from_end(line, ',');

            if ( (value = strstr(line, "genre")) != NULL) {
                strcpy(songs[song_index].genre, value + strlen("genre:")); 
            }

            if ( (value = strstr(line, "artist")) != NULL) {
                strcpy(songs[song_index].artist, value + strlen("artist:")); 
            }

            if ( (value = strstr(line, "title")) != NULL) {
                strcpy(songs[song_index].title, value + strlen("title:")); 
            }
        }

    }

    free(line);
    *count = song_index + 1; 
    return songs;
}
```

````c title="songs.h" showLineNumbers
#ifndef SONGS_H
#define SONGS_H

#define MAX_GENRE_LENGTH 30
#define MAX_ARTIST_LENGTH 50
#define MAX_TITLE_LENGTH 100

typedef struct Song {
    char genre[MAX_GENRE_LENGTH];
    char artist[MAX_ARTIST_LENGTH];
    char title[MAX_TITLE_LENGTH];
} Song;

Song* read_songs_from_file(const char *filename, int *count);

#endif
````

````c title="utils.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include "utils.h"

/** CODE: remove_char_from_end(char * str, char char_to_remove)
 *          Removes char_to_remove from the end of a c-string if it exists 
 * */

void remove_char_from_end(char * str, char char_to_remove){

    if (str[strlen(str) - 1] == char_to_remove) {
        str[strlen(str) - 1] = '\0';
    }
    
}
````

````c title="utils.h" showLineNumbers
#ifndef UTILS_H
#define UTILS_H

void remove_char_from_end(char * str, char char_to_remove);

#endif
````

````make title="Makefile" showLineNumbers
# Compiler settings
CC = gcc
BASE_CFLAGS = -Wall -Werror -g
CFLAGS += $(BASE_CFLAGS)

# Object files variable that contains a list of 
# the object files that will be built
# Add necessary objects for all .h files
# add songs.o below delimited by a space
OBJS = main.o songs.o utils.o

# Default target all runs the compilation for main and test
# by default it will create both files
all: main.bin

# Main program target
main.bin: $(OBJS)
	$(CC) $(CFLAGS) -o main.bin $(OBJS)

# Generic rule for building object files
%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

# Dependencies
# format > target: dependency
# example> utils.o: utils.h
main.o: main.c songs.h utils.h
# ADD target and dependency for songs.o, not sure try running gcc -MM songs.c 
songs.o: songs.c songs.h
utils.o: utils.c utils.h

# Clean target
clean:
	rm -f main.bin *.o

# .PHONY will cause the Makefile to the target
# all and then the target clean by default
.PHONY: all clean
````

````
hacker@24-lela-struct-make~lab-2-4-2-6-make-songs:~/cse240/labw/lab24/06$ make Makefile 
make: Nothing to be done for 'Makefile'.
````

````
hacker@24-lela-struct-make~lab-2-4-2-6-make-songs:~/cse240/labw/lab24/06$ /challenge/tester 
Build: ✔ PASS - 0.08s
Copied /home/hacker/cse240/labw/lab24/06/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of f773586679356f93462d8d8ef471d75a
[]
---------------[ System Tests ]---------------
System stest2415.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program read in all the songs. ran in 0.01s
System stest2415.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program prints out first song by Ariana Grande. ran in 0.01s
System stest2415.3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program does not print out All My Rowdy Friends. ran in 0.01s
System stest2415.4: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program does not print out the third song "needy". ran in 0.01s
System stest2415.5: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program does not print out too much data. ran in 0.01s
System stest2426.1: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify main.c includes "songs.h" ran in 0.01s
System stest2426.2: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify main.c does not contain "typdef struct" or "MAX_" ran in 0.01s
System stest2426.3: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify Makefile contains songs.o dependency information. ran in 0.01s
System stest2426.4: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify Makefile contains utils dependency information. ran in 0.01s
System stest2426.5: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify utils.h contains remove_char_from_end declaration. ran in 0.01s

All 10 Tests Passed 
Congrats, here's your flag
pwn.college{oCWurKDiy2Z9knSvFIAHDLuQuDd.QX1YTO3EDL4ITM0EzW}
````

&nbsp;

## Lab 2.4.2.6 - Filter Songs

### Code

````c title="main.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "songs.h"
#include "utils.h"


int main(int argc, char * argv[]) {
    int song_count = 0;
    if (argc < 2){
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    printf("Enter criteria: ");

    char filter_criteria[100];
    fgets(filter_criteria, 100, stdin);

    remove_char_from_end(filter_criteria, '\n');

    Song *songs;
    /** CODE: call read_songs_from_file set result to songs */
    songs = read_songs_from_file(argv[1], &song_count);
    
    printf("Read %d songs from file:\n", song_count);

    /** CODE: print every five songs from the array */
    for (int i = 0; i < song_count; i++) {

        char *genre = string_tolower(songs[i].genre);
        char *artist = string_tolower(songs[i].artist);
        char *title = string_tolower(songs[i].title);

        if (strstr(genre, filter_criteria) == NULL && strstr(artist, filter_criteria) == NULL && strstr(title, filter_criteria) == NULL) {

        }
        else {
            printf("Genre: %s, Artist: %s, Title: %s\n", songs[i].genre, songs[i].artist, songs[i].title);
        }

        free(genre);
        free(artist);
        free(title);
    }

    /** CODE: free songs */
    
    return 0;
}
````

```c title="songs.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "songs.h"
#include "utils.h"

/**  CODE: Song* read_songs_from_file(const char *filename, int *count)  
 *          Open file using provided filename
 *          Allocate initial memory for songs, capacity = 10, don't forget sizeof()  
                Memory Address      | Data (Song Struct)
                --------------------|---------------------------------------------------------
                0x1000              | Song 1
                0x1000 - 0x101D     |   genre (30 bytes)
                0x101E - 0x1049     |   artist (50 bytes)
                0x104A - 0x10D3     |   title (100 bytes)
                --------------------|---------------------------------------------------------
                0x10D4              | Song 2
                0x10D4 - 0x10F1     |   genre (30 bytes)
                0x10F2 - 0x111D     |   artist (50 bytes)
                0x111E - 0x11A7     |   title (100 bytes)
                --------------------|---------------------------------------------------------
                ...
 *          While getline  (using getline, which auto allocates on the heap any size of input)
 *              if +++BEGIN check if song_index is >= capacity, then allocate more space for list, next use memset to set all the strings to 0
 *              Clean up line using remove_char_from_end
 *              If genre: artist: title: in line then 
 *                  Copy the value to the structure using strncpy
 *                  Add null terminator to the end of the field b/c strncpy does not guarantee null termination when value is longer than genre's max size
 *          Set count pointer equal to song_index + 1 
 *          Close file and free line
 *          
 *              
*/

Song* read_songs_from_file(const char *filename, int *count) {
    FILE *file = NULL;

    char *line = NULL;
    size_t len = 0;

    int capacity = 10;
    
    Song *songs = malloc(capacity * sizeof(Song));

    int song_index = -1;
    
    file = fopen(filename, "r");

    // syntax: getline(buffer, len buffer var, file pointer) returns -1 when at EOF
    while ( (getline(&line, &len, file)) != -1 ) {

        if ((strstr(line, "+++ BEGIN")) != NULL) {
            song_index++;
            if(song_index >= capacity) {
                capacity *= 2;
                songs = realloc(songs, capacity * sizeof(Song));
            }
            continue;
        }

        if (song_index >= 0) {

            char* value;

            remove_char_from_end(line, '\n');
            remove_char_from_end(line, ',');

            if ( (value = strstr(line, "genre")) != NULL) {
                strcpy(songs[song_index].genre, value + strlen("genre:")); 
            }

            if ( (value = strstr(line, "artist")) != NULL) {
                strcpy(songs[song_index].artist, value + strlen("artist:")); 
            }

            if ( (value = strstr(line, "title")) != NULL) {
                strcpy(songs[song_index].title, value + strlen("title:")); 
            }
        }

    }

    free(line);
    *count = song_index + 1; 
    return songs;
}
```

````c title="songs.h" showLineNumbers
#ifndef SONGS_H
#define SONGS_H

#define MAX_GENRE_LENGTH 30
#define MAX_ARTIST_LENGTH 50
#define MAX_TITLE_LENGTH 100

typedef struct Song {
    char genre[MAX_GENRE_LENGTH];
    char artist[MAX_ARTIST_LENGTH];
    char title[MAX_TITLE_LENGTH];
} Song;

Song* read_songs_from_file(const char *filename, int *count);

#endif
````

````c title="utils.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "utils.h"

/** CODE: remove_char_from_end(char * str, char char_to_remove)
 *          Removes char_to_remove from the end of a c-string if it exists 
 * */

void remove_char_from_end (char * str, char char_to_remove) {

    if (str[strlen(str) - 1] == char_to_remove) {
        str[strlen(str) - 1] = '\0';
    }   
}

char *string_tolower (const char *str) {
    if (str == NULL) {
        return NULL;
    }

    size_t len = strlen(str);

    char *new_str = malloc((len+1) * sizeof(char));

    for (size_t i = 0; i < len; i++) {
        new_str[i] = tolower(str[i]);
    }

    new_str[len] = '\0';
    return new_str;
}
````

````c title="utils.h" showLineNumbers
#ifndef UTILS_H
#define UTILS_H

void remove_char_from_end(char * str, char char_to_remove);

char *string_tolower (const char *str);

#endif
````

````make title="Makefile" showLineNumbers
# Compiler settings
CC = gcc
BASE_CFLAGS = -Wall -Werror -g
CFLAGS += $(BASE_CFLAGS)

# Object files variable that contains a list of 
# the object files that will be built
# Add necessary objects for all .h files
# add songs.o below delimited by a space
OBJS = main.o songs.o utils.o

# Default target all runs the compilation for main and test
# by default it will create both files
all: main.bin

# Main program target
main.bin: $(OBJS)
	$(CC) $(CFLAGS) -o main.bin $(OBJS)

# Generic rule for building object files
%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

# Dependencies
# format > target: dependency
# example> utils.o: utils.h
main.o: main.c songs.h utils.h
# ADD target and dependency for songs.o, not sure try running gcc -MM songs.c 
songs.o: songs.c songs.h
utils.o: utils.c utils.h

# Clean target
clean:
	rm -f main.bin *.o

# .PHONY will cause the Makefile to the target
# all and then the target clean by default
.PHONY: all clean
````

````
hacker@24-lela-struct-make~lab-2-4-2-6-filter-songs:~/cse240/labw/lab24/07$ make Makefile 
make: Nothing to be done for 'Makefile'.
````

````
hacker@24-lela-struct-make~lab-2-4-2-6-filter-songs:~/cse240/labw/lab24/07$ /challenge/tester 
Build: ✔ PASS - 0.09s
Copied /home/hacker/cse240/labw/lab24/07/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of ecfdc37ad829b3b3d3476bc86561f254
[]
---------------[ System Tests ]---------------
System stest4: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program only prints out songs in the rock genre  ran in 0.01s
System stest1: target_path: /nix/var/nix/profiles/default/bin/cat
✔ PASS  - Verify main.c includes "utils.h" ran in 0.02s
System stest2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program only prints out songs that match the criteria ran in 0.01s
System stest3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program only prints out songs by the artist U2 ran in 0.01s

All 4 Tests Passed 
Congrats, here's your flag
pwn.college{gi7Jehqxaq90H4-Z-OCHL88xwE8.QX2YTO3EDL4ITM0EzW}
````