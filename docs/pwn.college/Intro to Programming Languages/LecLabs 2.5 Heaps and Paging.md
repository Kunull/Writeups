---
custom_edit_url: null
sidebar_position: 8
slug: /pwn-college/intro-to-programming-languages/leclabs-2.5
---

## Code

```c title="main.c" showLineNumbers
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

int main(){
    // CODE: Create a pointer variable named hba
    int *hba;
    
    // CODE: Set its address to a heap-based array that can hold 4 integer values
    hba = malloc(sizeof(int) * 4);

    // behind the scenes the compiler translates hba[0] into *(hba + 0)
    // CODE: set array index 0 to 100
    hba[0] = 100;

    // CODE: set *(hba+1) to 2000
    *(hba+1) = 2000;

    // behind the scenes the compiler translates hba[2] into *(hba + 2)
    // CODE: set hba[2] to 30000
    hba[2] = 30000;
    
    // CODE: set *(&(hba[3])) to 400000
    *(&(hba[3])) = 400000;

    // *(&(hba[3])) == hba[3] == *(hba + 3)
    
    printf("Address of hba: %p\n", &hba);
    printf("Heap address of *hba: %p\n", hba);

    for (int x =0; x < 4; x++){
        printf("%d) %d at %p\n", x+1, hba[x], (void*)&(hba[x]));
    }

    free(hba);

}
```

```
hacker@25-lela-heap~ezlab-2-5-1-6-heap:~/cse240/labw/lab25/01$ gcc main.c -g -o main.bin
```

```
hacker@25-lela-heap~ezlab-2-5-1-6-heap:~/cse240/labw/lab25/01$ /challenge/tester 
Build: ✔ PASS - 0.08s
Copied /home/hacker/cse240/labw/lab25/01/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 56a781444543ac24911c93c33065fed0
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest2: target_path: /usr/bin/valgrind
✔ PASS  - Test if program uses the heap. ran in 0.87s

All 2 Tests Passed 
Congrats, here's your flag
pwn.college{4ntNxyovw56f9FeK3F0RWJORmSX.QXwcTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.5.1.6 - Stack on Heap

### Code

```c title="main.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "stack.h"

int *stack = NULL;
int top_index = -1;
int capacity = 0;

/*
Stack Representation:

Initially:
Capacity = 2
  +---+---+
  |   |   |
  +---+---+
   0   1

After pushing 10:
Capacity = 2
  +----+---+
  | 10 |   |
  +----+---+
   0    1

After pushing 20:
Capacity = 2
  +----+----+
  | 10 | 20 |
  +----+----+
   0    1

After pushing 30 (resize):
Capacity = 4
  +----+----+----+----+
  | 10 | 20 | 30 |    |
  +----+----+----+----+
   0    1    2    3

After popping (30 is removed):
Capacity = 4
  +----+----+----+----+
  | 10 | 20 |    |    |
  +----+----+----+----+
   0    1    2    3
*/

// Function to initialize the stack
void initialize_stack(int initialCapacity) {
    /** CODE: initialize memory for stack onto the HEAP 
     *        set the capacity to initalCapacity  
     */
    capacity = initialCapacity;
    stack = malloc(initialCapacity * sizeof(int));
}

// Function to resize the stack
void resize_stack() {
    /** CODE: increase size of heap based array by doubling it
     */
    capacity *= 2;
    stack = realloc(stack, capacity * sizeof(int));
}

// Function to push an element onto the stack
void push(int value) {
    /** CODE: if the top is equal to capacity -1 then resizeStack 
     *        increase top
     *        add value to stack
    */
    if (top_index == (capacity - 1)) {
        resize_stack();
    }
    top_index++;
    stack[top_index] = value;
}

// Function to pop an element from the stack
int pop() {
    /** CODE: check if any values are on stack, if not, return -1 
     *        else, return the current top item and decrement the top_index */
    if (top_index == -1) {
        return -1;
    }

    int tbd_temp = stack[top_index];
    top_index--;
    return tbd_temp;
}

// Function to peek at the top element of the stack
int top() {
    /** CODE: check if any values are on stack, if not, return -1 
     *        else, return the current top item  */
    if (top_index == -1) {
        return -1;
    }
    
    return stack[top_index];
}

// Function to check if the stack is empty
int isEmpty() {
    /** CODE: return true if no items are left on the stack else return false
     *        This can be done with returning a single conditional statement */
    return top_index == -1;
}

// Function to free the stack
void freeStack() {
    free(stack);
}
```

### Tests
#### System tests

```
{
    "args": [ ],
    "input": [""],
    "output": ["30","20","10"],
    "unexpectedOutput": [],
    "target": "main.bin",
    "name": "Test that the program only prints out the first page",
    "description": "This test verifies the program displays the first page (i.e., the first 10 songs) by looking for the first and 10th."
}
```

```
hacker@25-lela-heap~lab-2-5-1-6-stack-on-heap:~/cse240/labw/lab25/02$ make Makefile 
make: Nothing to be done for 'Makefile'.
```

```
hacker@25-lela-heap~lab-2-5-1-6-stack-on-heap:~/cse240/labw/lab25/02$ /challenge/tester 
Build: ✔ PASS - 0.10s
Copied /home/hacker/cse240/labw/lab25/02/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 167adb90318afa063234c4bf123f6240
[]
---------------[ System Tests ]---------------
System stest25.16.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program only prints out the first page ran in 0.01s

All 1 Tests Passed 
Congrats, here's your flag
pwn.college{g5NgvmDWLXdUmx6AVzBS-0LbcEB.QXxcTO3EDL4ITM0EzW}
```

&nbsp;

## EzLab 2.5.2.4 Heap Based Array

### Code

```c title="main.c" showLineNumbers
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

struct Item {
    char * name;
    int * value;
};

int main(){
    struct Item * item_list;
    // CODE: assign a heap-based array with 2 spots in it to item_list
    //       it should use the sizeof the struct to ensure enough space is reserved
    item_list = malloc(sizeof(struct Item) * 2);
    
    // CODE: assign "Chair" and 25 to item_list[0]
    //       the code will need to allocate space for both name and value
    //       if you need to dereference the value, the code needs to do it like this *(item_list[0].val)
    //       also see print statement below 
    item_list[0].name = strdup("Chair");
    item_list[0].value = malloc(sizeof(int));
    *item_list[0].value = 25;
    
    printf("Name: %s %d\n", item_list[0].name, *(item_list[0].value));

    // CODE: assign "Baseball Cap" and 10 to item_list[1]
    item_list[1].name  = strdup("Baseball Cap");
    item_list[1].value = malloc(sizeof(int));
    *item_list[1].value = 10;   
    
    printf("Name: %s %d\n", item_list[1].name, *(item_list[1].value));

    free(item_list[0].name);
    free(item_list[0].value);
    free(item_list[1].name);
    free(item_list[1].value);
    free(item_list);    
    
    return 0;
}
```

### Tests
#### System tests

```json title="1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["Name: Chair 25","Name: Baseball Cap 10"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the array's values."
}
```

```json title="2.json" showLineNumbers
{
    "args": ["./main.bin"],
    "input": [""],
    "output": ["total heap usage: [1-9]+[0-9]* allocs, [1-9]+[0-9]* frees, [1-9]+[0-9,]+ bytes allocate","All heap blocks were freed"],
    "target": "valgrind",
    "type": "valgrind",
    "output_type": "regex",
    "name": "Test if program uses the heap.",
    "description": "This test verifies the program uses the heap by investigating with valgrind."
}
```

```
hacker@25-lela-heap~ezlab-2-5-2-4-heap-based-array:~/cse240/labw/lab25/03$ gcc main.c -g -o main.bin
```

```
hacker@25-lela-heap~ezlab-2-5-2-4-heap-based-array:~/cse240/labw/lab25/03$ /challenge/tester 
Build: ✔ PASS - 0.07s
Copied /home/hacker/cse240/labw/lab25/03/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 22d9cfc5e47183001b9d9bd8d6537917
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest2: target_path: /usr/bin/valgrind
✔ PASS  - Test if program uses the heap. ran in 0.90s

All 2 Tests Passed 
Congrats, here's your flag
pwn.college{kvicJJPG_LpRqap-L2HE-eaSAPD.QXzcTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.5.2.4 - Paging Songs

### Code

```c title="main.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "songs.h"
#include "utils.h"
#include "stack.h"


int main(int argc, char * argv[]) {
    int song_count = 0;
    if (argc < 2){
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    char filter_criteria[100];

    Song *songs;
    /** CODE: call read_songs_from_file set result to songs */
    songs = read_songs_from_file(argv[1], &song_count);
    
    printf("Read %d songs from file:\n", song_count);

    char ch = 's';
    int start_index = 0;
    int next_starting_index = 0;

    while (ch != 'q') {

        int num_displayed = 0;
        int i = 0;

        /** CODE: print every five songs from the array */
        for (i = start_index; i < song_count && num_displayed < 10; i++) {

            char *genre = string_tolower(songs[i].genre);
            char *artist = string_tolower(songs[i].artist);
            char *title = string_tolower(songs[i].title);

            if (strstr(genre, filter_criteria) == NULL && strstr(artist, filter_criteria) == NULL && strstr(title, filter_criteria) == NULL) {

            }
            else {
                printf("Genre: %s, Artist: %s, Title: %s\n", songs[i].genre, songs[i].artist, songs[i].title);
                num_displayed++;
            }

            free(genre);
            free(artist);
            free(title);
        }

        next_starting_index = i;
        printf("(n for next, p for previous, f for filter, q for quit)");
        ch = getchar();
        getchar();

        if (ch == 'n') {
            if (next_starting_index < song_count) {
                push(start_index);
                start_index += 10;
            }
        }
        if (ch == 'p') {
            start_index = pop();
            if (start_index < 0) {
                start_index = 0;
            }
        }
        if (ch == 'f') {
            printf("Enter criteria: ");
            fgets(filter_criteria, 100, stdin);
            remove_char_from_end(filter_criteria, '\n');
            start_index = 0;
        }
    }
    /** CODE: free songs */
    
    return 0;
}
```

````c title="songs.c" showLineNumbers
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
````

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

````c title="stack.c" showLineNumbers
#include <stdio.h>
#include <stdlib.h>
#include "stack.h"

int *stack = NULL;
int top_index = -1;
int capacity = 0;

/*
Stack Representation:

Initially:
Capacity = 2
  +---+---+
  |   |   |
  +---+---+
   0   1

After pushing 10:
Capacity = 2
  +----+---+
  | 10 |   |
  +----+---+
   0    1

After pushing 20:
Capacity = 2
  +----+----+
  | 10 | 20 |
  +----+----+
   0    1

After pushing 30 (resize):
Capacity = 4
  +----+----+----+----+
  | 10 | 20 | 30 |    |
  +----+----+----+----+
   0    1    2    3

After popping (30 is removed):
Capacity = 4
  +----+----+----+----+
  | 10 | 20 |    |    |
  +----+----+----+----+
   0    1    2    3
*/

// Function to initialize the stack
void initialize_stack(int initialCapacity) {
    stack = (int *)malloc(initialCapacity * sizeof(int));
    capacity = initialCapacity;
}

// Function to resize the stack
void resize_stack() {
    capacity *= 2;
    stack = (int *)realloc(stack, capacity * sizeof(int));
    // printf("Stack resized to capacity: %d\n", capacity);
}

// Function to push an element onto the stack
void push(int value) {
    if (top_index == capacity - 1) {
        resize_stack();
    }
    stack[++top_index] = value;
}

// Function to pop an element from the stack
int pop() {
    if (top_index == -1) {
        return -1;
    }
    return stack[top_index--];
}

// Function to peek at the top element of the stack
int top() {
    if (top_index == -1) {
        return -1;
    }
    return stack[top_index];
}

// Function to check if the stack is empty
int isEmpty() {
    return top_index == -1;
}

// Function to free the stack
void freeStack() {
    free(stack);
}
````

````c title="stack.h" showLineNumbers
#ifndef STACK_H
#define STACK_H

// Function declarations
void initialize_stack(int initialCapacity);
void resize_stack();
void push(int value);
int pop();
int top();
int isEmpty();
void freeStack();

#endif // STACK_H
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

### Tests
#### System tests

Too many.

````
hacker@25-lela-heap~lab-2-5-2-4-paging-songs:~/cse240/labw/lab25/04$ make
make: Nothing to be done for 'all'.
````

````
hacker@25-lela-heap~lab-2-5-2-4-paging-songs:~/cse240/labw/lab25/04$ /challenge/tester 
Build: ✔ PASS - 0.14s
Copied /home/hacker/cse240/labw/lab25/04/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of c162ee6e23fea319a47d62a710a04367
[]
---------------[ System Tests ]---------------
System stest25.24.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program only prints out the first page ran in 0.01s
System stest25.24.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program only prints out songs by the artist U2 ran in 0.02s
System stest25.24.3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program can navigate to next ran in 0.02s
System stest25.24.4: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test that the program can use next and forward when list is filtered ran in 0.01s

All 4 Tests Passed 
Congrats, here's your flag
pwn.college{8ZI9RqJqUtMxA7HQV_qdctD33b4.QXycTO3EDL4ITM0EzW}
````