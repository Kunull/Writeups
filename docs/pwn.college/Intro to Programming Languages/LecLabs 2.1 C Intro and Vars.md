---
custom_edit_url: null
sidebar_position: 1
slug: /pwn-college/intro-to-programming-languages/leclabs-2.1
---

## Lab - 2.1.2.1 - C Input

### Code

```c title="main.c" showLinenNumbers
#include <stdio.h>

/** CODE: add main function with int argc and char * argv[] for the parameters */
int main(int argc, char* argv[]) {

    /** CODE: print the name of the binary (argument 0 is the name of the program) */
    printf("%s\n", argv[0]);

    /** CODE: if argc > 1 then print argument 1 else print "no user arguments received" */
    if (argc > 1){
        printf("%s\n", argv[1]);
    }
    else {
        printf("no user arguments received\n");
    }

    printf("Enter a number: ");    
    
    /** CODE: do scanf */
    int num = 0;
    scanf("%d", &num);

    /** CODE: print the value received followed by a newline */
    printf("%d\n", num);

    getchar();

    printf("Enter a character: ");    

    /** CODE: use getchar to get the character and put it into a variable  */
    char ch = getchar();

    /** CODE: print the character entered and a newline */
    printf("%c\n", ch);

    /** CODE: if character = 't' then print "that's great!!!!\n"             */
    if (ch == 't') {
        printf("that's great!!!!\n");
    }

    // CODE return 0
    return 0;

/** CODE: end of main. */
}
```

### Tests
#### System tests

```json title="user_tests/stest21.21.1.json" showLineNumbers
{
    "args": ["hihi"],
    "input": ["99","a"],
    "output": ["main.bin", "hihi","99","a"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints out the argument 0, argument 1, standard input number, and standard input character."

}
```

```json title="user_tests/stest21.21.2.json" showLineNumbers
{
    "args": ["toyoda"],
    "input": ["44","t"],
    "output": ["main.bin", "44","t","that's great"],
    "target": "main.bin",
    "name": "Test printing of arguments and input values and test for if 't' .",
    "description": "This test verifies the student's program prints the argument 0, argument 1, standard input, and that's great when character input is 't'"

}
```

```json title="user_tests/stest21.21.3.json" showLineNumbers
{
    "args": [],
    "input": ["44","t"],
    "output": ["main.bin", "no user arguments"],
    "target": "main.bin",
    "name": "Test when no user argments are provided.",
    "description": "This test verifies that the program prints \"no user arguments\" when argument 1 is not provided. "

}
```

#### User tests

```json title="user_tests/utest21.21.1.json" showLineNumbers
{
    "args": ["firstargument"],
    "input": ["2", "a"],
    "output": ["firstargument"],
    "nameOfModelGoodTest": "Test for <testfilename> to Pass after first argument is supplied and printed out",
    "descriptionOfModelGoodTest": "A properly working test case should pass when executing modelGood. ",
    "nameOfModelBadTest": "Test for ./modelBad21.21.1 to fail because it will not print argument 1 ",
    "descriptionOfModelBadTest": "A properly working test case should fail when executing a modelBad designed to fail the test case. So, passing the test means that the result above should not be found."
}
```

```json title="user_tests/utest21.21.2.json" showLineNumbers
{
    "input": ["2", "t"],
    "output": ["2", "t", "that's great"],
    "nameOfModelGoodTest": "Test for <testfilename> to Pass after character 't' is input",
    "descriptionOfModelGoodTest": "A properly working test case should pass when executing modelGood. ",
    "nameOfModelBadTest": "Test for ./modelBad21.21.2 to fail after inputing 't' because it will output the wrong message",
    "descriptionOfModelBadTest": "A properly working test case should fail when executing a modelBad designed to fail the test case. So, passing the test means that the result above should not be found."
}
```

```
hacker@21-lela-c-intro-vars~lab-2-1-2-1-c-input:~/cse240/labw/lab21/01$ gcc main.c -g -o main.bin
```

```
hacker@21-lela-c-intro-vars~lab-2-1-2-1-c-input:~/cse240/labw/lab21/01$ /challenge/tester 
Build: ✔ PASS - 0.06s
Copied /home/hacker/cse240/labw/lab21/01/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of ed032a83567b6f3bfbd4a3db9e2c469c
['/home/hacker/cse240/labw/lab21/01/user_tests/utest21.21.1.json', '/home/hacker/cse240/labw/lab21/01/user_tests/utest21.21.2.json']
---------------[  User Tests  ]---------------
User utest21.21.1: target_path: /challenge/modelBad21.21.1.bin
✔ PASS  - Test for ./modelBad21.21.1 to fail because it will not print argument 1  ran in 0.01s
User utest21.21.1: target_path: /challenge/modelGood.bin
✔ PASS  - Test for modelGood.bin to Pass after first argument is supplied and printed out ran in 0.01s
User utest21.21.1: target_path: /home/hacker/cse240/labw/lab21/01/main.bin
✔ PASS  - Test for main.bin to Pass after first argument is supplied and printed out ran in 0.01s
User utest21.21.2: target_path: /challenge/modelBad21.21.2.bin
✔ PASS  - Test for ./modelBad21.21.2 to fail after inputing 't' because it will output the wrong message ran in 0.01s
User utest21.21.2: target_path: /challenge/modelGood.bin
✔ PASS  - Test for modelGood.bin to Pass after character 't' is input ran in 0.01s
User utest21.21.2: target_path: /home/hacker/cse240/labw/lab21/01/main.bin
✔ PASS  - Test for main.bin to Pass after character 't' is input ran in 0.01s

---------------[ System Tests ]---------------
System stest21.21.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest21.21.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test printing of arguments and input values and test for if 't' . ran in 0.01s
System stest21.21.3: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test when no user argments are provided. ran in 0.01s

All 9 Tests Passed 
Congrats, here's your flag
pwn.college{kFHnDqJeJYcpaTKtxGS7itCBv5R.QXxQTO3EDL4ITM0EzW}
```

&nbsp;

## EzLab 2.1.2.3 - Control Flow

### Code

```c title="main.c" showLineNumbers
#include <stdio.h>
int main(){
    int number = 0;
    scanf("%d", &number);
    // CODE: replace XXXXX with number
    for (int x=0; x < number; x++){
        // CODE: Insert print statement here
        printf("I can do it!\n");
    }
}
```

### Tests
#### System tests

```json title="system_tests/stest1.json"
{
    "args": [""],
    "input": ["5"],
    "output": ["I can do it!","I can do it!","I can do it!","I can do it!","I can do it!"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints \"I can do it!\" five times when the input is 5."

}
```

```json title="system_tests/stest2.json"
{
    "args": [""],
    "input": ["100"],
    "output": 
            [
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!",
                "I can do it!","I can do it!","I can do it!","I can do it!","I can do it!"
            ],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints \"I can do it!\" five times when the input is 5."

}
```

```
hacker@21-lela-c-intro-vars~ezlab-2-1-2-3-control-flow:~/cse240/labw/lab21/02$ gcc main.c -g -o main.bin
```

```
hacker@21-lela-c-intro-vars~ezlab-2-1-2-3-control-flow:~/cse240/labw/lab21/02$ /challenge/tester 
Build: ✔ PASS - 0.10s
Copied /home/hacker/cse240/labw/lab21/02/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 1c94a986523f348c39ff37b5925a31e0
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s
System stest2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 2 Tests Passed 
Congrats, here's your flag
pwn.college{8RKhV4RIHJ0n8AtlL_EUKKkXbFv.QXyQTO3EDL4ITM0EzW}
```

&nbsp;

## EzLab 2.1.3.2 - Pass by Value

### Code

```c title="main.c" showLineNumbers
#include<stdio.h>

int add1(int a, int b){
    int result = a +b;
    printf("add1: %d + %d = %d\n", a, b, result);
    return result;     
}

void add2(int a, int b, int result){
    result = a + b;
    printf("add2: %d + %d = %d\n", a, b, result);
}

int main(){
    int a = 5, b=10, result = 0;
    // CODE call function using a, b to achieve proper result 
    add2(a, b, result);
    printf("Result is 0 == %d\n", result);

    // CODE: call function using a, b to achieve result below 
    result = add1(a, b);
    printf("Result is 15 == %d\n", result);
}
```

### Tests
#### System tests

```json title="system_tests/stest1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": ["add2: 5 + 10 = 15","Result is 0 == 0","add1: 5 + 10 = 15","Result is 15 == 15"],
    "target": "main.bin",
    "name": "Test if program is printing out expected output.",
    "description": "This test verifies the program prints the designed and expected output."

}
```

```
hacker@21-lela-c-intro-vars~ezlab-2-1-3-2-pass-by-value:~/cse240/labw/lab21/03$ gcc main.c -g -o main.bin
```

```
hacker@21-lela-c-intro-vars~ezlab-2-1-3-2-pass-by-value:~/cse240/labw/lab21/03$ /challenge/tester 
Build: ✔ PASS - 0.06s
Copied /home/hacker/cse240/labw/lab21/03/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 9bd740551285a5787b0c6eccb5fb65be
[]
---------------[ System Tests ]---------------
System stest1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test if program is printing out expected output. ran in 0.01s

All 1 Tests Passed 
Congrats, here's your flag
pwn.college{sz51LGdFEtB-RF9Pc20gQCNfuL3.QXzQTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.1.3.1 - Functions

### Code

```c title="main.c" showLineNumbers
#include <stdio.h>

/** CODE: global variable: delivery_speed is 50 */
int delivery_speed = 50;

/** CODE: prototypes for for  */
//      display_order takes customer_number and distance
void display_order(int customer_number, int distance);
//      calculate_delivery_time takes distance and speed
double calculate_delivery_time(int distance, int speed);
//      deliver_pizza takes customer_number, distance, and speed
void deliver_pizza(int customer_number, int distance, int speed);

/** CODE: main function  */
//      define local variables
//          customer1_id is 1 and customer1_distance is 50
//          customer2_id is 2 and customer2_distandce is 25
//      call display order and deliver pizza for each customer 
//      return 0
int main (int argc, char* argv[]) {
    int customer1_id = 1;
    int customer1_distance = 50;
    int customer2_id = 2;
    int customer2_distance = 25;

    display_order(customer1_id, customer1_distance);
    deliver_pizza(customer1_id, customer1_distance, delivery_speed);

    display_order(customer2_id, customer2_distance);
    deliver_pizza(customer2_id, customer2_distance, delivery_speed);

    return 0;
}

/** CODE: function definitions for display_order */
//          Print "Customer number: <FORMATTER> \n"
//          Print "Distance to customer is <FORMATTER> light years.\n"
void display_order(int customer_number, int distance) {
    printf("Customer Number: %d \n", customer_number);
    printf("Distance to customer is %d light years.\n", distance);
}

/** CODE: function definitions for calculate_delivery_time */
//          Calculate the delivery time
//          Cast the result of the calculation to a double by placing (double) before the calcuation.
//          Return the result of the calculation
double calculate_delivery_time(int distance, int speed) {
    // int delivery_time = 0;
    double delivery_time = (double) distance / speed;
    return delivery_time;
}

/** CODE: function definitions for deliver_pizza */
//          Calculate the delivery time using the calculate_delivery_time function
//          Print "Customer <FORMMATTER>'s pizza will arrive in <FORMATTER> hours!\n."
//          Use the appropriate formatter for delivery time and make sure only 2 decimal points are shown, it should look like 0.50 or 1.00.
void deliver_pizza(int customer_number, int distance, int speed) {
    float delivery_time = calculate_delivery_time(distance, speed);
    printf("Customer %d's pizza will arrive in %2.2f hours!\n", customer_number, delivery_time);
}
```

### Tests
#### System tests

```json title="system_tests/stest21.31.1.json" showLineNumbers
{
    "args": [],
    "input": [],
    "output": ["Customer Number: 1", "Distance to customer is 50 light years", "Customer 1's pizza will arrive in 1.00 hours!"],
    "target": "main.bin",
    "name": "Test Customer 1's output",
    "description": "This test verifies the program prints out Customer 1's results."

}
```

```json title="system_tests/stest21.31.2.json" showLineNumbers
{
    "args": [],
    "input": [],
    "output": ["Customer Number: 2", "Distance to customer is 25 light years", "Customer 2's pizza will arrive in 0.50 hours!"],
    "target": "main.bin",
    "name": "Test Customer 2's output",
    "description": "This test verifies the program prints out Customer 2's results."

}
```

#### User tests

```json title="user_tests/utest21.31.1.json" showLineNumbers
{
    "args": [""],
    "input": [""],
    "output": [
        "Customer Number: 1",
        "Distance to customer is 50 light years",
        "Customer 1's pizza will arrive in 1.00 hours!"
    ],
    "nameOfModelGoodTest": "Test for <testfilename> to Pass after the first customer's order information is displayed.",
    "descriptionOfModelGoodTest": "A properly working test case should pass when executing modelGood. ",
    "nameOfModelBadTest": "Test for ./modelBad21.31.1 to fail because it will not print the first customers information. ",
    "descriptionOfModelBadTest": "A properly working test case should fail when executing a modelBad because this version of the modelBad is designed to fail this test case. So, passing the test means that given the inputs the expected output will not match the actual output."
}
```

```
hacker@21-lela-c-intro-vars~lab-2-1-3-1-functions:~/cse240/labw/lab21/04$ gcc main.c -g -o main.bin
```

```
hacker@21-lela-c-intro-vars~lab-2-1-3-1-functions:~/cse240/labw/lab21/04$ /challenge/tester 
Build: ✔ PASS - 0.06s
Copied /home/hacker/cse240/labw/lab21/04/main.bin to /challenge/system_tests/main.bin for system testing, with an md5 of 8ab913ebb24470c0a46732e3e17e602d
['/home/hacker/cse240/labw/lab21/04/user_tests/utest21.31.1.json']
---------------[  User Tests  ]---------------
User utest21.31.1: target_path: /challenge/modelBad21.31.1.bin
✔ PASS  - Test for ./modelBad21.31.1 to fail because it will not print the first customers information.  ran in 0.01s
User utest21.31.1: target_path: /challenge/modelGood.bin
✔ PASS  - Test for modelGood.bin to Pass after the first customer's order information is displayed. ran in 0.01s
User utest21.31.1: target_path: /home/hacker/cse240/labw/lab21/04/main.bin
✔ PASS  - Test for main.bin to Pass after the first customer's order information is displayed. ran in 0.01s

---------------[ System Tests ]---------------
System stest21.31.1: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test Customer 1's output ran in 0.01s
System stest21.31.2: target_path: /challenge/system_tests/main.bin
✔ PASS  - Test Customer 2's output ran in 0.01s

All 5 Tests Passed 
Congrats, here's your flag
pwn.college{gQrl22NVj-NbIq5ZIy0b3woEYSl.QX0QTO3EDL4ITM0EzW}
```

&nbsp;

## Lab 2.1.5.1 - Using VSCode Debugger

### Code

```c title="main.c" showLineNumbers
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char mangle(char val, int round)
{
    return (val ^ (0x33+round)) % 0xff;
}

int main()
{
    char plain_value = '0';
    char new_value = plain_value;
    for (int x =0; x < 5; x++){

        new_value = mangle(new_value,x); 
        
        printf("%d\n", x); // 1. put breakpoint here, continue until x is 2
                           // 2. Write down the hex value of new_value (x is 2)
                           // 3. Step through again until reaching the print statement again, x should now be 3
                           // 4. Write down the hex value of new_value (x is 3)
                           // 5. Change the value of new_value to 'b' which is 0x62
                           // 6. Remove the breakpoint 
                           // 7. Click on Continue to finish the running of the program
                           // 8. Write down the "Final value" that's printed at the end of execution
                           // 9. Run the program getflag, enter in the value from steps 2 and 4 and the final value only enter the 0xXX part.
    }

    printf("Final value: 0x%02x\n", new_value);
    
    printf("\n");
    
}
```

```
2 = 0x2
52 = 0x34
Set new_value to `b`
Final value: 0x55
```

```
hacker@21-lela-c-intro-vars~lab-2-1-5-1-using-vscode-debugger:~/cse240/labw/lab21/05$ getflag 
Enter value when x = 2 (format 0xXX): 0x2
Enter value when x = 3  (format 0xXX): 0x34
Enter printed out at the end after modifying new_value to equal 'b'  (format 0xXX): 0x55
firstval=0x3
firstval=0x37
firstval=0x2
secondval=0x34
First value matches
Second value matches
85
pwn.college{0w74Jy5DZNGXLK0GOYjgQtyscR3.QX1QTO3EDL4ITM0EzW}
```