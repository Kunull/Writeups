---
sidebar_position: 1
custom_edit_url: null
---

>  In Python, the `chr()` function can be used to convert an ASCII ordinal number to a character (the `ord()` function does the opposite).
- ASCII characters can be represented as decimal numbers as shown in this table.

## Solution
```python
def ascii(list):  
    flag = ""  
    for i in list:  
        asciiChar = chr(i)  
        flag += asciiChar  
    print(f"{flag}")  
  
if __name__ == '__main__':  
    list = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]  
    ascii(list)
```


```python
list = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125] 
flag = ""  
for i in list:  
    asciiChar = chr(i)  
    flag += asciiChar  
print(f"{flag}")  
```
