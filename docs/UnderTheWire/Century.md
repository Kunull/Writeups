---
custom_edit_url: null
sidebar_position: 1
---


## Century 0 -> 1

> The goal of this level is to log into the game. Do the following in order to achieve this goal.
>
> 1. Obtain the initial credentials via the #StartHere channel on our Slack (_[_link_](https://join.slack.com/t/underthewire/shared\_invite/zt-11xkgkxj5-VmAGL\_ofeIAQ2hNXuu\_irg)_). Once you are in the channel, scroll to the top to see the credentials.
>
> 2. After obtaining the credentials, connect to the server via SSH. You will need an SSH client such as Putty. The host that you will be connecting to is century.underthewire.tech, on port 22.
>
> 3. When prompted, use the credentials for the applicable game found in the #StartHere Slack channel.
>
> 4. You have successfully connected to the game server when your path changes to “PS C:\Users\Century1\desktop>”.

We can achieve this using ssh connection as follows:

```powershell
ssh century1@century.underthewire.tech -p 22
```

### Password for Century 1
```
century1
```

&nbsp;

## Century 1 -> 2

> The password for Century2 is the build version of the instance of PowerShell installed on this system.

We can obtain the build version using **$psVersionTable**_**:**_

```powershell
C:\users\century1\desktop> $PSVersionTable                                                                                                           Name                           Value
----                           -----
PSVersion                      5.1.14393.5127
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.14393.5127
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1         
```

_\[$psVersionTable is **an automatic variable (whose type is System.**_ _**Collections.) that reveals some information about the PowerShell that runs the current session**.]_

### Password for Century 2
```
10.0.14393.5127
```

&nbsp;

## Century 2 -> 3

> The password for Century3 is the name of the built-in cmdlet that performs the wget like function within PowerShell PLUS the name of the file on the desktop.

We could conduct a simple google search for the answer. But since the goal is to use the PowerShell we could use the **Get-Alias** cmdlet:

```powershell
PS C:\users\century1\desktop> Get-Alias wget   

CommandType     Name                                               Version
-----------     ----                                               -------
Alias           wget -> Invoke-WebRequest 
```

_\[The Get-Alias cmdlet **gets the aliases in the current session**. This includes built-in aliases, aliases that you have set or imported, and aliases that you have added to your PowerShell profile. By default, Get-Alias takes an alias and returns the command name.]_

2\. We can use the **Get-ChildItem** cmdlet to get the name of the file:

```powershell
PS C:\users\century2\desktop> Get-ChildItem 

  
    Directory: C:\users\century2\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:29 AM            693 443    
```

_\[The Get-ChildItem cmdlet **gets the items in one or more specified locations**. If the item is a container, it gets the items inside the container, known as child items. You can use the Recurse parameter to get items in all child containers and use the Depth parameter to limit the number of levels to recurse.]_

### Password for Century 3
```
Invoke-WebRequest443
```

&nbsp;

## Century 3 -> 4

> The password for Century4 is the number of files on the desktop.

We can obtain the number of files by piping the **Measure-Object** cmlet with the **Get-ChildItem** cmdlet:

```powershell
PS C:\users\century3\desktop> (Get-ChildItem -File | Measure-Object).Count

123
```

_\[The Measure-Object cmdlet **performs calculations on the property values of objects**. You can use Measure-Object to count objects or count objects with a specified Property. You can also use Measure-Object to calculate the Minimum, Maximum, Sum, Standard Deviation and Average of numeric values.]_

### Password for Century 4
```
123
```

&nbsp;

## Century 4 -> 5

> The password for Century5 is the name of the file within a directory on the desktop that has spaces in its name.

We can filter the **Get-ChildItem** cmdlet to get only the directories with spaces in their name as follows:

```powershell
PS C:\users\century4\desktop> Get-ChildItem -Directory -Filter "* *"

  
    Directory: C:\users\century4\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/23/2022  10:30 PM                Can You Open Me
```

We can move into the directory and again use **Get-ChildItem**:

```powershell
PS C:\users\century4\desktop> cd "Can You Open Me"
PS C:\users\century4\desktop\Can You Open Me> Get-ChildItem

  
    Directory: C:\users\century4\desktop\Can You Open Me 

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/23/2022  10:24 PM             24 49125 
```

### Password for Century 5
```
495125
```

&nbsp;

## Century 5 -> 6

> The password for Century6 is the short name of the domain in which this system resides in PLUS the name of the file on the desktop.

We can get the required domain name using Get-WmiObject cmdlet:

```powershell
PS C:\users\century5\desktop> Get-WmiObject Win32_ComputerSystem

Domain              : underthewire.tech
Manufacturer        : OpenStack Foundation
Model               : OpenStack Nova
Name                : UTW
PrimaryOwnerName    : UTW_Team
TotalPhysicalMemory : 12582359040  
```

_\[The Get-WmiObject cmdlet **gets instances of WMI classes or information about the available WMI classes**. To specify a remote computer, use the ComputerName parameter. If the List parameter is specified, the cmdlet gets information about the WMI classes that are available in a specified namespace.]_

For the filename we will use the Get-ChildItem cmdlet:

```powershell
PS C:\users\century5\desktop> Get-ChildItem

  
    Directory: C:\users\century5\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:29 AM             54 3347
```

### Password for Century 6
```
underthewire3347
```

&nbsp;

## Century 6 -> 7

> The password for Century7 is the number of folders on the desktop.

We can add the -Directory filter to the Get-ChildItem in order to get only directories as the result.

Then we can pipe the result with the Measure-Object cmdlet.

We then wrap the entire result with the Count operator

```powershell
PS C:\users\century6\desktop> (Get-ChildItem -Directory | Measure-Object).Count

197
```

### Password for Century 7
```
197
```

&nbsp;

## Century 7 -> 8

> The password for Century8 is in a readme file somewhere within the contacts, desktop, documents, downloads, favorites, music, or videos folder in the user’s profile.

We can search recursively for the file and set a filter to get any file which has readme in its starting part.

```powershell
PS C:\users\century7\desktop> Get-ChildItem ..\ -Recurse -File -Filter readme* | get-content

7points
```

### Password for Century 8
```
7points
```

&nbsp;

## Century 8 -> 9

> The password for Century9 is the number of unique entries within the file on the desktop.

We can use the **Get-Content** cmdlet to display the file content and the pipe it in the following manner to get desired result:

```powershell
PS C:\users\century8\desktop> (Get-Content .\Unique.txt | Sort-Object | Get-Unique | Measure-Object).Count

696
```

_\[The Get-Content cmdlet **gets the content of the item at the location specified by the path, such as the text in a file or the content of a function**. For files, the content is read one line at a time and returns a collection of objects, each of which represents a line of content.]_

### Password for Century 9
```
696
```

&nbsp;

## Century 9 -> 10

> The password for Century10 is the 161st word within the file on the desktop.

We can use the **Get-Content** cmdlet to get the result:

```powershell
PS C:\users\century8\desktop> (Get-Content Word_File.txt)[161]

pierid
```

### Password for Century 10
```
pierid
```

&nbsp;

## Century 10 -> 11

> The password for Century11 is the 10th and 8th word of the Windows Update service description combined PLUS the name of the file on the desktop.

We can pipe the **Get-WmiObject** and **Select-Object** as follows:

```powershell
PS C:\users\century10\desktop> Get-WmiObject win32_Service -Filter “DisplayName = ‘Windows Update’” | Select-Object Description | ft -Wrap

Description
-----------
Enables the detection, download, and installation of updates for Windows and other programs. If this service is disabled, users of this computer will not be able to use Windows Update or its automatic updating feature, and programs will not be able to use the Windows Update Agent (WUA) API.    
```

_**\[The Select-Object cmdlet** selects specified properties of an object or set of objects. It can also select unique objects, a specified number of objects, or objects in a specified position in an array. To select objects from a collection, use the First, Last, Unique, Skip, and Index parameters.]_

```powershell
PS C:\users\century5\desktop> Get-ChildItem

  
    Directory: C:\users\century10\desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:34 AM             43 110
```

### Password for Century 11
```
windowsupdates110
```

&nbsp;

## Century 11 -> 12

> The password for Century12 is the name of the hidden file within the contacts, desktop, documents, downloads, favorites, music, or videos folder in the user’s profile.

```powershell
PS C:\Users\century11> Get-ChildItem | Get-ChildItem -Recurse -File -Hidden | Where-Object {$_.Name -ne 'desktop.ini'}


    Directory: C:\Users\century11\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a-h--         6/8/2017   4:59 PM              0 secret_sauce
```

### Password for Century 12
```
secret\_sauce
```

&nbsp;

## Century 12 -> 13

> The password for Century13 is the description of the computer designated as a Domain Controller within this domain PLUS the name of the file on the desktop.

```powershell
PS C:\users\century12\desktop> Get-ADComputer UTW -Properties Description


Description       : i_authenticate
DistinguishedName : CN=UTW,OU=Domain Controllers,DC=underthewire,DC=tech
DNSHostName       : utw.underthewire.tech
Enabled           : True
Name              : UTW
ObjectClass       : computer
ObjectGUID        : 5ca56844-bb73-4234-ac85-eed2d0d01a2e
SamAccountName    : UTW$
SID               : S-1-5-21-758131494-606461608-3556270690-1000
UserPrincipalName :
```

_\[The Get-ADComputer cmdlet gets a computer or performs a search to retrieve multiple computers.]_

```powershell
PS C:\users\century12\desktop> Get-ChildItem

    
    Directory: C:\users\century12\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:34 AM             30 i\_authenticate\_things
```

### Password for Century 13
```
i\_authenticate\_things
```

&nbsp;

## Century 13 -> 14

> The password for Century14 is the number of words within the file on the desktop.

```powershell
PS C:\users\century13\desktop> (Get-ChildItem | get-content | Measure-Object -Word).Words
755
```

### Password for Century 14
```
755
```

&nbsp;

## Century 14 -> 15

> The password for Century15 is the number of times the word “polo” appears within the file on the desktop.

We can obtain the required string using the **Select-String** cmdlet and then we can pipe it with **Measure-Object**

```powershell
PS C:\Users\century14\Desktop> (Get-Content stuff.txt | Select-String -Pattern "polo" | Measure-Object).Count

10
```

### Password for Century 15
```
10
```
