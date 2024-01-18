---
custom_edit_url: null
pagination_next: null
pagination_prev: null
---

> The flag used to be there. But then I redacted it. Good Luck. https://mega.nz/#!3CwDFZpJ!Jjr55hfJQJ5-jspnyrnVtqBkMHGJrd6Nn_QqM7iXEuc
- Let's look at the contents of the directory.
```
>dir
 Volume in drive D is DATA
 Volume Serial Number is 904D-581D

 Directory of D:\gitIsGood

30-10-2016  14:33    <DIR>          .
30-10-2016  14:33    <DIR>          ..
30-10-2016  14:33    <DIR>          .git
30-10-2016  14:33                15 flag.txt
               1 File(s)             15 bytes
               3 Dir(s)  662,738,264,064 bytes free
```
- We can look at the `.git` directory for the information about the project.
```
dir
 Volume in drive D is DATA
 Volume Serial Number is 904D-581D

 Directory of D:\gitIsGood\.git

30-10-2016  14:33    <DIR>          .
30-10-2016  14:33    <DIR>          ..
30-10-2016  14:31    <DIR>          branches
30-10-2016  14:33               220 COMMIT_EDITMSG
30-10-2016  14:31               137 config
30-10-2016  14:31                73 description
30-10-2016  14:31                23 HEAD
30-10-2016  14:31    <DIR>          hooks
30-10-2016  14:33               137 index
30-10-2016  14:31    <DIR>          info
30-10-2016  14:32    <DIR>          logs
30-10-2016  14:33    <DIR>          objects
30-10-2016  14:31    <DIR>          refs
               5 File(s)            590 bytes
               8 Dir(s)  662,738,264,064 bytes free
```
- We can look at the logs using the `git log` command.
```
git log
commit d10f77c4e766705ab36c7f31dc47b0c5056666bb (HEAD -> master)
Author: LaScalaLuke <lascala.luke@gmail.com>
Date:   Sun Oct 30 14:33:18 2016 -0400

    Edited files

commit 195dd65b9f5130d5f8a435c5995159d4d760741b
Author: LaScalaLuke <lascala.luke@gmail.com>
Date:   Sun Oct 30 14:32:44 2016 -0400

    Edited files

commit 6e824db5ef3b0fa2eb2350f63a9f0fdd9cc7b0bf
Author: LaScalaLuke <lascala.luke@gmail.com>
Date:   Sun Oct 30 14:32:11 2016 -0400

    edited files
```
- So the `flag.txt` file was edited three times in the span of around two minutes.
- If we use the `p` flag, we can see what the edits were.
```
>git log -p
commit d10f77c4e766705ab36c7f31dc47b0c5056666bb (HEAD -> master)
Author: LaScalaLuke <lascala.luke@gmail.com>
Date:   Sun Oct 30 14:33:18 2016 -0400

    Edited files

diff --git a/flag.txt b/flag.txt
index 8684e68..c5250d0 100644
--- a/flag.txt
+++ b/flag.txt
@@ -1 +1 @@
-flag{protect_your_git}
+flag{REDACTED}

commit 195dd65b9f5130d5f8a435c5995159d4d760741b
Author: LaScalaLuke <lascala.luke@gmail.com>
Date:   Sun Oct 30 14:32:44 2016 -0400

    Edited files

diff --git a/flag.txt b/flag.txt
index c5250d0..8684e68 100644
--- a/flag.txt
+++ b/flag.txt
@@ -1 +1 @@
-flag{REDACTED}
+flag{protect_your_git}

commit 6e824db5ef3b0fa2eb2350f63a9f0fdd9cc7b0bf
Author: LaScalaLuke <lascala.luke@gmail.com>
Date:   Sun Oct 30 14:32:11 2016 -0400

    edited files

diff --git a/flag.txt b/flag.txt
new file mode 100644
index 0000000..c5250d0
--- /dev/null
+++ b/flag.txt
@@ -0,0 +1 @@
+flag{REDACTED}
```
- Now we know that the flag was `flag{REDACTED}`, which was then changed to `flag{protect_your_git}` and then again changed to `flag{REDACTED}`.
## Flag
```
flag{protect_your_git}
```
