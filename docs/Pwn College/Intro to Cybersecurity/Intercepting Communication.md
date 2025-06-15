---
custom_edit_url: null
sidebar_position: 2
---

## Connect

In this challegne, we have to connect to `10.0.0.2` on port `31337`.

```
hacker@intercepting-communication~connect:/$ /challenge/run 
root@ip-10-0-0-1:/#
```

```
root@ip-10-0-0-1:/# nc 10.0.0.2 31337
pwn.college{wbLEvztIH-MlyXZbTzR3-bhhAwh.dlTNzMDL4ITM0EzW}
```

&nbsp;

## Send

This time we have to send a message containing `"Hello, World!""` to the remote host `10.0.0.2` on port `31337`.

```
root@ip-10-0-0-1:/# nc 10.0.0.2 31337
Hello, World!
pwn.college{0Hb11t9ijpcF9e3tDdE_3W2fDWk.QX1IDM2EDL4ITM0EzW}
```

&nbsp;

## Shutdown

We can use the `-N` option in `nc` so that it shuts down on `CTRL-D`.

```
hacker@intercepting-communication~shutdown:/$ /challenge/run 
root@ip-10-0-0-1:/# 
```

```
root@ip-10-0-0-1:/# nc -N 10.0.0.2 31337
pwn.college{M0ZqQvNQkxl9FGLlvmqyp4DYcoE.QX2IDM2EDL4ITM0EzW}
```

&nbsp;

## Listen
