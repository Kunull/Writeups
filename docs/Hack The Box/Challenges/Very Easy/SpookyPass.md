> All the coolest ghosts in town are going to a Haunted Houseparty - can you prove you deserve to get in?

After downloading the file, we can unzip it as follows:

```
$ sudo unzip SpookyPass.zip
Archive:  SpookyPass.zip
   creating: rev_spookypass/
[SpookyPass.zip] rev_spookypass/pass password: 
  inflating: rev_spookypass/pass  
```

Let's execute the file.

```
$ ./rev_spookypass/pass 
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password: test
You're not a real ghost; clear off!
```

We see that it asks for a password, which we currently do not have.

## strings

In Linux, we can use the `strings` utility to dump all strings from a binary executable.

```
$ strings ./rev_spookypass/pass 
/lib64/ld-linux-x86-64.so.2
fgets
stdin
puts
__stack_chk_fail
__libc_start_main
__cxa_finalize
strchr
printf
strcmp
libc.so.6
GLIBC_2.4
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u3UH
Welcome to the 
[1;3mSPOOKIEST
[0m party of the year.
Before we let you in, you'll need to give us the password: 
s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
Welcome inside!
You're not a real ghost; clear off!
;*3$"
GCC: (GNU) 14.2.1 20240805
GCC: (GNU) 14.2.1 20240910
main.c
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
_fini
__stack_chk_fail@GLIBC_2.4
strchr@GLIBC_2.2.5
printf@GLIBC_2.2.5
parts
fgets@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
_end
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
```

![1](https://github.com/user-attachments/assets/fe77e2b8-4a24-4f77-a084-cd637c5e80e0)

```
s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
```

Let's execute the file again and provide the password this time.

```
$ ./rev_spookypass/pass 
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password: s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
Welcome inside!
HTB{un0bfu5c4t3d_5tr1ng5}
```

## Flag

```
HTB{un0bfu5c4t3d_5tr1ng5}
```
