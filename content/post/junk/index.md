---
title: junk
date: 2022-01-10T14:46:33.912Z
draft: false
featured: false
image:
  filename: featured
  focal_point: Smart
  preview_only: false
---
```python {linenos = inline}
#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *
from time import sleep
# Set up pwntools for the correct architecture
exe  = context.binary = ELF('%s')
host = args.HOST or '%s'
port = int(args.PORT or %s)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = start()

R = Rootkit(io)
payload = R.Exploit()

io.interactive()
```
