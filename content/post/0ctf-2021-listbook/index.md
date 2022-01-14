---
title: 0ctf 2021
date: 2022-01-07T10:40:20.642Z
draft: false
featured: true
tags:
  - pwn
  - libc-2.31
  - tcache-stashing-unlink-plus
categories:
  - heap
image:
  filename: b2b46a3ab8e563d35bb7d38c8cc18091.png
  focal_point: Smart
  preview_only: true
  alt_text: ""
---
- - -

> # listbook

- - -

> CTF : https://ctftime.org/event/1356 <br>
> Challenge : https://ctftime.org/writeup/29118 <br>
> Challenge files : https://github.com/4n0nym4u5/CTF-Writeups/tree/main/0ctf-21-listbook <br>
> Points: 154 <br>
>
> # Checksec

- - -

```yaml
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
RUNPATH:  './'
```

> # Overview

- - -

It's a classic `libc 2.31` heap challenge. 

```ags
 _     _     _   ____              _    
| |   (_)___| |_| __ )  ___   ___ | | __
| |   | / __| __|  _ \ / _ \ / _ \| |/ /
| |___| \__ \ |_| |_) | (_) | (_) |   < 
|_____|_|___/\__|____/ \___/ \___/|_|\_\
==============================================

1.add
2.delete
3.show
4.exit
>>
```

As shown in the options we can add , delete and show heap notes. Lets look at these functions in IDA now

### main

![](https://imgur.com/kE40Aw8.png)

### add

![](https://imgur.com/KotctqV.png)

### remove

![](https://imgur.com/zPUCDvk.png)

### show

![](https://imgur.com/PCLMb5L.png)

There is one more interesting function that is `gen_hash()` used in `add` function.

![](https://imgur.com/DEHTmyU.png)

This function seems pretty good isn't it. Now lets look at the `abs8()` in gdb.
Lets give "A" as our name and hit breakpoint at 0x138f
![enter image description here](https://imgur.com/oraDnOw.png)


So everything is fine here right?. I bruteforced all values from 0x0 to 0xff and checked the returned value from the `gen_hash` function and saw something weird. Now lets give our `note->name` as "\x80"


![enter image description here](https://imgur.com/3cgsgFO.png) 

Lets see the disassembly of `abs8()`. <br> So `al` is being right shifted by 7 and since `al` is being used instead of `eax` there is a signedness issue here. Lets follow the operations after the `sar` instruction

![](https://imgur.com/NSmAdbH.png)

So there are two bugs. 

* UAF bug in `remove()` function    
* OOB in `gen_hash()` function

Next i quickly wrote a fuzzer to allocate chunks randomly. And i got nice crashes. 

* Tcache dup
* ( Unsorted / smallbin ) bin corruption

[![asciicast](https://asciinema.org/a/459156.svg)](https://asciinema.org/a/459156)

Now lets build our exploit. <br> So with the OOB bug we can mark chunk idx 0 and 1 as in_use by creating a "\x80" named chunk. <br> When a "\x80" named chunk is created the heap address of this chunk gets overlapped with the address of `in_use` variable in bss.<br>

```yaml
pwndbg> x/gx $in_use
0x555555558440: 0x0000000100000001 chunk 0 & 1 are in use
0x555555558440: 0x000055555555c720 "\x80" chunk heap address overlapped
```

<br>So we can use this primitive for getting leaks and building our exploit.<br>

> # Exploit

- - -

1. Use name "\x80" to trigger UAF in chunk idx 0 and 1.
2. Since it uses libc 2.31 and the allocation size is 0x31 and 0x211 ( smallbin size ) we use [Tcache Stashing Unlink+](https://qianfei11.github.io/2020/05/05/Tcache-Stashing-Unlink-Attack/#Tcache-Stashing-Unlink-Attack-Plus) attack to create overlapping chunks and overwrite fd of the tcache in the list.<br>

   ![](https://imgur.com/a/iLkBSj8.png)