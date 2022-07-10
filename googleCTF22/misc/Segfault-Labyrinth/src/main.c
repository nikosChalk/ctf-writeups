
#include "seg-faulting-labs.h"
#include <stdio.h>
#include <sys/mman.h>
#include <linux/seccomp.h>

/* Decompiled and cleaned up `main` function from the challenge binary */

/* WARNING: Could not reconcile some variable overlaps */

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

