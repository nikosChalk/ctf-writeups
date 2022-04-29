# veryfastvm

Categories: Pwn/Rev

Description:
> Just a Python VM. Someone could say that this challenge is more rev than pwn.
> nc ctf.b01lers.com 9204
> 
> Author: anton00b
> Difficulty: Medium

**Tags:** CPU Emulator, Reversing, Timing side-channel, Flush & Reload

## Takeaways

A cool timing side-channel attack.

## Solution

For this challenge, we are given the source code in [cpu.orig.py](cpu.orig.py). As we can quickly notice, this a CPU emulator (i.e. a VM implementation). It supports a bunch of instructions, like `mov`, `add`, `xor`, etc. The code isn't really readable as the variables have weird names, so let's try to clean it up. The deobfuscated/annotated code can be found in [cpu.py](cpu.py)

As we can see, this CPU has 10 general purpose registers (`r0` through `r9` stored in `regs` variable), a program count (`pc`) register, a register that gets incremented every cycle (`time_reg`), 1MB memory, and a cache. The registers are all 32-bit. Each memory address is capable of holding a 32-bit value. The instructions are held in a separate memory and are not accessible at all from the VM. It also has 4 secret registers (`secret_vector`) which get initialized during the first boot with random values and are also inaccessible from the VM.

(*Minor VM modification:* To ease debugging, in the [cpu.py](cpu.py), we have disabled input limitations (55 instructions and 2000 characters) and we have hard-coded secrets instead of random ones. We also added one more VM instruction, `bp`, which stands for breakpoint. You can add this instruction to your payload and set a breakpoint in your debugger inside the `ins.op == "bp"` if case.)

In order to get the flag, we have to reboot it once so that the `num_of_reboots==2`, put the secret values into the first four registers `r0`, `r1`, `r2`, `r3`, and then execute the `magic` instruction.

```python
if ins.op == "magic" AND self.num_of_reboots == 2:
    # order in tuple comparison is important
    if tuple(self.regs[0:4]) == self.secret_vector:
        # Loads the flag into the registers r0, r1, etc.
        # To dump the flag, terminate by doing `halt`
        with open("flag.txt", "rb") as fp:
            cc = fp.read()
        cc = cc.strip()
        cc = cc.ljust(len(self.regs)*4, b"\x00")
        for i in range(len(self.regs)):
            self.regs[i] = struct.unpack("<I", cc[i*4:(i+1)*4])[0]
```


Let's examine the code a little bit more. After the instructions have been read, `run()` is invoked.

```python
def run(self):
    for i,v in enumerate(self.secret_vector):
        self.memory[i] = v
    while (self.pc>=0 and self.pc<len(self.instructions) and self.num_of_reboots<4 and self.time_reg<20000):
        ins = self.instructions[self.pc]
        self.execute(ins) # Execute a single instruction and change self.pc to the next instruction
```

The secret is transferred from the registers to the memory during the first boot. This is because from the VM we have no other way to read the registers. So, can we simply reboot to satisfy `num_of_reboots==2` and then transfer from memory to registers the secrets and get the flag? The answer is no.

```python
def reset(self):
    self.pc = 0
    self.regs = [0 for r in range(num_of_gp_regs)]
    self.memory = [0 for _ in range(MEM_LIMIT)]   # 1MB
    self.time_reg = 0
    for k in self.cache.keys():
        self.cache[k] = 0
    self.num_of_reboots += 1
```

As you can see, upon reboot the memory, cache, and registers get erased. We do not have a place to store the secret without it getting erased between reboots. Let's pay a little more attention to the instructions themselves.

```python
def execute(self, ins):
    '''Execute a single instruction'''

    self.time_reg += 1
    if ins.op == "bp":
        self.pc += 1
    elif ins.op == "movc":
        self.regs[ins.op2] = ins.imm
        self.pc += 1
    elif ins.op == "reset":
        self.reset()
    elif ins.op == "time":
        self.regs[0] = self.time_reg
        self.pc += 1
    elif ins.op == "add":
        v = self.regs[ins.op2] + self.regs[ins.op1]
        self.regs[ins.op2] = (v & 0xffffffff)
        self.pc += 1
    elif ins.op == "movfrom": # load from memory
        addr = ins.op_mem + self.regs[ins.dsp]
        addr = addr % len(self.memory)
        if addr in self.cache:
            v = self.cache[addr]
            v = (v & 0xffffffff)
            self.regs[ins.op2] = v
            self.pc += 1
        else:
            v = self.memory[addr]
            self.cache[addr] = v
            self.execute(ins)
    elif ins.op == "movto": # store to memory
        addr = ins.op_mem + self.regs[ins.dsp]
        addr = addr % len(self.memory)
        if addr in self.cache:
            del self.cache[addr]
        v = (self.regs[ins.op2] & 0xffffffff)
        self.memory[addr] = v
        self.pc += 1
    # ... #
    else:
        assert False
    return
```

As you can see, the `time_reg` is readable via the `time` instruction and it gets incremented by 1 in every instruction. Except in `movfrom`. Now this is a good time to understand how the cache works.

When we want to load a value from a memory address `addr`, we first check if the value is present in the cache by indexing it with the address `addr`. If it is in the cache (key exists), then everything is great and we simply fetch the value from the cache. If it is not in the cache, then we bring it from the memory and we retry the instruction as it can be seen from the `self.execute(ins)` line. On the other hand, when we store in memory, any associated cache entry gets removed from the cache via the `del self.cache[addr]`.

There are two interesting things going on here. First, a cache miss results in a `movfrom` that increments the `time_reg` by 2, while a cache hit (and all the other instructions) increment it by 1. In other words, `time_reg` counts clock cycles. All instructions take 1 clock cycle to execute, except a `movfrom` that is a cache miss which takes 2 cycles. **Since we can read the `time_reg`, this is a timing side-channel to know if we have a cache hit or a cache miss.**

The second thing has to do with `del self.cache[addr]`. Now this seems a perfectly legit behavior to do right? If we perform a store operation at `addr`, then we also remove any old contents from the cache at index `addr`. But what happens during reboot?

```python
for k in self.cache.keys():
    self.cache[k] = 0
```

Hold up! **During reboot the entries from cache are not removed**, they are simply set to 0. This does not have an impact on the program's correctness because the memory is also zeroed out, so reading from an address that stayed in the cache between reboots will still result in a value-read of 0. Correctness is not violated. However, we have yet again another side-channel! **We can preserve values between reboots by storing them as indexes in the cache!**

For example, let's say that a secret value is `0xdeadbeef`. We can perform a load at address `0xdeadbeef` and then reboot. Then with a loop, a counter, and our timing side-channel, we can check every cache entry to see if the current entry exists or not. Once we stumble upon an existing cache entry, we know that our counter contains the secret value!

```c
// r2 == 0xdeadbeef (secret)
// movfrom syntax: movfrom reg [mem+dsp]
//   * semantics: reg = [mem + dsp]

// Set cache index 0xdeadbeef by fetching from mem [0xdeadbeef]. Then reboot.
movfrom r0 00000 r2
reset

// `0xdeadbeef in self.cache` evaluates to true. Search for it.
int secret=0;
while(1) {
    if secret in cache //key lookup
        break;
    secret++;
}

printf("Secret is %d\n", secret);
```

Great! Does this actually work? Not exactly. The intuition is correct, but the memory is 1MB and also the cache is indexed modulo 1MB (`addr = addr % len(self.memory)`). So, the cache can hold up to 2^20 entries and the secret value is 32 bits. So, with this method we lose 12 bits of information due to the modulo operation. Let's try an alternative approach.

We will encode the secret over multiple consecutive addresses of the cache. Each bit of the secret will correspond to a different cache address. If the bit is 1, then the cache entry shall exist. If the bit is 0, we can make sure that the cache entry does not exist (via a `movto`). The value of the cache entry does not matter. For example

```python
# secret = 0xdeadbeef
# 0xdeadbeef.   d     e    a    d   b    e    e    f
# (MSB)        1101 1110 1010 1101 1011 1110 1110 1111 (LSB)
# We will store it in little-endian format.
# The values of cache entries do not matter. 
cache = {
    0x00: exists,
    0x01: exists,
    0x02: exists,
    0x03: exists,

    # 0x04: non-existent, #
    0x05: exists,
    ...
    # 0x1D: non-existent, #
    0x1E: exists,
    0x1F: exists
}
```

Awesome! Let's try to write some pseudo-C code that does this for all 4 secret values and then we will try to convert that into assembly.

```c
//C-like encoder code
for(int secret_counter=0; secret_counter<4 ++secret_counter) {
    int secret = secrets[secret_counter];
    int cache_idx = secret_counter*32;
    for(int i=0; i<32; ++i) {
        int bit = secret & (1ULL << i);
        if(bit)
            set cache[cache_idx+i];
    }
}
```

Great! This code does the encoding that we described above. However, is it directly translatable to the VM's instruction set? Not exactly. For example we are lacking some useful instructions, like `jmpl` (jump if less), division, and shifting instructions. Let's transform the above code so that it is closer to the VM's architecture.

```c
//C-like encoder code, close to the VM's architecture
int secret_counter = 4;
while(secret_counter > 0) {
    int cache_idx = secret_counter*32;
    int secret = secrets[secret_counter-1];
    int secret_idx     = 1;
    while(secret_idx > 0) {
        int bit = secret & secret_idx;
        if bit:
            set cache[cache_idx];
        secret_idx    = secret_idx * 2;
        ++cache_idx;
    }
    --secret_counter;
}
```

So, `secret[0]` gets encoded in `cache[32:64]`, `secret[1]` gets encoded in `cache[64:96]`, etc.. Let's also write the decoder. The decoder shall reconstruct the secrets from the cache and store them in memory.

```c
//C-like decoder code, close to the VM's architecture
int secret_counter = 5;
while(secret_counter > 0) {
    //start from the MSB as the constructed value is
    //constantly pushed to the left.
    int cache_idx         = (secret_counter*32)-1;

    int recovered_secret  = 0;
    int i                 = 32;
    while(i > 0) {
        //perform cache timing side-channel attack
        t1 = time();
        access memory[cache_idx]
        t2 = time();
        int bit = t2 - t1 - 3;
        //bit == 0 means cached        <==> bit is 1
        //bit == 1 means not cached    <==> bit is 0
        bit = bit ^ 1   //flip the bit
        recovered_secret = recovered_secret * 2 //shift left
        recovered_secret = recovered_secret | bit
        --cache_idx;
        --i;
    }
    //store recovered_secret in mem[1000000 + secret_counter]
    movto recovered_secret 1000000 secret_counter
    --secret_counter;
}
```

Great! So now, after decoding, `secret[0]` will be stored in `mem[1000002]`, `secret[1]` will be stored in `mem[1000003]`, etc.. The only remaining thing to deal with is reboots.

We can perform a reboot after we have done our encoding via the `reset` instruction. The only issue here is that the program stats executing from the beginning. So, we need a way to identify if a reboot has occurred or not in order to decide if we should execute the encoder or the decoder.

We can do this in two ways. The first way is to use our timing side-channel by checking a fixed cache index, e.g. `0xBEEF` which the encoder will set. But this takes too many VM instructions and remember that we have a limit of 55. There is another way in which we can do it.

Recall that on the first boot, the first 4 addresses of memory are populated with the secret. And upon reboot the memory is erased.

```python
def run(self):
    ins = self.instructions[0]
    for i,v in enumerate(self.secret_vector):
        self.memory[i] = v
        ...
def reset(self):
    self.memory = [0 for _ in range(MEM_LIMIT)]
    ...
```

So, we can check if `mem[0]` is zero or not in order to determine if our reboot has occurred or not correspondingly. Now, let's *assemble* our VM code to get the flag!

```x86asm
# Check if reboot has occurred
movfrom r0 0000000 r1
jmpz 22 # goto label_after_reset

############# encoder #############

# In the cache:
#  * indexes [ 32: 64] - They belong to mem[0], i.e. secret[0]
#  * indexes [ 64: 96] - They belong to mem[1], i.e. secret[1]
#  * indexes [ 96:128] - They belong to mem[2], i.e. secret[2]
#  * indexes [128:160] - They belong to mem[3], i.e. secret[3]

# r1, r2 counter registers
# r1 = secret_counter (outer)
# r2 = cache_idx      (inner)
# r3 = secret         (inner)
# r4 = secret_idx     (inner)
# r6 = CONSTANT(32)
# r7 = CONSTANT(0)
# r8 = CONSTANT(1)
# r9 = CONSTANT(2)
movc r1  4   # secret_counter = 4
movc r6 32   # constant
movc r7  0   # constant
movc r8  1   # constant
movc r9  2   # constant

# label_outer_loop:
mov     r2 r1
mul     r2 r6              # cache_idx  = secret_counter*32
movfrom r3 1048575 r1      # secret     = secret[secret_counter-1]
movc    r4 0x00000001      # secret_idx = 1

# label_inner_loop:
mov     r0 r4
and     r0 r3   # bit = secret & secret_idx
jmpz    2       # skip next instruction
movfrom r0 0000000 r2   # set cache[cache_idx];

mul     r4 r9   # secret_idx = secret_idx *2
add     r2 r8   # ++cache_idx
mov     r0 r4
jmpg r7 -7      # goto label_inner_loop

sub     r1 r8
mov     r0 r1
jmpg r7 -15  # goto label_outer_loop

reset
# label_after_reset:

############# decoder #############

# In memory:
#  * mem[1000002]  = recovered_secret[0]
#  * mem[1000003]  = recovered_secret[1]
#  * mem[1000004]  = recovered_secret[2]
#  * mem[1000005]  = recovered_secret[3]

# r1, r2 counter registers
# r1 = secret_counter   (outer)
# r2 = cache_idx        (inner)
# r3 = recovered_secret (inner)
# r4 = i                (inner)
# r5 scratch register
# r6 = CONSTANT(32)
# r7 = CONSTANT(0)
# r8 = CONSTANT(1)
# r9 = CONSTANT(2)
movc r1  5   # secret_counter = 5
movc r6 32   # constant
movc r7  0   # constant
movc r8  1   # constant
movc r9  2   # constant

# label_outer_loop:
mov     r2 r1
mul     r2 r6     
sub     r2 r8     # cache_idx          = (secret_counter*32) - 1
movc    r3 0      # recovered_secret   = 0
movc    r4 32     # i                  = 32

# label_inner_loop:
time
mov     r5 r0           # r5 = timestamp1
movfrom r0 0000000 r2   # check if address "cache_idx" is in cache
time                    # r0 = timestamp2

# compare timestamps
sub r0 r5
sub r0 r8   
sub r0 r9   # r0 = timestamp2 - timestamp1 - 3
xor r0 r8   # r0 = bit
mul r3 r9   # recovered_secret = recovered_secret * 2
or  r3 r0   # recovered_secret = recovered_secret | bit

sub     r2 r8   # --cache_idx
sub     r4 r8   # --i;
mov     r0 r4
jmpg r7 -13      # goto label_inner_loop

movto   r3 1000000 r1 # far away from caching region
sub     r1 r8
mov     r0 r1
jmpg r8 -22  # goto label_outer_loop

##########

movfrom r0 1000002 r7
movfrom r1 1000003 r7
movfrom r2 1000004 r7
movfrom r3 1000005 r7
magic
halt
```

Only a really tiny small caveat here blocking our way. The payload is 57 instructions long, while the program expects maximum 55 instructions. Since registers are always zero-initialized during boot, we can skip twice the initialization of `r8` to 0, and we can also skip the final `halt` instruction. This brings us down to 54 instructions. We re-align our jumps and run again our payload. This time we managed to get it running!

```log
Registers: [
    1718903650, 1664377723, 1735289192, 1601399135, 
    2037527414, 1869571935,    8220516,          0, 
    0, 0
]
```

Awesome! We got the flag! Let's convert the bytes to printable characters

```python
regs = [
    1718903650, 1664377723, 1735289192, 1601399135, 
    2037527414, 1869571935,    8220516
]
for reg in regs:
    print(reg.to_bytes(4, 'little').decode('ascii'), end='')
print()
```

And the flag is `bctf{c4ching_is_v3ry_goodo}`
