
# babyvm

Categories: Reversing

Description:
> By Jakob
> 
> I wanted to learn how a JIT works, so I wrote my own.
> 
> Compiler? Bytecode spec? That's a secret :)
> 
> The executable was built on Ubuntu 20.04.
> https://storage.googleapis.com/umassctf-22-challenges/4122985c-aa52-4395-9539-f6516ac5139e/babyvm.zip 

## Takeaways

How to script GDB

## Solution

The program `mmaps` a region and starts spitting x86 assembly code there. Then it jumps to the base address of the region and starts executing. The emitted assembly contains some overlapping instructions, but that did appear as a problem anywhere down the road.

Also it creates the file `/tmp/shellcode.bin`. This file is the same as the emitted binary code (dumping the region and performing a diff gives the same result). The babyvm also reads from stdin 55 bytes and then writes 1 byte to stdout (run it via `strace`).

The emitted x86 assembly is horrible to look at, a bunch of `inc` and `dec` instructions. For the VM, it seems its stack pointer is the `rax` register and is incapable of arithmetic operations, just `inc` and `dec`. It also operates on 1-byte memory addresses and registers. Besides, `rax` it also uses `bl`.

After a lot of fiddling around we can draw some conclusions.

* First, the whole input is read before the VM spits out the flag.
* The `write()` system call is invoked only once and its output is the same regardless of input.
* The location of the `write()` system call is always the same `stack_base+0x73`, always 1 byte and always the character `)`, regardless of input
* The input is stored in a small memory range at `stack_base`, e.g.
    ```
    # The input consists of 'P'*55
    37 00 00 00 01 50 01 50  7....P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 01 50 01 50 01 50  .P.P.P.P
    01 50 00 50 00 00 00 00  .P.P....
    00 00 00 00 00 00 00 00  ........
    00 00 00 00 00 00 00 00  ........
    00 00 00 00 00 00 00 00  ........
    ```

At this point I was stuck but still kept fiddling around and dumping memory with GDB watchpoints. At some point, we observe a pattern when dumping memory

We set a breakpoint to watch 2 bytes from `stack_base+0x73`. Upon hitting the breakpoint, we dump those two bytes. We see a pattern:

```log
Breakpoint expression: *(0x7fffffffaa0b as *const u8 )
Dumping range [0x7fffffffaa0b, 0x7fffffffaa0d) - 0x2 bytes

02 00  ..
01 00  ..
00 00  ..
01 00  ..
02 00  ..
03 00  ..
04 00  ..
05 00  ..
06 00  ..
07 00  ..
08 00  ..
09 00  ..
0a 00  ..
0b 00  ..
0c 00  ..
0d 00  ..
0e 00  ..
0f 00  ..
10 00  ..
11 00  ..
12 00  ..
13 00  ..
14 00  ..
15 00  ..
16 00  ..
17 00  ..
18 00  ..
19 00  ..
1a 00  ..
1b 00  ..
1c 00  ..
1d 00  ..
1e 00  ..
1f 00  ..
20 00   .
21 00  !.
22 00  ".
23 00  #.
24 00  $.
25 00  %.
26 00  &.
27 00  '.
28 00  (.
29 00  ).
2a 00  *.
2b 00  +.
2c 00  ,.
2d 00  -.
2e 00  ..
2f 00  /.
30 00  0.
31 00  1.
32 00  2.
33 00  3.
34 00  4.
35 00  5.
36 00  6.
37 00  7.
38 00  8.
39 00  9.
3a 00  :.
3b 00  ;.
3c 00  <.
3d 00  =.
3e 00  >.
3f 00  ?.
40 00  @.
41 00  A.
42 00  B.
43 00  C.
44 00  D.
45 00  E.
46 00  F.
47 00  G.
48 00  H.
49 00  I.
4a 00  J.
4b 00  K.
4c 00  L.
4d 00  M.
4e 00  N.
4f 00  O.
50 00  P.
4f 55  OU
!!!!!!!!!!!!!!!!!!!!!!
4e 54  NT
4d 53  MS
4c 52  LR
4b 51  KQ
4a 50  JP
49 4f  IO
48 4e  HN
47 4d  GM
46 4c  FL
45 4b  EK
44 4a  DJ
43 49  CI
42 48  BH
41 47  AG
40 46  @F
3f 45  ?E
3e 44  >D
3d 43  =C
3c 42  <B
3b 41  ;A
3a 40  :@
39 3f  9?
38 3e  8>
37 3d  7=
36 3c  6<
35 3b  5;
34 3a  4:
33 39  39
32 38  28
31 37  17
30 36  06
2f 35  /5
2e 34  .4
2d 33  -3
2c 32  ,2
2b 31  +1
2a 30  *0
29 2f  )/
28 2e  (.
27 2d  '-
26 2c  &,
25 2b  %+
24 2a  $*
23 29  #)
22 28  "(
21 27  !'
20 26   &
1f 25  .%
1e 24  .$
1d 23  .#
1c 22  ."
1b 21  .!
1a 20  . 
19 1f  ..
18 1e  ..
17 1d  ..
16 1c  ..
15 1b  ..
14 1a  ..
13 19  ..
12 18  ..
11 17  ..
10 16  ..
0f 15  ..
0e 14  ..
0d 13  ..
0c 12  ..
0b 11  ..
0a 10  ..
09 0f  ..
08 0e  ..
07 0d  ..
06 0c  ..
05 0b  ..
04 0a  ..
03 09  ..
02 08  ..
01 07  ..
00 06  ..
01 05  ..
00 05  ..
01 00  ..
00 00  ..
01 00  ..
02 00  ..
03 00  ..
04 00  ..
05 00  ..
06 00  ..
07 00  ..
08 00  ..
09 00  ..
0a 00  ..
0b 00  ..
0c 00  ..
0d 00  ..
0e 00  ..
0f 00  ..
10 00  ..
11 00  ..
12 00  ..
13 00  ..
14 00  ..
15 00  ..
16 00  ..
17 00  ..
18 00  ..
19 00  ..
1a 00  ..
1b 00  ..
1c 00  ..
1d 00  ..
1e 00  ..
1f 00  ..
20 00   .
21 00  !.
22 00  ".
23 00  #.
24 00  $.
25 00  %.
26 00  &.
27 00  '.
28 00  (.
29 00  ).
2a 00  *.
2b 00  +.
2c 00  ,.
2d 00  -.
2e 00  ..
2f 00  /.
30 00  0.
31 00  1.
32 00  2.
33 00  3.
34 00  4.
35 00  5.
36 00  6.
37 00  7.
38 00  8.
39 00  9.
3a 00  :.
3b 00  ;.
3c 00  <.
3d 00  =.
3e 00  >.
3f 00  ?.
40 00  @.
41 00  A.
42 00  B.
43 00  C.
44 00  D.
45 00  E.
46 00  F.
47 00  G.
48 00  H.
49 00  I.
4a 00  J.
4b 00  K.
4c 00  L.
4d 00  M.
4e 00  N.
4f 00  O.
50 00  P.
4f 4d  OM
!!!!!!!!!!!!!!!!!!!!!!
4e 4c  NL
4d 4b  MK
4c 4a  LJ
4b 49  KI
4a 48  JH
49 47  IG
48 46  HF
47 45  GE
46 44  FD
45 43  EC
44 42  DB
43 41  CA
42 40  B@
41 3f  A?
40 3e  @>
3f 3d  ?=
3e 3c  ><
3d 3b  =;
3c 3a  <:
3b 39  ;9
3a 38  :8
39 37  97
38 36  86
37 35  75
36 34  64
35 33  53
34 32  42
33 31  31
32 30  20
31 2f  1/
30 2e  0.
2f 2d  /-
2e 2c  .,
2d 2b  -+
2c 2a  ,*
2b 29  +)
2a 28  *(
29 27  )'
28 26  (&
27 25  '%
26 24  &$
25 23  %#
24 22  $"
23 21  #!
22 20  " 
21 1f  !.
20 1e   .
1f 1d  ..
1e 1c  ..
1d 1b  ..
1c 1a  ..
1b 19  ..
1a 18  ..
19 17  ..
18 16  ..
17 15  ..
16 14  ..
15 13  ..
14 12  ..
13 11  ..
12 10  ..
11 0f  ..
10 0e  ..
0f 0d  ..
0e 0c  ..
0d 0b  ..
0c 0a  ..
0b 09  ..
0a 08  ..
09 07  ..
08 06  ..
07 05  ..
06 04  ..
05 03  ..
04 02  ..
03 01  ..
02 00  ..
01 ff  .ÿ
00 fe  .þ
01 fd  .ý
00 fd  .ý
01 00  ..
00 00  ..
01 00  ..
02 00  ..
03 00  ..
04 00  ..
05 00  ..
06 00  ..
07 00  ..
08 00  ..
09 00  ..
0a 00  ..
0b 00  ..
0c 00  ..
0d 00  ..
0e 00  ..
0f 00  ..
10 00  ..
11 00  ..
12 00  ..
13 00  ..
14 00  ..
15 00  ..
16 00  ..
17 00  ..
18 00  ..
19 00  ..
1a 00  ..
1b 00  ..
1c 00  ..
1d 00  ..
1e 00  ..
1f 00  ..
20 00   .
21 00  !.
22 00  ".
23 00  #.
24 00  $.
25 00  %.
26 00  &.
27 00  '.
28 00  (.
29 00  ).
2a 00  *.
2b 00  +.
2c 00  ,.
2d 00  -.
2e 00  ..
2f 00  /.
30 00  0.
31 00  1.
32 00  2.
33 00  3.
34 00  4.
35 00  5.
36 00  6.
37 00  7.
38 00  8.
39 00  9.
3a 00  :.
3b 00  ;.
3c 00  <.
3d 00  =.
3e 00  >.
3f 00  ?.
40 00  @.
41 00  A.
42 00  B.
43 00  C.
44 00  D.
45 00  E.
46 00  F.
47 00  G.
48 00  H.
49 00  I.
4a 00  J.
4b 00  K.
4c 00  L.
4d 00  M.
4e 00  N.
4f 00  O.
50 00  P.
4f 41  OA
!!!!!!!!!!!!!!!!!!!!!!
4e 40  N@
4d 3f  M?
4c 3e  L>
4b 3d  K=
4a 3c  J<
49 3b  I;
48 3a  H:
47 39  G9
46 38  F8
45 37  E7
44 36  D6
43 35  C5
42 34  B4
41 33  A3
40 32  @2
3f 31  ?1
3e 30  >0
3d 2f  =/
3c 2e  <.
3b 2d  ;-
3a 2c  :,
39 2b  9+
38 2a  8*
37 29  7)
36 28  6(
35 27  5'
34 26  4&
33 25  3%
32 24  2$
31 23  1#
30 22  0"
2f 21  /!
2e 20  . 
2d 1f  -.
2c 1e  ,.
2b 1d  +.
2a 1c  *.
29 1b  ).
28 1a  (.
27 19  '.
26 18  &.
25 17  %.
24 16  $.
23 15  #.
22 14  ".
21 13  !.
20 12   .
1f 11  ..
1e 10  ..
1d 0f  ..
1c 0e  ..
1b 0d  ..
1a 0c  ..
19 0b  ..
18 0a  ..
17 09  ..
16 08  ..
15 07  ..
14 06  ..
13 05  ..
12 04  ..
11 03  ..
10 02  ..
0f 01  ..
0e 00  ..
0d ff  .ÿ
0c fe  .þ
0b fd  .ý
0a fc  .ü
09 fb  .û
08 fa  .ú
07 f9  .ù
06 f8  .ø
05 f7  .÷
04 f6  .ö
03 f5  .õ
02 f4  .ô
01 f3  .ó
00 f2  .ò
01 f1  .ñ
00 f1  .ñ
01 00  ..
00 00  ..
01 00  ..
02 00  ..
03 00  ..
04 00  ..
05 00  ..
06 00  ..
07 00  ..
08 00  ..
09 00  ..
0a 00  ..
0b 00  ..
0c 00  ..
0d 00  ..
0e 00  ..
0f 00  ..
10 00  ..
11 00  ..
12 00  ..
13 00  ..
14 00  ..
15 00  ..
16 00  ..
17 00  ..
18 00  ..
19 00  ..
1a 00  ..
1b 00  ..
1c 00  ..
1d 00  ..
1e 00  ..
1f 00  ..
20 00   .
21 00  !.
22 00  ".
23 00  #.
24 00  $.
25 00  %.
26 00  &.
27 00  '.
28 00  (.
29 00  ).
2a 00  *.
2b 00  +.
2c 00  ,.
2d 00  -.
2e 00  ..
2f 00  /.
30 00  0.
31 00  1.
32 00  2.
33 00  3.
34 00  4.
35 00  5.
36 00  6.
37 00  7.
38 00  8.
39 00  9.
3a 00  :.
3b 00  ;.
3c 00  <.
3d 00  =.
3e 00  >.
3f 00  ?.
40 00  @.
41 00  A.
42 00  B.
43 00  C.
44 00  D.
45 00  E.
46 00  F.
47 00  G.
48 00  H.
49 00  I.
4a 00  J.
4b 00  K.
4c 00  L.
4d 00  M.
4e 00  N.
4f 00  O.
50 00  P.
4f 53  OS
!!!!!!!!!!!!!!!!!!!!!!
...
```

Our input was `'P'*55`. As you can see, the first byte keeps incrementing until it reaches our input byte. On the next touch, it decreases by one and the 2nd byte flips from `0x00` to an important character. Afterwards, both bytes keep decreasing until they become simultaneously `00 00` and this cycle repeats. The important character is one flag character at a time because as you can see above it forms the `UMAS` string, which is the initial part of the flag.

Using the following GDB python script we can perform the above described dumping and get the flag:

```python
import gdb

BP_STOP = True
BP_CONT = False

prog_input = b'P'*55    # 'P' == 0x50
with open('inp.txt', 'wb') as f:
    f.write(prog_input)

binary_base_addr  = 0x555555554000
jmp_jit_code_addr = binary_base_addr + 0x83bd # call R14
jit_code_addr     = None                      # set later, e.g. 0x00007ffff7d38000

class JITStartBreakPoint(gdb.Breakpoint):
    '''
    If the method returns True , the inferior will be stopped at the location of the breakpoint
    If the method returns False, the inferior will continue.
    You should not alter the execution state of the inferior (e.g. no stepping!), alter the current frame context, or alter, add or delete any breakpoint!
    '''
    def stop(self):
        global jit_code_addr
        jit_code_addr = int(gdb.parse_and_eval("$r14")) # stay away from gdb.Value shit
        return BP_STOP

JITStartBreakPoint(f"*{hex(jmp_jit_code_addr)}")
gdb.execute("r < inp.txt")

# JITStartBreakPoint hit.
inf = gdb.inferiors()[0]
print("JIT Code Addr: " + hex(jit_code_addr))

gdb.Breakpoint(f"*{hex(jit_code_addr + 0x1d)}", temporary=True) # 0x7ffff7d3801d  mov rax, rsp
gdb.execute("continue")

# tbreak hit:  0x7ffff7d3801d  mov rax, rsp
jit_stack_base = int(gdb.parse_and_eval("$rsp"))     # 0x7fffffffa998
jit_stack_end  = jit_stack_base + 0x3000             # 0x7fffffffd998
output_addr    = jit_stack_base+0x73                 # The program spits in stdout 1 byte from this address
print("JIT stack base: " + hex(jit_stack_base))
print("JIT stack end : " + hex(jit_stack_end ))

# Catch all read() system calls
class ReadSyscallBreakPoint(gdb.Breakpoint):
    def __init__(self, *args, **kwargs) -> None:
        super(ReadSyscallBreakPoint, self).__init__(*args, **kwargs)
        self.count = 0
    
    def stop(self):
        self.count+=1
        if self.count < 55:
            return BP_CONT
        else:
            return BP_STOP
ReadSyscallBreakPoint(f"*{hex(jit_code_addr + 0x1433)}")

gdb.execute("continue")

# Now we have hit the last read() syscall

class LogBreakPoint(gdb.Breakpoint):
    '''
    Breakpoint that dumps memory when hit
    '''
    def __init__(self, *args, **kwargs) -> None:
        self.dump_start = kwargs.pop('dump_start')
        self.dump_sz = kwargs.pop('dump_sz')
        super(LogBreakPoint, self).__init__(*args, **kwargs)
        self.fp = open(f'gdb-dumps/bp{self.number}.log-{hex(self.dump_start)}.txt', 'w')
        self.fp.write(f'Breakpoint expression: {args[0]}\n')
        self.fp.write(f'Dumping range [{hex(self.dump_start)}, {hex(self.dump_start+self.dump_sz)}) - {hex(self.dump_sz)} bytes\n\n')
        self.prev = None

    def stop(self):
        rip = int(gdb.parse_and_eval("$rip"))
        mem  = bytes(inf.read_memory(self.dump_start, self.dump_sz))

        self.fp.write(f"RIP: {hex(rip)}:\n")
        for i in range(0, len(mem), 8):
            chunk = mem[i:min(i+8, len(mem))]

            self.fp.write("    ")
            for b in chunk:
                self.fp.write("%02x " % (b))
            self.fp.write(' ')
            for b in chunk:
                if chr(b).isprintable():
                    self.fp.write(f"{chr(b)}")
                else:
                    self.fp.write(".")
            self.fp.write('\n')
        self.fp.flush()
        return BP_CONT


LogBreakPoint(f"*({hex(jit_stack_base+0x73)} as *const u8)", type=gdb.BP_WATCHPOINT, wp_class=gdb.WP_WRITE, dump_start=jit_stack_base+0x73, dump_sz=0x02)

class FlagBreakPoint(gdb.Breakpoint):
    '''
    Breakpoint that dumps the flag in flag.txt
    '''
    def __init__(self, *args, **kwargs) -> None:
        global output_addr
        super(FlagBreakPoint, self).__init__(
            f"*({hex(output_addr)} as *const u8 )",
            type=gdb.BP_WATCHPOINT,
            wp_class=gdb.WP_WRITE,
            *args, **kwargs
        )
        self.fp = open('flag.txt', 'w')
        self.prev = None

    def stop(self):
        global output_addr
        mem  = bytes(inf.read_memory(output_addr, 0x02))

        if not self.prev:
            self.prev = mem
            return BP_CONT

        if self.prev[0] == ord('P') and self.prev[1] == 0x00:
            self.fp.write(f"{chr(mem[1])}")
            self.fp.flush()
        
        self.prev = mem
        return BP_CONT
FlagBreakPoint()

gdb.execute("continue")

# Now the process has exited
gdb.execute("quit")
```

For a full script, see `gdbpy-script.py`. Run it like: 

`gdb -x gdbpy-script.py ./babyvm`

The flag is `UMASS{H0Pe_1_NEVer_h4ve_70_5EE_7H1z_E50L4nG_EVeR_4G41N}`.
