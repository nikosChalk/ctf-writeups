
import gdb

BP_STOP = True
BP_CONT = False

flag_prefix = 'UMASS{'
prog_input = b'P'*55    # 'P' == 0x50
# prog_input = bytes(flag_prefix + 'A'*(55-len(flag_prefix)), encoding='utf-8')
# prog_input = b'ABCDEFGHIJKLMNOPQRSTUVWXZY0123456789abcdefghijklmnopqrs'
# prog_input = b'UMASS{GHIJKLMNOPQRSTUVWXZY0123456789abcdefghijklmnopqrs'

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
        global jit_code_addr
        fd    = int(gdb.parse_and_eval("$rdi"))
        buf   = int(gdb.parse_and_eval("$rsi"))
        count = int(gdb.parse_and_eval("$rdx"))
        print(f"{self.count}. Reading {count} bytes in {hex(buf)} == jit_stack_base + {hex(buf-jit_stack_base)}")
        gdb.execute(f"dump binary memory gdb-dumps/stack{str(self.count)}.bin {hex(jit_stack_base)} {hex(jit_stack_base+0xa0)}")

        self.count+=1
        if self.count < 55:
            return BP_CONT
        else:
            return BP_STOP
ReadSyscallBreakPoint(f"*{hex(jit_code_addr + 0x1433)}")

# Catch all write() system calls
class WriteSyscallBreakPoint(gdb.Breakpoint):
    def stop(self):
        global jit_code_addr
        fd    = int(gdb.parse_and_eval("$rdi"))
        buf   = int(gdb.parse_and_eval("$rsi"))
        count = int(gdb.parse_and_eval("$rdx"))
        print(f"Writing {count} bytes in {hex(buf)} == jit_stack_base + {hex(buf-jit_stack_base)}")
        return BP_STOP
WriteSyscallBreakPoint(f"*{hex(jit_code_addr + 0x3caf2)}")

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

LogBreakPoint(f"*({hex(jit_stack_base)}      as *const u32)", type=gdb.BP_WATCHPOINT, wp_class=gdb.WP_WRITE, dump_start=jit_stack_base     , dump_sz=0x90)
LogBreakPoint(f"*({hex(jit_stack_base+0x70)} as *const u64)", type=gdb.BP_WATCHPOINT, wp_class=gdb.WP_WRITE, dump_start=jit_stack_base+0x70, dump_sz=0x20)

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

# Now the process has hit the write() syscall
gdb.execute("continue")

# Now the process has exited
gdb.execute("quit")
