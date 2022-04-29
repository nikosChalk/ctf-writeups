import sys
import os
import random
import struct
MEM_LIMIT = 1024*1024
num_of_gp_regs = 10
class Instruction:
    op = None   # opcode
    imm = 0     # immediate operant
    op2 = None  # For ALU: opcode op2 op1
    op1 = None  # For ALU: opcode op2 op1
    dsp = None  # Displacement register used only in movfrom/movto
    
    pc_rel = None   # for jump instructions.
    op_mem = 0  # memory operand
    str_rep = None

    def __init__(self, tstr):
        self.str_rep = tstr
        def parse_imm(tt):
            if tt.startswith("0x"):
                try:
                    v = int(tt, 16)
                except ValueError:
                    assert False
            else:
                try:
                    v = int(tt)
                except ValueError:
                    assert False
            assert v>=0
            assert v<pow(2,32)
            return v
        def parse_pc_rel(tt):
            try:
                v = int(tt)
            except ValueError:
                assert False
            assert v>-1000
            assert v<1000
            return v
        def parse_reg(tt):
            assert len(tt) == 2
            assert tt[0] == "r"
            try:
                v = int(tt[1])
            except ValueError:
                assert False
            assert v>=0
            assert v<num_of_gp_regs
            return v
        def parse_mem_addr(tt):
            try:
                v = int(tt)
            except ValueError:
                assert False
            assert v>=0
            assert v<MEM_LIMIT
            return v
        assert len(tstr)<100
        sstr = tstr.split()
        assert len(sstr)>=1
        assert len(sstr)<=4

        # opcode
        if len(sstr) == 1:
            t_op = sstr[0]
            assert t_op in ["halt", "time", "magic", "reset", "bp"]
            self.op = t_op

        elif len(sstr) == 2:
            t_op, t_1 = sstr
            assert t_op in ["jmp", "jmpz"]
            self.op = t_op
            if self.op == "jmp":
                self.pc_rel = parse_pc_rel(t_1)
            elif self.op == "jmpz":
                self.pc_rel = parse_pc_rel(t_1)
            else:
                assert False
        elif len(sstr) == 3:
            t_op, t_1, t_2 = sstr
            assert t_op in ["mov", "movc", "jmpg", "add", "sub", "mul", "and", "or", "xor"]
            self.op = t_op
            if self.op == "mov":
                # opcode op2 op1
                self.op2 = parse_reg(t_1)
                self.op1 = parse_reg(t_2)
            elif self.op in ["add", "sub", "mul", "and", "or", "xor"]:
                # opcode op2 op1
                self.op2 = parse_reg(t_1)
                self.op1 = parse_reg(t_2)
            elif self.op == "movc":
                # opcode op2 imm
                self.op2 = parse_reg(t_1)
                self.imm = parse_imm(t_2)
            elif self.op == "jmpg":
                self.op2 = parse_reg(t_1)
                self.pc_rel = parse_pc_rel(t_2)
            else:
                assert False
        elif len(sstr) == 4:
            t_op, t_1, t_2, t_3 = sstr
            assert t_op in ["movfrom", "movto"]
            self.op = t_op
            if self.op == "movfrom":
                # opcode op2 mem dsp
                # op2 = [mem+dsp]
                self.op2    = parse_reg(t_1)
                self.op_mem = parse_mem_addr(t_2)
                self.dsp    = parse_reg(t_3)
            elif self.op == "movto":
                # opcode op2 mem dsp
                # [mem+dsp] = op2
                self.op2    = parse_reg(t_1)
                self.op_mem = parse_mem_addr(t_2)
                self.dsp    = parse_reg(t_3)
            else:
                assert False
        else:
            assert False
    def pprint(self):
        tstr = "%s %s %s %s %s %s" %            (self.op, 
            "None" if self.op2==None else "r%d"%self.op2,
            "None" if self.op1==None else "r%d"%self.op1,
            hex(self.imm), "None" if self.pc_rel==None else self.pc_rel, self.op_mem)
        return tstr
class Cpu:
    '''Program counter'''
    pc = 0

    '''List of Instruction objects'''
    instructions = None

    '''
    List of registers: regs[0], regs[1], ..., regs[9]
    '''
    regs = None

    '''Key-value pairs'''
    memory = None

    '''Incremented by 1 on each instruction executed.'''
    time_reg = 0

    '''Memory cache. Key-value pairs
     * If upon `movfrom`, the memory address does not exist in cache, we fetch from main memory
       to the cache and repeat the instruction (2 cycles)
     * Upon `movto`, we invalidate the corresponding cache line and write directly to memory.
    '''
    cache = None

    '''Number of times that we have "reset()"'''
    num_of_reboots = 0

    '''
    Secret vector of 4 elements, initialized during the 1st boot
    Read-only. Values are 32-bit, so we have a 128-bit secret.
    '''
    secret_vector = None

    def __init__(self):
        self.instructions = []
        self.cache = {}
        # self.secret_vector = (random.randint(1,4200000000), random.randint(1,4200000000) , random.randint(1,4200000000), random.randint(1,4200000000))
        self.secret_vector = (0xdeadbeef, 0x0BBBBBBF , 0x0CCCCCCF, 0x0DDDDDDF)
        # self.secret_vector = (0xdeadbeef, 0x00000000 , 0x00000000, 0x00000000)
        self.reset()
    def reset(self):
        self.pc = 0
        self.regs = [0 for r in range(num_of_gp_regs)]
        self.memory = [0 for _ in range(MEM_LIMIT)]   # 1MB
        self.time_reg = 0
        for k in self.cache.keys():
            self.cache[k] = 0
        self.num_of_reboots += 1
    def load_instructions(self, tt):
        for line in tt.split("\n"):
            if "#" in line:
                line = line.split("#")[0]
            line = line.strip()
            if not line:
                continue
            self.instructions.append(Instruction(line))
            if len(self.instructions) > 55:
                print(" !!!!!!!!!!!!!!! TOO MANY INSTRUCTIONS !!!!!!!!!!!!!!!")
                # assert False
    def run(self):
        ins = self.instructions[0]
        for i,v in enumerate(self.secret_vector):
            self.memory[i] = v
        while (self.pc>=0 and self.pc<len(self.instructions) and self.num_of_reboots<4 and self.time_reg<20000):
            # print(self.pprint())
            ins = self.instructions[self.pc]
            self.execute(ins)
    def execute(self, ins):
        '''Execute a single instruction'''

        self.time_reg += 1
        if ins.op == "bp":
            # An additional instruction meant to ease debugging. Simply add a breakpoint
            # in this line in your debugger.
            self.pc += 1
        elif ins.op == "movc":
            self.regs[ins.op2] = ins.imm
            self.pc += 1
        elif ins.op == "magic":
            if self.num_of_reboots == 2:
                # order in comparison is important
                if tuple(self.regs[0:4]) == self.secret_vector:
                    # Loads the flag into the registers. To dump the flag, terminate by doing `halt`
                    with open("flag.txt", "rb") as fp:
                        cc = fp.read()
                    cc = cc.strip()
                    cc = cc.ljust(len(self.regs)*4, b"\x00")
                    for i in range(len(self.regs)):
                        self.regs[i] = struct.unpack("<I", cc[i*4:(i+1)*4])[0]
            self.pc += 1
        elif ins.op == "reset":
            self.reset()
        elif ins.op == "halt":
            self.pc = len(self.instructions)
        elif ins.op == "time":
            self.regs[0] = self.time_reg
            self.pc += 1
        elif ins.op == "jmp":
            nt = self.pc + ins.pc_rel
            assert nt >=0 
            assert nt < len(self.instructions)
            self.pc = nt
        elif ins.op == "jmpz":
            if self.regs[0] == 0:
                nt = self.pc + ins.pc_rel
                assert nt >=0 
                assert nt < len(self.instructions)
                self.pc = nt
            else:
                self.pc += 1
        elif ins.op == "jmpg":
            if self.regs[0] > self.regs[ins.op2]:
                nt = self.pc + ins.pc_rel
                assert nt >=0 
                assert nt < len(self.instructions)
                self.pc = nt
            else:
                self.pc += 1
        elif ins.op == "mov":
            self.regs[ins.op2] = self.regs[ins.op1]
            self.pc += 1
        elif ins.op == "sub":
            v = self.regs[ins.op2] - self.regs[ins.op1]
            self.regs[ins.op2] = (v & 0xffffffff)
            self.pc += 1
        elif ins.op == "add":
            v = self.regs[ins.op2] + self.regs[ins.op1]
            self.regs[ins.op2] = (v & 0xffffffff)
            self.pc += 1
        elif ins.op == "mul":
            v = self.regs[ins.op2] * self.regs[ins.op1]
            self.regs[ins.op2] = (v & 0xffffffff)
            self.pc += 1
        elif ins.op == "and":
            v = self.regs[ins.op2] & self.regs[ins.op1]
            self.regs[ins.op2] = (v & 0xffffffff)
            self.pc += 1
        elif ins.op == "or":
            v = self.regs[ins.op2] | self.regs[ins.op1]
            self.regs[ins.op2] = (v & 0xffffffff)
            self.pc += 1
        elif ins.op == "xor":
            v = self.regs[ins.op2] ^ self.regs[ins.op1]
            self.regs[ins.op2] = (v & 0xffffffff)
            self.pc += 1
        elif ins.op == "movfrom":
            # Small bug:
            # Upon reboot, we do not do `del self.cache[addr]` but instead do
            # self.cache[addr] = 0.
            # keys stay in cache! keys stay in cache! keys stay in cache!
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
        elif ins.op == "movto":
            addr = ins.op_mem + self.regs[ins.dsp]
            addr = addr % len(self.memory)
            if addr in self.cache:
                del self.cache[addr]
            v = (self.regs[ins.op2] & 0xffffffff)
            self.memory[addr] = v
            self.pc += 1
        else:
            assert False
        return 
    def pprint(self, debug=0):
        tstr = ""
        tstr += "%02d> "%self.pc
        tstr += "[%5d] "%self.time_reg
        tstrl = []
        for i,r in enumerate(self.regs):
            tstrl.append("r%d=%3d"%(i,r))
        tstr += ", ".join(tstrl)
        tstr += "\t\t# " + self.instructions[self.pc].str_rep
        if debug>1:
            tstr += "\nM->"
            vv = []
            for i,v in enumerate(self.memory):
                if v!=0:
                    vv.append("%d:%d"%(i,v))
            tstr += ",".join(vv)
            tstr += "\nC->"
            tstr += repr(self.cache)
        return tstr
def main():
    print("Welcome to a very fast VM!")
    print("Give me your instructions.")
    print("To terminate, send 3 consecutive empty lines.")
    instructions = ""
    empty_line_counter = 0
    while True:
        line = input()
        if not line.strip():
            empty_line_counter += 1
        else:
            empty_line_counter = 0
        instructions += line + "\n"
        if empty_line_counter >= 3:
            if len(instructions) > 2000:
                print("!!!!! CODE TOO LONG !!!!!")
                # assert False
            break
    c = Cpu()
    print("Parsing...")
    c.load_instructions(instructions)
    print("Loaded {} instructions".format(len(c.instructions)))
    print("Running...")
    c.run()
    print("Done!")
    print("Registers: " + repr(c.regs)) # prints the flag
    for i in range(4):
        print("r{} = {}".format(i, hex(c.regs[i])))
    print("Mem:")
    for i in range(1000000, 1000010):
        print("[{}] {}".format(i, hex(c.memory[i])))

    print("Goodbye.")
if __name__ == "__main__":
    sys.exit(main())