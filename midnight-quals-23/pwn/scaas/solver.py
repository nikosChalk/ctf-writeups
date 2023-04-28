

import angr
import claripy
import sys
import logging
logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

bin_file = 'scaas' if len(sys.argv) < 2 else sys.argv[1]
p = angr.Project(bin_file, auto_load_libs=False,
    main_opts = {
        'base_addr': 0x10000,
    }
)

symbolic_passwords = []
symbolic_input = claripy.BVS('input', 0)
for k in range(3): # three check functions
    symbolic_passwords.append([])
    for i in range(5):  # each function reads 5 passwords. Each password is 40 bytes.
        # The input will be `0xSSSSSSSSSSSSSSSS\x00<whatever>` where `S` is a symbolic hex digit.
        hex_digits = claripy.BVS(f'passwords_{k}_{i}', 16*8) # 16 hex digits are enough. No need for all 40.
        symbolic_passwords[-1].append(hex_digits)
        get_ulong_sym_buf = claripy.Concat(b'0x', hex_digits, claripy.BVV(0x00, 22*8)) # symbolic input for the get_ulong()
        assert(len(get_ulong_sym_buf)//8 == 40)
        symbolic_input = claripy.Concat(symbolic_input, get_ulong_sym_buf)
assert(len(symbolic_input)//8 == (3*5*40))

initial_state = p.factory.call_state(
    p.loader.find_symbol('unlock_serivce').rebased_addr,
    stdin=symbolic_input
)
for i in range(len(symbolic_passwords)):
    for j in range(len(symbolic_passwords[i])):
        bvs = symbolic_passwords[i][j]
        for k, chop in enumerate(bvs.chop(8)):
            # Add constraints for hex digits. Let's keep our sanity by avoiding weird bases
            # when strtoul() is executed, such as octal... e.g. 0100 would be interpreted in octal
            # and be the value 64 in decimal...
            if k == 0:
                cond = claripy.Or(
                    claripy.And(chop >= ord('1'), chop <= ord('9')),
                    claripy.And(chop >= ord('a'), chop <= ord('f')),
                )
            else:
                cond = claripy.Or(
                    claripy.And(chop >= ord('0'), chop <= ord('9')),
                    claripy.And(chop >= ord('a'), chop <= ord('f')),
                    chop == 0x00 # NULL terminator for the get_ulong()
                )
            initial_state.solver.add(cond)
initial_state.solver.simplify()

find_addr  = p.loader.find_symbol('unlock_serivce').rebased_addr + 0x3f # CALL scaas
avoid_addr = p.loader.find_symbol('unlock_serivce').rebased_addr + 0x46

simgr = p.factory.simulation_manager(initial_state)
simgr.explore(
    find= lambda state: state.addr == find_addr,
    avoid=lambda state: state.addr == avoid_addr
)

state = simgr.found[0]
solution_input = state.posix.dumps(0)
assert(len(solution_input) == (3*5*40))

import IPython; IPython.embed();

evaluated_password = []
for i in range(len(symbolic_passwords)):
    evaluated_password.append([])
    for symbolic_hex_num in symbolic_passwords[i]:
        res = state.solver.eval(symbolic_hex_num, cast_to=bytes)
        res_end = res.find(b'\x00') # find NULL terminator for the get_ulong()
        print(res)
        res = int('0x' + res[:res_end].decode('ascii'), 16)
        print(hex(res))
        evaluated_password[-1].append(res)
    print()
print(evaluated_password)

import IPython; IPython.embed();

with open('solution.txt', 'w') as f:
    for password in evaluated_password:
        for number in password:
            f.write(f'{hex(number)}\n')
