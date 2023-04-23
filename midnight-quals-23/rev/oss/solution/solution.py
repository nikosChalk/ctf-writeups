

import angr
import claripy
import sys
import logging
import signal
import os
from ctypes import *
logging.getLogger('angr.sim_manager').setLevel(logging.DEBUG)

def killmyself():
    os.system('kill %d' % os.getpid())
def sigint_handler(signum, frame):
    print('Stopping Execution for Debug. If you want to kill the programm issue: killmyself()')
    if not "IPython" in sys.modules:
        import IPython
        IPython.embed()
signal.signal(signal.SIGINT, sigint_handler)

p = angr.Project(
    'oss.angr.O0',
    auto_load_libs=False,
)

PREFIX=b'midnight{'
FLAG_LEN=24
symbolic_input = claripy.BVS('input', (FLAG_LEN-len(PREFIX)-1)*8)
initial_state = p.factory.entry_state(
    stdin=claripy.Concat(PREFIX, symbolic_input, b'}')
)
for chop in symbolic_input.chop(8):
    initial_state.solver.add(
        claripy.And(chop >= 0x21, chop < 0x7f) # only printable chars
    )

# find_addr  = p.loader.find_symbol('win')
# avoid_addr = p.loader.find_symbol('fail')

simgr = p.factory.simulation_manager(initial_state)
# simgr.use_technique(angr.exploration_techniques.DFS())
# simgr.explore(find=lambda state: state.addr == find_addr, avoid=lambda state: state.addr == avoid_addr)
simgr.explore(
    find=lambda s: b":)" in s.posix.dumps(1),
    avoid=lambda s: any(x in s.posix.dumps(1) for x in [b"wrong ra", b"wrong rb", b"wrong rc", b":("])
)

print(simgr)
import IPython; IPython.embed();

state = simgr.found[0]
print(state.posix.dumps(0))

# bruteforce checksum
while True:
    inner_res = state.solver.eval(symbolic_input, cast_to=bytes)
    res = PREFIX + inner_res + b'}'
    print(res)
    # satisfy the polynomial rolling hash function
    s1d = 0
    for a2z in range(0, FLAG_LEN):
        s1d = c_uint((s1d * 251) ^ res[a2z]).value
    if(s1d == 0x4E6F76D0):
        print(" [*] correct_checksum")
        break
    else:
        print(" [*] wrong_checksum")
        state.solver.add(symbolic_input != inner_res)

# midnight{0p3N_50rCeRy!!}
# TODO: checkout klee
