
import string
import os
import sys

FLAG_LEN = 51
IF_NAME = 'generated_input.txt'
OF_NAME = "output.txt"
prefix = 'dice{'

def readOutput(OF_NAME):
    res = []
    with open(OF_NAME) as f:
        for _ in range(FLAG_LEN):
            num = int(f.readline().strip())
            res.append(num)
    assert(len(res) == FLAG_LEN)
    return res
expected_flag = readOutput("src/flag.out")
# print(expected_flag)

while len(prefix) < FLAG_LEN:
    print(f"Current prefix: {prefix}")
    alphabet = string.printable
    guess_found = False
    for g in alphabet:
        flag = prefix + g + 'A'*(FLAG_LEN-len(prefix)-1-1) + '}'
        assert(len(flag) == FLAG_LEN)
        with open(IF_NAME, 'w') as f:
            f.write(f'{FLAG_LEN}\n')
            for c in flag:
                f.write(f'{ord(c)}\n')
        os.system(f'./src/pppp -n 1 -i {IF_NAME} -o {OF_NAME} > /dev/null')
        output = readOutput(OF_NAME)
        guess_idx = len(prefix)
        if expected_flag[:guess_idx+1] == output[:guess_idx+1]:
            print(f"It is a match! char: {g}")
            guess_found = True
            prefix += g
            break

    if not guess_found:
        print("No guess found!")
        sys.exit(1)
    
    if len(prefix) == FLAG_LEN-1:
        prefix += '}'
        break

print(f"\nFlag: {prefix}")
# dice{p4r411el_pref1x_sc4ns_w0rk_efficient_but_sl0w}
