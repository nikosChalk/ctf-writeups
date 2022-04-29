
# Solution, but has <= 55 instructrions.
######################################
# Check if reboot has occurred
movfrom r0 0000000 r1
jmpz 21 # goto label_after_reset

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



