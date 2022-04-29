

/*
# Code that performs side-channel
# Assumptions:
#   * r0,r1 - scratch registers
#   * r9 == 3
#   * r6 == address which we want to check if cached
#   * r0 == return value
time
mov     r1 r0           # r1 = timestamp1
movfrom r0 0000000 r6   # check if [r6] is in cache
time                    # r0 = timestamp2

# compare r0,r1
sub r0 r1   # r0 = timestamp2 - timestamp1
sub r0 r9   # r0 = timestamp2 - timestamp1 - 3
# Use result in r0.
# r0 == 0 if [r6] is in cache
# r0 == 1 if [r6] is NOT in cache
*/

int main() {
    if mem[00000] == 0: //i.e. a reboot has occurred
        goto after_reset;

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

    //////////// RESET ////////////

after_reset:
    int secret_counter = 5;
    while(secret_counter > 1) {
        int cache_idx         = (secret_counter*32)-1;
        int recovered_secret  = 0;
        int i                 = 32;
        while(i > 0) {
            t1 = time();
            access memory[cache_idx]
            t2 = time();
            int bit = t2 - t1 - 3;
            //bit == 0 means cached        <==> bit is 1
            //bit == 1 means not cached    <==> bit is 0
            bit = bit ^ 1
            recovered_secret = recovered_secret * 2
            recovered_secret = recovered_secret | bit

            --cache_idx;
            --i;
        }
        store recovered_secret in memory[1000000 + secret_counter]
        --secret_counter;
    }
}

