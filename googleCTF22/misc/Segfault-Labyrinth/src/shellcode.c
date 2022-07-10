

void pseudo_solution(unsigned long *base) {
    unsigned long *level = base;
    int i=0;
    while(i<10) {

        int j=0;

        while(j<16) {
            int syscall_res = stat("test", level[j]+0x100); //careful to not overwrite pointers
            if(syscall_res == 0)
                goto breaklabel;
            ++j;
        }
        breaklabel:
        level = level[j];
        ++i;
    }
}
