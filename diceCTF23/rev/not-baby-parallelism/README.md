# not-baby-parallelism

Categories: Rev

Description:
> According to my timing experiments, sequential is still empirically faster. So being a CTF exercise is just about the only use for this now.
> 
>author: jyu
>
>[pppp](src/pppp) [flag.out](src/flag.out)
>
> Run with `pppp -n [number of threads] -i [input file] -o [output file]`

**Tags:** rev, multi-threaded, C++, no-writeup

## Takeaways

* None - simple reversing with byte-by-byte bruteforce

## Solution

Let's do the usual stuff to recon the binary, run it, and examine its runtime behavior:

```bash
nikos@ctf-box:~/not-baby-parallelism$ file pppp
pppp: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0dd37e51f91b0376cf5dc1ebc830c643a08ec133, for GNU/Linux 3.2.0, stripped
nikos@ctf-box:~/not-baby-parallelism$ checksec --file=./pppp
[*] '~/not-baby-parallelism/pppp'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
nikos@ctf-box:~/not-baby-parallelism$ head flag.out
100
13
110
19
104
30
42
1539
1591
1544

nikos@ctf-box:~/not-baby-parallelism$ ./pppp
0.00055342600000000
nikos@ctf-box:~/not-baby-parallelism$ ./pppp -n 1
0.00041608600000000
nikos@ctf-box:~/not-baby-parallelism$ ./pppp -n 100
0.00987143900000000
nikos@ctf-box:~/not-baby-parallelism$ ./pppp -n 1000
0.06816811200000000
nikos@ctf-box:~/not-baby-parallelism$ ./pppp -n 10000
terminate called after throwing an instance of 'std::system_error'
  what():  Resource temporarily unavailable
Aborted (core dumped)
nikos@ctf-box:~/not-baby-parallelism$ ./pppp -n 5000
0.28532321500000002
nikos@ctf-box:~/not-baby-parallelism$ echo 'dice{dummy}' > input.txt
nikos@ctf-box:~/not-baby-parallelism$ ./pppp -n 1 -i input.txt -o output.txt
0.00048669600000000
nikos@ctf-box:~/not-baby-parallelism$ cat output.txt
<file is empty>
```

Okay, here is what we infer from the above:

* The output seems to be the time that the binary took to execute.
  * The higher the number of threads `n`, the longer it takes to execute
  * For very high `n` values (e.g. 10000), the binary crashes
* The given `flag.out` does not appear to contain ASCII characters.
* We have to reverse the format of the input, as currently the input that we supply seems to wrong as the produced output file is empty.

So, with the above in mind, lets reverse the binary and find out the format of the input:

```c
//Decompile produce from ghidra. Don't read it into detail yet.
int main(int argc,char **argv) {
  char cVar1;
  uint *puVar2;
  basic_ostream *this;
  long *plVar3;
  basic_ostream<char,std::char_traits<char>> *pbVar4;
  char *__format;
  undefined8 local_4a8;
  undefined8 local_4a0;
  void *local_498 [3];
  uint local_47c;
  basic_ostream<char,std::char_traits<char>> local_478 [512];
  basic_istream<char,std::char_traits<char>> local_278 [524];
  int local_6c;
  _Alloc_hider local_68 [46];
  allocator local_3a [2];
  undefined8 local_38;
  undefined8 local_30;
  int local_24;
  int local_20;
  int local_1c;
  
  std::basic_ifstream<char,std::char_traits<char>>::basic_ifstream();
                    /* try { // try from 001024f6 to 001024fa has its CatchHandler @ 001028b2 */
  std::basic_ofstream<char,std::char_traits<char>>::basic_ofstream();
  do {
    while( true ) {
      while( true ) {
        local_24 = getopt(argc,argv,"n:i:o:");
        if (local_24 == -1) {
          std::basic_istream<char,std::char_traits<char>>::operator>>(local_278,(int *)&local_47c);
          srand(local_47c ^ DAT_001081d8);
          FUN_001031f8();
                    /* try { // try from 001026d3 to 001026d7 has its CatchHandler @ 00102879 */
          FUN_00103230((long *)local_498,(long)(int)local_47c);
          FUN_00103214();
          for (local_1c = 0; local_1c < (int)local_47c; local_1c = local_1c + 1) {
            plVar3 = (long *)FUN_001032ea((long *)local_498,(long)local_1c);
                    /* try { // try from 00102715 to 00102811 has its CatchHandler @ 0010288a */
            std::basic_istream<char,std::char_traits<char>>::operator>>(local_278,plVar3);
          }
          local_4a0 = std::chrono::_V2::system_clock::now();
          FUN_001036c3(local_498,FUN_0010330a,FUN_00103323,FUN_0010333a);
          local_4a8 = std::chrono::_V2::system_clock::now();
          local_30 = FUN_00102dd4(&local_4a8,&local_4a0);
          FUN_00103915(&local_30);
          FUN_0010393a(&local_38);
          printf(__format,"%.17f\n");
          for (local_20 = 0; local_20 < (int)local_47c; local_20 = local_20 + 1) {
            plVar3 = (long *)FUN_001032ea((long *)local_498,(long)local_20);
            pbVar4 = (basic_ostream<char,std::char_traits<char>> *)
                     std::basic_ostream<char,std::char_traits<char>>::operator<<(local_478,*plVar3);
            std::basic_ostream<char,std::char_traits<char>>::operator<<
                      (pbVar4,std::endl<char,std::char_traits<char>>);
          }
          FUN_001032a6(local_498);
          std::basic_ofstream<char,std::char_traits<char>>::~basic_ofstream
                    ((basic_ofstream<char,std::char_traits<char>> *)local_478);
          std::basic_ifstream<char,std::char_traits<char>>::~basic_ifstream
                    ((basic_ifstream<char,std::char_traits<char>> *)local_278);
          return 0;
        }
        if (local_24 != 0x6f) break;
        std::basic_ofstream<char,std::char_traits<char>>::open
                  ((char *)local_478,(_Ios_Openmode)optarg);
      }
      if (local_24 < 0x70) break;
LAB_00102611:
      this = std::operator<<((basic_ostream *)std::cerr,"Unknown flag ");
      pbVar4 = (basic_ostream<char,std::char_traits<char>> *)
               std::basic_ostream<char,std::char_traits<char>>::operator<<
                         ((basic_ostream<char,std::char_traits<char>> *)this,local_24);
      std::basic_ostream<char,std::char_traits<char>>::operator<<
                (pbVar4,std::endl<char,std::char_traits<char>>);
    }
    if (local_24 == 0x69) {
                    /* try { // try from 001025bb to 00102697 has its CatchHandler @ 0010289e */
      std::basic_ifstream<char,std::char_traits<char>>::open
                ((char *)local_278,(_Ios_Openmode)optarg);
      cVar1 = std::basic_ifstream<char,std::char_traits<char>>::is_open();
      if (cVar1 != '\x01') {
        std::operator<<((basic_ostream *)std::cerr,"Failed to open input file\n");
      }
    }
    else {
      if (local_24 != 0x6e) goto LAB_00102611;
      std::allocator<char>::allocator();
                    /* try { // try from 00102549 to 0010254d has its CatchHandler @ 00102868 */
      FUN_00103130(local_68,optarg,local_3a);
                    /* try { // try from 0010255f to 00102563 has its CatchHandler @ 00102857 */
      local_6c = FUN_001029f7(local_68,(long *)0x0,10);
      puVar2 = (uint *)FUN_001031d0((int *)&DAT_001081d8,&local_6c);
      DAT_001081d8 = *puVar2;
      std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
                ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_68);
      std::allocator<char>::~allocator((allocator<char> *)local_3a);
    }
  } while( true );
}
```

Ouuf. It seems to be a C++ binary.

[*... After hours of reversing...* ]

See [solution.py](solution.py)

And the flag is:

`dice{p4r411el_pref1x_sc4ns_w0rk_efficient_but_sl0w}`
