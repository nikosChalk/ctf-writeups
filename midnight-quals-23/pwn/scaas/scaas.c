#include <sys/mman.h>
#include <ctype.h>

unsigned int scaas() {
  void *v0; // esp
  int v4; // [esp+0h] [ebp-28h] BYREF
  int n; // [esp+8h] [ebp-20h]
  int v6; // [esp+Ch] [ebp-1Ch]
  char *s; // [esp+10h] [ebp-18h]
  void *code; // [esp+14h] [ebp-14h]
  void *v9; // [esp+18h] [ebp-10h]
  unsigned int v10; // [esp+1Ch] [ebp-Ch]

  v10 = __readgsdword(0x14u);
  n = 500;
  v6 = 499;
  v0 = alloca(512);
  STACK[0x1FC] = STACK[0x1FC];
  char *buf = (char *)&v4;
  printf("Run SCAAS (alphanumeric shellcode, max 500 bytes): ");

  //Reading stops after an EOF or a newline.
  fgets(buf, n, stdin);
  buf[strcspn(buf, "\n")] = '\0'; // NULL terminator
  
  if ( is_alphanumeric(buf) != 1 ) {
    puts("Error: shellcode must be alphanumeric");
  } else {
    code = mmap(
      NULL, n, 
      PROT_READ | PROT_WRITE| PROT_EXEC,
      MAP_PRIVATE | MAP_ANONYMOUS,
      -1, 0
    );
    if ( code == (void *)-1 ) {
      perror("mmap");
    } else {
      memcpy(code, buf, strlen(buf));
      v9 = code;
      ( (void (*)(void))code )(); //invoke shellcode
    }
  }
  return v10 - __readgsdword(0x14u);
}

int is_alphanumeric(char *str) {  
  char *cptr = str;
  while(1) {
    char c = *cptr;
    if (c == 0)
      return 1; //success

    ushort **ppuVar1 = __ctype_b_loc(); //https://stackoverflow.com/questions/37702434/ctype-b-loc-what-is-its-purpose
    if ( ((*ppuVar1)[c] & 8) == 0)
      return 0;
    ++cptr;
  }
}
