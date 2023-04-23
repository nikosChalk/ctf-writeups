#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

/*
#ifndef FLAG
#error "FLAG is not defined."
#endif
*/

#define Z3K(val)       (((val) << 4) | ((val) >> 4))
#define V5H(val)       (((val) << 1) | ((val) >> 7))
#define S6E(val)       (((val) << 3) ^ ((val) >> 5))

#define XOR(a, b)      ((a) ^ (b))
#define XOR_BYTE(a, b) (((a) ^ (b)) & 0xff) /* XOR to values and keep only the least significant byte */
#define Y2G(a, b)      ((a) & 0x55) | (((b) & 0xaa) >> 1)
#define W4U(a, b)      ((((a) * (b)) % 1257) & 0xff)
#define D7F(a, b)      (((a) << 4) ^ (b))

#define A1C(a, b, c, d) Z3K(W4U(V5H(Z3K(Y2G(V5H(XOR_BYTE(a, b)), V5H(XOR_BYTE(c, d))))), b)) /* Function W */
#define B2D(a, b) V5H(Z3K(XOR_BYTE(a, b)))
#define C3E(a, b) D7F(b, Z3K(XOR_BYTE(a, b)))

typedef unsigned int uint;
uint ra = 1, rb = 1, rc = 1;

#define wrong_ra()        \
  {                       \
    printf("wrong ra\n"); \
    exit(1);              \
  }
#define wrong_rb()        \
  {                       \
    printf("wrong rb\n"); \
    exit(1);              \
  }
#define wrong_rc()        \
  {                       \
    printf("wrong rc\n"); \
    exit(1);              \
  }

#define ra_cond_inc(a, expected) (W4U(V5H(Z3K(a)), ra) == (expected) ? (++ra) : ( wrong_ra() ) )
#define rb_cond_inc(a, expected) (V5H(Z3K(a))          == (expected) ? (++rb) : ( wrong_rb() ) )
#define rc_cond_inc(a, expected) (S6E(a)               == (expected) ? (++rc) : ( wrong_rc() ) )

int main(void) {
  #define FLAG_LEN 24
  char flag[FLAG_LEN+1];
  for(int i=0; i<FLAG_LEN+1; i++)
    flag[i] = 0;
  read(0, flag, FLAG_LEN);

  /* TODO: REMOVE
  uint h8m[] = {
    A1C(flag[19], flag[15], flag[11], flag[4] ),
    A1C(flag[3] , flag[20], flag[10], flag[14]),
    A1C(flag[0] , flag[6] , flag[1] , flag[8] ),
    A1C(flag[17], flag[13], flag[9] , flag[23]),
  };
  uint g7k[] = {
    XOR(C3E(flag[4] , flag[23]), C3E(flag[11], flag[18]) ),
    XOR(C3E(flag[17], flag[10]), C3E(flag[12], flag[7])  ),
    XOR(C3E(flag[15], flag[6]) , C3E(flag[20], flag[1])  ),
    XOR(C3E(flag[22], flag[14]), C3E(flag[5] , flag[3])  ),
    XOR(C3E(flag[9] , flag[0]) , C3E(flag[13], flag[16]) ),
    XOR(C3E(flag[8] , flag[19]), C3E(flag[5] , flag[21]) ),
  };
  */


  /*
  uint p5f[12] = {0x10, 0, 010, 20, 0xe, 014, 0x12, 02, 0x16, 012, 6, 4};
  uint g7k[6]  = {0};
  uint h8m[6]  = {0};
  uint j9n[12] = {0};

  for (uint i = 0; i < FLAG_LEN; i += 4) {
    if (i < 12) {
      j9n[p5f[i + 3] / 2] = B2D(flag[p5f[i + 3]], flag[p5f[i + 3] + 1]);
      g7k[i / 4] = XOR(C3E(flag[i * 2], flag[i * 2 + 2]), C3E(flag[i * 2 + 4], flag[i * 2 + 6]));
      if (i < 4)
        h8m[i / 4] = A1C(flag[i], flag[i + 4], flag[i + 8], flag[i + 12]);
      g7k[(i / 4) + 3] = XOR(C3E(flag[i * 2 + 1], flag[i * 2 + 3]), C3E(flag[i * 2 + 5], flag[i * 2 + 7]));
      j9n[p5f[i + 1] / 2] = B2D(flag[p5f[i + 1]], flag[p5f[i + 1] + 1]);
      j9n[p5f[i + 2] / 2] = B2D(flag[p5f[i + 2]], flag[p5f[i + 2] + 1]);
      if (i == 4)
        h8m[1] = A1C(flag[16], flag[20], flag[1], flag[5]);
      j9n[p5f[i] / 2] = B2D(flag[p5f[i]], flag[p5f[i] + 1]);
    } else {
      if (i < 16) {
        h8m[i / 6] = A1C(flag[i - 3], flag[i + 1], flag[i + 5], flag[i * 2 - 3]);
        h8m[3] = A1C(flag[2], flag[6], flag[10], flag[14]);
      }
      rc_cond_inc(g7k[0], 0x202);
      rc_cond_inc(g7k[1], 0x1aa2);
      rc_cond_inc(g7k[2], 0x5a5);
    }
  }
  */

  uint g7k[6]  = {0};
  uint h8m[6]  = {0};
  uint j9n[12] = {0};
  
  g7k[0] = XOR(C3E(flag[0] , flag[2]) , C3E(flag[4] , flag[6]) );
  rc_cond_inc(g7k[0], 0x202);

  g7k[1] = XOR(C3E(flag[8] , flag[10]), C3E(flag[12], flag[14]));
  rc_cond_inc(g7k[1], 0x1aa2);

  g7k[2] = XOR(C3E(flag[16], flag[18]), C3E(flag[20], flag[22]));
  rc_cond_inc(g7k[2], 0x5a5);
  rc=10; //avoid the remaining repetitive calls

  printf("correct rc 1/2\n");

  /*
  h8m[4] = A1C(flag[rc * 2 - ra - rb], flag[rc * 2 + ra + rb], flag[ra * 3], flag[rb * 7]);
  h8m[5] = A1C(flag[rc + ra], flag[rc + 5], flag[rc * 2 - rb], flag[rc * 2 + 3]);
  */

  h8m[0] = A1C(flag[0] , flag[4] , flag[8] , flag[12]);
  ra_cond_inc(h8m[0], 0x5B);

  h8m[1] = A1C(flag[16], flag[20], flag[1] , flag[5] );
  ra_cond_inc(h8m[1], 13);

  h8m[2] = A1C(flag[9] , flag[13], flag[17], flag[21]);
  ra_cond_inc(h8m[2], 0x5D);

  h8m[3] = A1C(flag[2] , flag[6] , flag[10], flag[14]);
  ra_cond_inc(h8m[3], 0244);

  h8m[4] = A1C(flag[18], flag[22], flag[3] , flag[7]);
  ra_cond_inc(h8m[4], 52);

  h8m[5] = A1C(flag[11], flag[15], flag[19], flag[23]);
  ra_cond_inc(h8m[5], 0xDC);

  printf("correct ra\n");

  

  j9n[0]  = B2D(flag[0] , flag[1] );
  rb_cond_inc(j9n[0], 0x1010);

  j9n[1]  = B2D(flag[2] , flag[3] );
  rb_cond_inc(j9n[1], 024050);

  j9n[2]  = B2D(flag[4] , flag[5] );
  rb_cond_inc(j9n[2], 034070);

  j9n[3]  = B2D(flag[6] , flag[7] );
  rb_cond_inc(j9n[3], 28784);

  j9n[4]  = B2D(flag[8] , flag[9] );
  rb_cond_inc(j9n[4], 0x12d2d);

  j9n[5]  = B2D(flag[10], flag[11]);
  rb_cond_inc(j9n[5], 0x10d0d);

  j9n[6]  = B2D(flag[12], flag[13]);
  rb_cond_inc(j9n[6], 042104);

  j9n[7]  = B2D(flag[14], flag[15]);
  rb_cond_inc(j9n[7], 012024);

  j9n[8]  = B2D(flag[16], flag[17]);
  rb_cond_inc(j9n[8], 0xc4c4);

  j9n[9]  = B2D(flag[18], flag[19]);
  rb_cond_inc(j9n[9], 0156334);

  j9n[10] = B2D(flag[20], flag[21]);
  rb_cond_inc(j9n[10], 0x16161);

  j9n[11] = B2D(flag[22], flag[23]);
  rb_cond_inc(j9n[11], 0270561);

  rb_cond_inc(B2D(flag[20], flag[23]), 4112);
  rb_cond_inc(B2D(flag[14], flag[0]), 90465);

  printf("correct rb\n");

  g7k[3] = XOR(C3E(flag[1] , flag[3]) , C3E(flag[5] , flag[7]) );
  rc_cond_inc(g7k[3], 03417);

  g7k[4] = XOR(C3E(flag[9] , flag[11]), C3E(flag[13], flag[15]));
  rc_cond_inc(g7k[4], 0x3787);

  g7k[5] = XOR(C3E(flag[17], flag[19]), C3E(flag[21], flag[23]));
  rc_cond_inc(g7k[5], 030421);

  printf("correct rc 2/2\n");

  //enable checksum. We can also bruteforce it.
  /*
  uint s1d = 0;
  for (uint i = 0; i < FLAG_LEN; i++)
    s1d = (s1d * 251) ^ flag[i];
  
  if (s1d == 0x4E6F76D0)
    printf(":)\n");
  else
    printf(":(\n");
  */

  printf(":)\n"); //checksum disabled

  return 0;
}
