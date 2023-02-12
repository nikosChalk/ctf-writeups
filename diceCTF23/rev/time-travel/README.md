# time-travel

Categories: Rev

Description:
> This flag calculator has been running for a while...
> 
>author: infuzion
>
>[input.bin](src/input.bin) [time_travel](src/time_travel)
>

**Tags:** rev

## Takeaways

* None - simple reversing.

## Solution

### Reversing

* No remote machine, so flag is probably the output of the program when given `input.bin`
  * Running `./time_travel input.bin` takes forever.
* Input size must match original `input.bin` size, which is exactly 166404 bytes
* Recursive reduction of a NxN matrix to a single value.
  * This is matrix determinant calculation using recursing of an (N-1)x(N-1) matrix
* Approach: lift the binary in python and calculate it using numpy

So, after manual reverse engineering of the binary, we know that it performs matrix determinant calculation. The solution is to understand the format of the `input.bin` and lift the binary by performing the calculation in python. Here is the binary after reverse engineering:

```c
struct segment {
    int matrix_sz;
    long data[18][18];
    char stored_char;
    undefined[3] padding;
}; //0xa28 == 2600 bytes

struct input {
    struct segment segments[64];
    undefined padding[4];
}; //0x28a04 == 166404 bytes == 64*sizeof(struct segment) + 4 bytes

//Allocates an `struct input` object of size 0x28a04
//and reads exactly 0x28a04 bytes from argv[1]
struct input * read_input(char *fname);

//Allocates a NxN matrix and returns it
//The returned result is an array of pointers
long ** alloc_matrix(int N);

int main(int argc,char **argv) {
  struct input *input;
  long **matrix;
  long determinant;
  int i;
  int j;
  
  input = read_input(argv[1]);
  for (int i = 0; i < 0x40; i++) {
    matrix = alloc_matrix(input->segments[0].matrix_sz);

    //row copy
    for (int j = 0; j < input->segments[0].matrix_sz; j++) {
      memcpy(matrix[j], input->segments[i].data + (j*0x12), 0x90);
    }
    determinant = calc_matrix_determinant_recursive(matrix, input->segments[0].matrix_sz);
    putchar(i + (char)(input->segments[i].stored_char - (char)determinant)); //flag character
    fflush(stdout);
  }
  putchar('\n');
  return 0;
}

struct input * read_input(char *fname) {
  size_t sVar1;
  
  struct input *__ptr = (struct input *)malloc(sizeof(struct input)); //0x28a04
  FILE *__stream = fopen(fname,"r");
  if ((__stream != (FILE *)0x0) && (sVar1 = fread(__ptr,sizeof(struct input),1,__stream), sVar1 == 1)) {
    fclose(__stream);
    return __ptr;
  }
  puts("Failed.");
  return NULL;
}
long ** alloc_matrix(int N) {
  long **array = malloc(N*8);
  for (int i = 0; i < N; i = i + 1) {
    array[i] = malloc(N*8);
  }
  return array;
}
```

As we can see from the main program, `input.bin` is just an array of 64 matrices. Each matrix seems to be hardcoded to `0x12` rows where each row is `0x90` bytes. Since `sizeof(long) == 8`, this means that each matrix has 18 rows and columns, so `input->segments[i].matrix_sz == N == 18`.

Each character of the flag depends only on 1 matrix and the current index. So, let's see examine the dependency on the matrix by reversing the function `calc_matrix_determinant_recursive(matrix, N=18);`

```c
//Calculates the determinant of `matrix`, which is a NxN square matrix.
//The computation is performed recursively using Laplace expansion, i.e.:
//The determinant of an NxN matrix A can be computed as a weighted sum of minors, which are the determinants of some (N-1)x(N-1) submatrices of A.
long calc_matrix_determinant_recursive(long **matrix, int N);

//matrix1 is NxN, matrix2 is (N-1)x(N-1)
//Copies from matrix1 to matrix2 all elements, except that:
// * First row of matrix1 is skipped
// * Column `iteration` of matrix1 is skipped
//In terms of linear algebra, we compute the minor `matrix2` from matrix1
void copy_matrix(long **matrix1, int N, long **matrix2, int iteration);

long calc_matrix_determinant_recursive(long **matrix,int N) {
  if (N == 1) //base case
    return **matrix;

  //recursive case.
  long res = 0;
  long sign = 1;
  for (int i=0; i<N; i++) {
    long **matrix2 = alloc_matrix(N-1);  //allocate matrix2 which is (N-1)x(N-1)
    copy_matrix(matrix,N,matrix2,i); //compute minor matrix2 by skipping row 0 and column i
    long sub_det = calc_matrix_determinant_recursive(matrix2, N-1);
    res = res + sub_det * sign * matrix[0][i];
    sign = -sign;
    free_matrix(matrix2, N-1);
  }
  return res;
}

void copy_matrix(long **matrix1, int N, long **matrix2, int iteration) {
  
  for (int m1_i=1, m2_i=0; m1_i<N; m1_i++, m2_i++) {

    for(int m1_j=0, m2_j=0; m1_j<N m1_j++) {
      if (m1_j != iteration) {
        matrix2[m2_i][m2_j++] = matrix1[m1_i][m1_j];
      }
    }
  }
}
```

### Lifting

So, the format of `input.bin` is just an array of 64 elements of `struct segment`

```c
struct segment {
    int matrix_sz;
    long data[18][18];
    char stored_char;
    undefined[3] padding;
}; //0xa28 == 2600 bytes
```

And the flag is 64 characters long and printed using the formula:

```c
for (int i=0; i<0x40; i++) {
  matrix = /* matrix from segment at index i from input.bin */
  determinant = calc_matrix_determinant_recursive(matrix, 18);
  putchar(i + (char)(segments[i].stored_char - (char)determinant)); //flag character
  fflush(stdout);
}
```

For our python implementation, we only have to be careful about overflows and to use 64-bit signed numbers:

```python

import struct
import numpy as np
from ctypes import *

with open("input.bin", 'rb') as f:
    data = f.read()
assert(len(data) == 0x28a04)

flag = ''
N = struct.unpack("<i", data[:4])[0] # 18
print(f"N: {hex(N)}")
for i in range(0x40):
    matrix = np.zeros((N, N))
    matrix_offset = 2600*i
    for k in range(N):
        row_offset = matrix_offset + 4 + k*0x12*8
        for j in range(N):
            offset = row_offset + j*8
            matrix[k][j] = struct.unpack("<q", data[offset:(offset+8)])[0]
    # print(matrix)
    stored_char = c_uint8(data[matrix_offset+2596]).value
    det = np.linalg.det(matrix)
    final_det = c_long(round(det)).value

    print(f"stored_char: {hex(stored_char)}")
    print(f"det        : {det}")
    print(f"final_det  : {final_det}")

    # putchar(i + (char)(input->segments[i].stored_char - (char)determinant));
    res = i + (stored_char - (final_det & 0xff))
    c = c_uint8(res).value
    print(f"res: {res}, c: {c}")
    print(f"chr: {chr(c)}")
    print()
    flag += chr(c)
print(flag)
```

`dice{d3t4rm1n1NanT5_c4n_b3_F4sT_1a7sN2j1867327mA6jmapc817jgd6m0}`
