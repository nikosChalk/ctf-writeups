/**
 * Definition of an AVL-node used by the accounting software.
 * Code exported by ghidra
 */

typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef unsigned short    word;
typedef struct node node, *Pnode;

struct node {
    int bells_cost;
    struct node * left;
    struct node * right;
    int height;
    char item_name[16]; /* Given 0x15. NULL written at 0x1b */
    void * print_edges_f; /* == 0x80487a6 == &print_edges */
};

