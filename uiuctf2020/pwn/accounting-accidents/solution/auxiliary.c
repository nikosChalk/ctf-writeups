

/**
 * Auxiliary defining functions that are compiled into a share object, auxiliary.so
 * The the SO is loaded into the GDB to make our life easier when reversing
 * gcc -m32 -g -fPIC -shared -o auxiliary.so auxiliary.c
 */

#include <stdio.h>
#include "node.h"

void inorder_print(struct node* root);
void outer_print(struct node* root);

void inorder_print(struct node* root) {
    if (root == 0x00)
        return;
    inorder_print(root->left);
    printf("%d, ", root->bells_cost);
    inorder_print(root->right);
}

void outer_print(struct node* root) {
    inorder_print(root);
    printf("\n");
}
