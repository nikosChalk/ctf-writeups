#!/bin/sh
# directory initramfs/ contains the extracted initramfs.cpio.gz

set -e
gcc -static main.c -o main
mv main initramfs

cd initramfs
find . -print0 | cpio --null --create --verbose --format=newc | gzip --best > ../initramfs_patched.cpio.gz
cd -

cp initramfs_patched.cpio.gz /mnt/vm-tmp-shared/tmp-upload/initramfs_patched.cpio.gz
# http://80.113.228.215:53023/initramfs_patched.cpio.gz
