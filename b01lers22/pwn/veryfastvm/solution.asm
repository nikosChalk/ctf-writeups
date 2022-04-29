
# Solution with no comments to satisfy 2000 characters limitation
movfrom r0 0000000 r1
jmpz 21 
movc r1  4   
movc r6 32   
movc r8  1   
movc r9  2   
mov     r2 r1
mul     r2 r6              
movfrom r3 1048575 r1      
movc    r4 0x00000001      
mov     r0 r4
and     r0 r3   
jmpz    2       
movfrom r0 0000000 r2   
mul     r4 r9   
add     r2 r8   
mov     r0 r4
jmpg r7 -7      
sub     r1 r8
mov     r0 r1
jmpg r7 -15  

reset

movc r1  5   
movc r6 32   
movc r8  1   
movc r9  2   
mov     r2 r1
mul     r2 r6     
sub     r2 r8     
movc    r3 0      
movc    r4 32     
time
mov     r5 r0           
movfrom r0 0000000 r2   
time                    
sub r0 r5
sub r0 r8   
sub r0 r9   
xor r0 r8   
mul r3 r9   
or  r3 r0   
sub     r2 r8   
sub     r4 r8   
mov     r0 r4
jmpg r7 -13      
movto   r3 1000000 r1 
sub     r1 r8
mov     r0 r1
jmpg r8 -22  
movfrom r0 1000002 r7
movfrom r1 1000003 r7
movfrom r2 1000004 r7
movfrom r3 1000005 r7   
magic



