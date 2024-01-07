
set exception-verbose on
set show-tips off

# Command: SIGN_CLASS_STUDENT. First call to TEE_MemMove:
#   TEE_MemMove(curSignedStudent,student1,0x10);
breakrva 0x14b8 grade_ta.so

command
vmmap $rsi -B2 -A2
end

# Command: SIGN_STUDENT. First and second calls to TEE_CheckMemoryAccessRights:
#  TVar1 = TEE_CheckMemoryAccessRights(5,student2,(params->memref).size);
#  TVar1 = TEE_CheckMemoryAccessRights(5,curSignedStudent,sz);
breakrva 0x1667 grade_ta.so
breakrva 0x1685 grade_ta.so

# set context-output /dev/null

# continue
