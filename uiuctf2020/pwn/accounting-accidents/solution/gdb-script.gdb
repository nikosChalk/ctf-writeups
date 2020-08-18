
set confirm off
set disassembly-flavor intel

delete breakpoints

b *main
commands $bpnum
    silent
    print (void*) __libc_dlopen_mode("auxiliary.so", 2)
    continue
end


# b *insert+4
# commands $bpnum
#     printf "Beginning of insert\n"
#     set $old_root = *((void **)($esp+12))
#     printf "old_root=0x%08x, item_name=%s\n", $old_root, *((void **)($esp+12+8))
#     #if $old_root != 0x00
#     #    call (void (*)(void*))print_edges($old_root)
#     #end
# end

# b *insert+419
# commands $bpnum
#     set $new_root = $eax
#     printf "End of insert\n"
#     printf "new_root=0x%08x, item_name=%s\n", $new_root, ((char*)($eax)+16)
#     printf "\nBefore:\n"
#     if $old_root != 0x00
#     #    call (void (*)(void*))print_edges($old_root)
#         call (void (*)(void*))outer_print($old_root)
#     end
#     printf "\nAfter:\n"
#     #call (void (*)(void*))print_edges($new_root)
#     call (void (*)(void*))outer_print($new_root)
# end

define hook-stop
    x/3i $eip
    x/8wx $esp
end

b *main+344
# Remember: Stack is nasty and unreliable. The value 0xffffcc24 may change
# depending on your environment variables
commands $bpnum
    printf "Break @ line34: i = 0;\n"
    printf "Current root is 0x%08x\n", *(void**)(0xffffcc24)
    call outer_print(*(struct node**)(0xffffcc24))
end

b *main+552
commands $bpnum
    set $old_root = *(struct node**)($ebp-0x134)
    set $new_root = (struct node*)$eax
    printf "Break @ line44: new_root = insert(new_root,bells_cost,missing_items_name[i]);\n"
    printf "\nBefore:\n"
    call outer_print($old_root)
    printf "\nAfter:\n"
    call outer_print($new_root)
    printf "\n"
end

set confirm on
