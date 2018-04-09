# coding:utf-8
import hashlib, string
from pwn import *

#context.log_level = 'debug'
def encr_str(plaintext):
    return hashlib.sha256(plaintext.encode()).hexdigest()

io = remote("202.120.7.206", 13337)

data = io.recvline()[:-1]
#io.recvuntil(":please do not ends with \"\n\"):")
io.recvuntil("):")

part2 = data[12:28]
sha_res = data[32:]

print 'part2', part2
print 'sha256 result', sha_res

log.info('start guess')
flg_guessed = False
for k0 in string.letters+string.digits:
    if flg_guessed:
        break
    for k1 in string.letters+string.digits:
        if flg_guessed:
            break
        for k2 in string.letters+string.digits:
            if flg_guessed:
                break
            for k3 in string.letters+string.digits:
                if flg_guessed:
                    break
                part1 = k0+k1+k2+k3
                tmp = part1 + part2
                guess = encr_str(tmp)
                if guess in sha_res:
                    flg_guessed = True
                    log.success("guess ok")
                    print part1
                    io.send(part1)
                    break

ms = [269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977, 4862378745380642626737318101484977637219057323564658907686653339599714454790559130946320953938197181210525554039710122136086190642013402927952831079021210585653078786813279351784906397934209, 221855981602380704196804518854316541759883857932028285581812549404634844243737502744011549757448453135493556098964216532950604590733853450272184987603430882682754171300742698179931849310347]

io.sendline(str(ms[0]))
io.sendline(str(ms[1]))
io.sendline(str(ms[2]))
io.interactive()

