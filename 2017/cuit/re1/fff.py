
alph_Ls = [0x73, 0x8D, 0xF2, 0x4C, 0xC7, 0xD4, 0x7B, 0xF7, 0x18, 0x32, 0x71, 0x0D, 0xCF, 0xDC, 0x67, 0x4F, 0x7F, 0x0B, 0x6D]

chk_list = []

for c in alph_Ls:
    chk_list.append(c^0x20)

print "len:", len(chk_list)
res = ""
for i in range(len(chk_list)):
    cp = chk_list[i]
    c = cp^i
    off = i&7
    left = (c<<off)&0xFF
    rigtht = (c>>(8-off))&0xFF
    m = (left|rigtht)&0xFF
    res += chr(m)

print res
