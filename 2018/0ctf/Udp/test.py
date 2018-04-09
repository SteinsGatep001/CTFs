# coding:utf-8

from pwn import *

path_lst = [[0 for i in range(4000)] for i in range(4000)]

fp = open("dump.dex", "rb")
for i in range(4000):
    for j in range(4000):
        path_lst[i][j] = u64(fp.read(8))
fp.close()

go_list = [0 for i in range(4000)]
k = 0

def factorcal(laststp, nextstp):
    global k, go_list, path_lst
    if laststp>=4000 or nextstp>=4000:
        return -1
    if nextstp== 1:
        go_list[k] = 1
        return path_lst[laststp][nextstp]
    for i in range(1, 4000):
        if i == nextstp:
            continue
        if path_lst[laststp][nextstp]<=0:
            continue
        tmp = factorcal(nextstp, i)
        if tmp == -1:
            continue
        go_list.append(i)
        path_lst[laststp][nextstp] -= min(path_lst[laststp][nextstp], tmp)

res = 0
for i in range(4000):
    go_list[0] = 0
    go_list[1] = i
    k = 0
    res += factorcal(0, i)

