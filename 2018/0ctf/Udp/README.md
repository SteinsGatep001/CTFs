

```Python
b *0x0400B45

400b45:
最开始的父进程和所有子进程通信。
子进程先发个0。
while True:
    while True:
        recv all [v1]   # 会检测如果收到的不是自己或者子进程发的，就exit
        v1==2 or <1: exit
        if v1>2: break
        if v1==1: send 2 to k+6000
    if (v1 == 3):
        if id_80140E0==1:
            v2=4
        else:
            v2=5;
            for ( i = 0; i <= 3999; ++i )
                if ( i != id_80140E0 && qword_8014110[i])
                    send 3 to i+6000
                    while(1)
                        recv all [v5]
                        v5==3: send 5 to k1+6000
                        v5!=3: break
                    recv not i+6000: exit;
                    v5==4: qword_8014110[i]--, v2=4; elif v5!=5: exit; 
                    v2==4: break
        if v2==4 and (ntohs(v16)-6000)!=-1 then 8014110[i]++
        send v2 to k+6000
    elif v1!=4:
        exit
                
main:
第一个循环（除去400b45）循环收。非0：exit
倒数第二个循环 send 1。  非2：exit
最后的循环 send 3。    4：flag++，5：print flag，其他：exit

loop
6000 [0][1]--
6001 [1][1]++
flag++

6000 [1]--
6001 [1]++
6002 

```

