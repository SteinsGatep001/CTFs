


```
times = 0
while times < 2
case 1: create file ... newfp==0  _has_newfile<=0
filename: /sandbox/md5(input, len(input))
_newfp=fopen, _has_newfile = 1, _times++
case 2: read file   ... newfp==0  _has_newfile<=0
filename: /sandbox/md5(input, len(input))
_newfp=fopen,_has_newfile = 2,  _times++
case 3: go
    _has_newfile==1:   write data(stack overflow), write key ; newfp=_has_newfile=0
    _has_newfile==2:   check key, print data                 ; newfp=_has_newfile=0

```


