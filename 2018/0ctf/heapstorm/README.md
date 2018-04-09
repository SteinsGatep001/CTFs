

## heapstrom

in 0ctf moyu

## large/unsorted bin storm attack

### prepare

```C
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

/**     so after overwrite
chunkA in unsorted bin  0x4F1
=================================
0           |   0x4F1
=================================
fd          |   bk
---------------------------------
0           |   target - 0x20
=================================
fd_nextsize |   bk_nextsize
---------------------------------
un          |   un
---------------------------------

chunkB in large bin     0x4E1
=================================
0           |   0x4E1
=================================
fd          |   bk
---------------------------------
0           |   target + 0x08
=================================
fd_nextsize |   bk_nextsize
---------------------------------
0           |   target - 0x18 + 5
---------------------------------
**/
```

### why?

for small bins are null, we `calloc(0x48)` will do something below

```C
for (;; )
    {
      int iters = 0;
      while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
        {
          bck = victim->bk; // target-0x20
          if (__builtin_expect (chunksize_nomask (victim) <= 2 * SIZE_SZ, 0)
              || __builtin_expect (chunksize_nomask (victim)
                                   > av->system_mem, 0))
            malloc_printerr ("malloc(): memory corruption");
          size = chunksize (victim);    // chunkA 0x4F0
            /****....***/
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;   // av->bk = target-0x20
          bck->fd = unsorted_chunks (av);   // (target-0x20+0x10) = av
          /* Take now instead of binning if exact fit */
          if (size == nb)   // size != nb, so... goto else
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                set_non_main_arena (victim);
#if USE_TCACHE  // tcache is not enabled in libc 2.23, 2.24
/** ... **/
#endif
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
#if USE_TCACHE
                }
#endif
            }
            }
          /* place chunk in bin */
          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
```

in else, too long.

> after deeping in source code, we found that for large chunk, largechunk[a+1].size - largechunk[a].size = 0x20, so `victim_index = largebin_index (0x4F0);` will return index to chunkB(size: 0x4E0) (0x4F0>>6 == 0x4E0 >>6)
```C
else
  {
    victim_index = largebin_index (size);   //  chunkB index is 0x43
    bck = bin_at (av, victim_index);    // larege bin point to B
    fwd = bck->fd;      // ptr chunkB
    /* maintain large bins in sorted order */
    if (fwd != bck) // index k's large bin is not null
      {
        /* Or with inuse bit to speed comparisons */
        size |= PREV_INUSE; // chunkA's
        /* if smaller than smallest, bypass loop below */
        assert (chunk_main_arena (bck->bk));    // check size(0x4E1) is in main arena
        if ((unsigned long) (size)
            < (unsigned long) chunksize_nomask (bck->bk))   // chunkA.size > chunkB.size
          {
            fwd = bck;
            bck = bck->bk;
            victim->fd_nextsize = fwd->fd;
            victim->bk_nextsize = fwd->fd->bk_nextsize;
            fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
          }
        else
          {
            assert (chunk_main_arena (fwd));
            while ((unsigned long) size < chunksize_nomask (fwd))
              {
                fwd = fwd->fd_nextsize;
                assert (chunk_main_arena (fwd));
              }
            if ((unsigned long) size
                == (unsigned long) chunksize_nomask (fwd))
              /* Always insert in the second position.  */
              fwd = fwd->fd;
            else
              {//  critical
                victim->fd_nextsize = fwd;  // chunkA[0x20] = p_chunkB
                victim->bk_nextsize = fwd->bk_nextsize; // victim->bk_nextsize(chunkA[0x28]) = target - 0x18 + 5
                fwd->bk_nextsize = victim;      // chunkB[0x28] = p_chunkA
                victim->bk_nextsize->fd_nextsize = victim;  /* *(target - 0x18 + 5 + 0x20) = p_chunkA*/
              }
            bck = fwd->bk;  // bck = chunkB[0x18] (target+0x18)
          }
      }
    else
      victim->fd_nextsize = victim->bk_nextsize = victim;
  }
mark_bin (av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;   // *(target+0x18) = p_A

/**     after that
chunkA in unsorted bin  0x4F1
=================================0x00
0           |   0x4F1
=================================0x10
fd          |   bk
---------------------------------
p_B         |   target+0x18
=================================0x20
fd_nextsize |   bk_nextsize
---------------------------------
p_B         |   target-0x18+5
---------------------------------

chunkB in large bin     0x4E1
=================================0x00
0           |   0x4E1
=================================0x10
fd          |   bk
---------------------------------
0           |   p_A
=================================0x20
fd_nextsize |   bk_nextsize
---------------------------------
0           |   p_A
---------------------------------
**/
```

```C
*(target + 8 - 5) = p_A
/**
if heap address is `0x55xxxxxxxxxx`, the `fake_chunk's` size is 0x55
if heap address is `0x56xxxxxxxxxx`, the `fake_chunk's` size is 0x56
**/
*(target+0x18) = p_A    // target->bk = p_A
```

As the code show above, ` while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))` will loop again.

This time, `unsorted_chunks (av)->bk` is `target-0x20`, size is 0x50(0x55), so `_int_malloc` return target address

After `_int_malloc`, libc do some check more
```C
assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
        av == arena_for_chunk (mem2chunk (mem)));
// chunk_is_mmapped: ((((mchunkptr)((char*)(mem) - 2*(sizeof (size_t)))))->mchunk_size & 0x2)
```

1. mem is not null, failed
2. emmmm
3. `arena_for_chunk` return arena of mem, failed

so, 0x56 will pass this check.

### Last

Just leak address and overwrite ptr, the getshell.

Orz......

