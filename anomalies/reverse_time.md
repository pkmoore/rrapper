Reverse Time
===============

This anomaly appears when subset time-related calls return a time EARLIER
than a previous call.  This can happen because the system clock changed,
NTP stepped in, or a variety of other factors.  Applications should check
for this sitauation and handle it gracefully.

This anomaly is simple to inject.  Simply modify the time returned by the
call in question.

```
8406  time(NULL)                        = 1542050714 (2018-11-12T11:41:54-0800)
8406  fstat64(1, {st_dev=makedev(0, 21), st_ino=13, st_mode=S_IFCHR|0620, st_nlink=1, st_uid=1000, st_gid=5, st_blksize=1024, st_blocks=0, st_rdev=makedev(136, 10), st_atime=1542051712 /* 2018-11-12T11:41:52.633977815-0800 */, st_atime_nsec=633977815, st_mtime=1542051712 /* 2018-11-12T11:41:52.633977815-0800 */, st_mtime_nsec=633977815, st_ctime=1541621747 /* 2018-11-07T12:15:47.633977815-0800 */, st_ctime_nsec=633977815}) = 0
8406  brk(NULL)                         = 0x804b000
8406  brk(0x806c000)                    = 0x806c000
8406  write(1, "1542051714\n", 11)      = 11
8406  time([1542050014 /* 2018-11-12T11:41:54-0800 */]) = 1542050014 (2018-11-12T11:41:54-0800)
8406  write(1, "1542051714\n", 11)      = 11
```

In the above trace, the second time() call has been modified so that it
returns a time 700 seconds earlier than the previous time() call.  This can
be done manually or with the ReverseTimeMutator with a command line similar
to:

```
rrtest configure --name=gtodtest --traceline=65 --event=140 --sniplen=7 --mutator="ReverseTimeMutator(1000)"
```


