Weird Filetypes
===============

This environmental anomaly appears when a file an applicaiton depends on is
of a different Linux file type than the appication is expecting.  This
anomaly can be injected by modifying the st_mode member of the stat
structure returned by one of the system calls of the "stat" family.  For
more information check out the (man page)[https://linux.die.net/man/2/stat].

For example, the below stat() call indicates that /etc/localtime is a
regular file (S_IFREG) with 0644 as its permissions.
```
14435 stat64("/etc/localtime", {st_dev=makedev(8, 1), st_ino=790755, st_mode=S_IFREG|0644, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=8, st_size=2845, st_atime=2018/04/29-13:30:53.769404451, st_mtime=2017/11/09-16:00:05, st_ctime=2017/11/16-12:19:50.704847991}) = 0
```

This anomaly can cause problems in applications that read() from a file
without checking the st_mode.

Possible values and their usual result:

| Value    | File Type        | Possible bad behavior
| ---      | ---              | --- 
| S_IFREG  | Regular File     | Most applications expect/assume this type
| S_IFDIR  | Directory        | Future read()'s, write()'s, etc will fail with EISDIR
| S_IFCHR  | Character Device | Possible crashes/hangs
| S_IFBLK  | Block Device     | Possible crash/hangs, these can be "infinitely large" (/dev/urandom, /dev/zero)
| S_IFIFO  | FIFO Pipe        | Application will hang waiting for the pipe to receive data
| S_IFLNK  | Symbolic Link    | Symlinks are good for tricking an application into processing one of the other filetypes
| S_IFSOCK | Socket           | ??? Needs more experimenting

This anomaly can be injected manually or with a command line similar to:
```
rrtest configure --event 714 --name aspell --traceline 352 --mutator='UnusualFiletypeMutator("S_IFBLK")'
```
