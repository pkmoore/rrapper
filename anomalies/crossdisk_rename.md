Cross-disk Rename
=================

The best way to rename (i.e. move) a file under Linux is with the rename()
system call.  It ensures that all the necessary steps are correctly carried
out in an atomic fashion.  However, this system call is not able to move a
file from one disk to another.  In this situation, it returns -1 with errno
set to EXDEV.  By inserting this return value we can see whether or not an
application responds to this sitaution.

This anomaly can be injected manually or with a command line similar to:
```
rrtest configure --name=renametest --traceline=65 --event 140 --mutator="CrossdiskRenameMutator()"
```
