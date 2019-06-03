Interrupted File Descriptor Close
=================================

When the close system call fails, the errno returned is EINTR, the syscall
is reissued. However, sometimes when reissuing the system call, the socket
may not close as intended, leaving it hanging. On top of that, you may 
additionally get an EBADF, a bad file descriptor error. With this mutator, 
close returns -1 with errno set to EINTR. By inserting this return value 
we can see whether or not an application responds to this sitaution.

This anomaly can be injected manually or with a command line similar to:
```
rrtest configure --name=closetest --traceline=65 --event 140 --mutator="CloseInterruptedMutator()"
```
