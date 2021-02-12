# syscallreplay


Replay results and side effects of previously recorded system calls

This is a library that works alongside with the rrapper injector in order to perform
record-replay executions of previously recorded system calls

## To compile and install

On an x86-64 machine, gcc will spew out errors about unknown 32-bit registers. As a result,
please compile on a x86 machine.

```
$ sudo python setup.py install
$ python
  ...
  > import syscallreplay
```
