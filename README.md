# Overview

-This repository contains the scripts that work alongside the modified version of rr located [here](https://github.com/pkmoore/rr).

# Requirements

* Supported OS:

```
uname -a Linux dev.local 3.19.0-49-generic #55-Ubuntu SMP Fri Jan 22 02:09:44 UTC 2016 i686 i686 i686 GNU/Linux
```

* ASLR Disabled:

```
echo 0 | sudo tee /proc/sys/kernel/randomize\_va\_space
```

* kernel.randomize\_va\_space = 0 #in /etc/sysctl.d/01-disable-aslr.conf

* Python 2.7.9

* kernel.yama.ptrace\_scope = 0  in /etc/sysctl.d/10-ptrace.conf on modern Ubuntu

* libpython2-dev

* zlib

# Installation

After cloning this repository a few dependencies must be put in place:

First, [posix-omni-parser](http://github.com/pkmoore/posix-omni-parser)
*  This library requires a syscall\_definitions.pickle file be generated using
   the provided script and placed in the base directory (the one with rreplay.py
   etc.)

Second, [syscallreplay](http://github.com/pkmoore/syscallreplay)
* This lbrary must be cloned into the base directory and the C extension it
  contains must be compiled.
* In the syscallreplay directory run python setup.py build\_ext --inplace
* Alternatively, the syscallreplay extension can be complied and installed
  alongside its dependencies somewhere in python's module path


# Usage

## Recording a trace with rr

**tl;dr: rr record -n <command to record>**

By default, rr attempts to buffer system calls for performance reasons.  We need
to disable this functionality when recording so all system calls are present and
can be interacted with.  This is easily accomplished using the **-n** command
line switch.

*Configuration* 

Various aspects replay and injection behavior must be configured in a
configuration file.  The comments in the below code snippet describe required
elements.

```ini
# Top level section specifies global stuff. Right now, the only element in use
# defines the directory containing the rr recording to be used.
[rr_recording]
rr_dir = test/flask-1/
# Each subsequent section describes an rr event during which we want to spin off
# processes and attach an injector.  Each element below is required to tie all
# these pieces together correctly.
[request_handling_process]
# The rr event during which to perform spin off and injection
event = 16154
# The pid amongst the group spun off to which we want to attach the injector.
# This is the pid of the process as recoreded by rr.  The actual pid the spun
# off processes gets will differ.  Mapping between these two is handled
# automatically by rrapper.py
pid = 14350
# The file that contains the strace segment that describes application behavior
# AFTER it has been spun off
trace_file = test/flask_request_snip.strace
# Defines the line that the injector should start with when it takes over for rr
# and begins its work
trace_start = 0
# Defines the last line that the injector should be concerned with.  Once this
# strace line has been handled by the injector, the injector considers its work
# done and the processes associated with this injection are killed cleaned up.
trace_end = 13
```


# Tips

## Identifying the rr Event in which You are Interested

**tl;dr: RR_LOG=ReplaySession rr replay -a**

Setting the RR_LOG environment variable allows you to enable and disable logging
for different parts of rr.  Conveniently, logging only ReplaySession outputs a
listing of system calls as they are handled.  You can use this output to pick
out the system call you are interested (its associated event is listed).

## Generating an Appropriate Strace Segment

**tl;dr strace -f -s 65535 -vvvvv -o <filename> <command>**

For now, the fastest way to get a strace segment to use in driving the injector
is to re-record the application with strace.  Strace segments must have certain
information in order to be used by the system.  The above flags configure strace
to output the current process's pid (-f), don't limit the length of strings (-s
65535) and be as verbose as possible with structures (-vvvvv).  This can result
in huge traces so you should chop out any lines that are not relevant to your
replay efforts.  Because the injector's handling of a process can be rough in
places, you should ask it to handle as small of a segment as is required to
exercise your test case.
