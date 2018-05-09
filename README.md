# Overview

This repository contains the scripts that work alongside the modified version of
rr located [here](https://github.com/pkmoore/rr).

# Requirements

* Supported OS: uname -a Linux dev.local 3.19.0-49-generic #55-Ubuntu SMP Fri Jan 22 02:09:44 UTC 2016 i686 i686 i686 GNU/Linux

* ASLR Disabled: echo 0 | sudo tee /proc/sys/kernel/randomize\_va\_space

* kernel.randomize\_va\_space = 0 #in /etc/sysctl.d/01-disable-aslr.conf

* Python 2.7.9

* kernel.yama.ptrace\_scope = 0  in /etc/sysctl.d/10-ptrace.conf on modern Ubuntu

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
