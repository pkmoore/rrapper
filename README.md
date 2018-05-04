# Overview

This repository contains the scripts that work alongside the modified version of
rr located [here](https://github.com/pkmoore/rr).

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
