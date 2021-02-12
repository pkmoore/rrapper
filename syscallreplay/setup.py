"""Compile and install the syscallreplay C extension
"""
from distutils.core import setup, Extension


SYSCALLREPLAY_MOD = Extension('syscallreplay.syscallreplay',
                              ['syscallreplay/syscallreplay.c'],
                              extra_compile_args=['-m32', '-Wall', '--std=c11'])

setup(name='syscallreplay',
      version='0.1',
      packages=['syscallreplay'],
      description='Replay a system call trace through an application',
      ext_modules=[SYSCALLREPLAY_MOD])
