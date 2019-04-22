#! /usr/bin/env python2
""" Test the UnusualFiletypeMutator
"""

from __future__ import print_function

from src.mutator.UnusualFiletype import UnusualFiletypeMutator

import unittest
import mock
import tempfile
import os
from bunch import Bunch


class TestNonIFDIRMutations(unittest.TestCase):
  def test_init_both_name_and_file_descriptor(self):
    self.assertRaises(UnusualFiletypeMutator, name='test.txt',
                                              file_descriptor=3)

  def test_mutate_stat_call(self):
    stat_str = '90731 stat("test.txt", {st_dev=makedev(8, 1), st_ino=1182892, st_mode=S_IFREG|0664, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=5, st_atime=1555962159 /* 2019-04-22T20:42:39.955603803+0100 */, st_atime_nsec=955603803, st_mtime=1555962159 /* 2019-04-22T20:42:39.955603803+0100 */, st_mtime_nsec=955603803, st_ctime=1555962159 /* 2019-04-22T20:42:39.955603803+0100 */, st_ctime_nsec=955603803}) = 0'

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(stat_str)
    tmp.close()
    mutator = UnusualFiletypeMutator(filetype='S_IFCHR', name='test.txt')
    mutator.mutate_trace(tmp.name)
    with open(tmp.name) as f:
      data = f.readlines()
      line = data[0]
      self.assertTrue('S_IFCHR' in line)
    os.unlink(tmp.name)


  def test_mutate_lstat_call(self):
    stat_str = '90731 lstat("test.txt", {st_dev=makedev(8, 1), st_ino=1182892, st_mode=S_IFREG|0664, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=5, st_atime=1555962159 /* 2019-04-22T20:42:39.955603803+0100 */, st_atime_nsec=955603803, st_mtime=1555962159 /* 2019-04-22T20:42:39.955603803+0100 */, st_mtime_nsec=955603803, st_ctime=1555962159 /* 2019-04-22T20:42:39.955603803+0100 */, st_ctime_nsec=955603803}) = 0'

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(stat_str)
    tmp.close()
    mutator = UnusualFiletypeMutator(filetype='S_IFCHR', name='test.txt')
    mutator.mutate_trace(tmp.name)
    with open(tmp.name) as f:
      data = f.readlines()
      line = data[0]
      self.assertTrue('S_IFCHR' in line)
    os.unlink(tmp.name)



  def test_mutate_fstat_call(self):
    stat_str = '90731 fstat(3, {st_dev=makedev(8, 1), st_ino=1182892, st_mode=S_IFREG|0664, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=5, st_atime=1555962159 /* 2019-04-22T20:42:39.955603803+0100 */, st_atime_nsec=955603803, st_mtime=1555962159 /* 2019-04-22T20:42:39.955603803+0100 */, st_mtime_nsec=955603803, st_ctime=1555962159 /* 2019-04-22T20:42:39.955603803+0100 */, st_ctime_nsec=955603803}) = 0'

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(stat_str)
    tmp.close()
    mutator = UnusualFiletypeMutator(filetype='S_IFCHR', file_descriptor=3)
    mutator.mutate_trace(tmp.name)
    with open(tmp.name) as f:
      data = f.readlines()
      line = data[0]
      self.assertTrue('S_IFCHR' in line)
    os.unlink(tmp.name)


class TestIFDIRMutations(unittest.TestCase):
  def test_mutate_stat_call(self):
    calls_str = r'''118798 stat("test.txt", {st_dev=makedev(8, 1), st_ino=1182893, st_mode=S_IFREG|0664, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=5, st_atime=1555971967 /* 2019-04-22T23:26:07.806253267+0100 */, st_atime_nsec=806253267, st_mtime=1555971967 /* 2019-04-22T23:26:07.806253267+0100 */, st_mtime_nsec=806253267, st_ctime=1555971967 /* 2019-04-22T23:26:07.806253267+0100 */, st_ctime_nsec=806253267}) = 0
118798 openat(AT_FDCWD, "test.txt", O_RDONLY) = 3
118798 fadvise64(3, 0, 0, POSIX_FADV_SEQUENTIAL) = 0
118798 read(3, "test\n", 16384)         = 5
118798 openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache", O_RDONLY) = 4
118798 mmap(NULL, 26376, PROT_READ, MAP_SHARED, 4, 0) = 0x7ffff7ff0000
118798 close(4)                         = 0
118798 read(3, "", 16384)               = 0
118798 write(1, "1 1 5 test.txt\n", 15) = 15
118798 close(3)                         = 0
118798 close(1)                         = 0
118798 close(2)                         = 0
118798 exit_group(0)                    = ?
'''
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(calls_str)
    tmp.close()
    mutator = UnusualFiletypeMutator(filetype='S_IFDIR', name='test.txt')
    mutator.mutate_trace(tmp.name)
    with open(tmp.name) as f:
      lines = f.readlines()
      self.assertTrue(' = -1 EISDIR\n' in lines[3])
      self.assertTrue(' = -1 EISDIR\n' in lines[7])
