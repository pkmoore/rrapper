#! /usr/bin/env python2
""" Test the UnusualFiletypeMutator
"""

from src.mutator.UnusualFiletype import UnusualFiletypeMutator

import unittest
import mock
import tempfile
import os
from bunch import Bunch


class TestRequiredMethods(unittest.TestCase):
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
