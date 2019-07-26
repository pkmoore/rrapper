''' Tests for the FsyncNoSpaceMutator
'''

import unittest
import mock
from bunch import Bunch
import tempfile
from posix_omni_parser import Trace

from ..consts import DEFAULT_CONFIG_PATH

from FsyncNoSpace import FsyncNoSpaceMutator

class TestIdentify(unittest.TestCase):
  '''Test identify_opportunities
  '''

  def test_identify_with_no_opportunities(self):
    '''FsyncNoSpaceMutator should find no opportunities in a trace
    with no stat-like calls
    '''

    trace_data = r''' 5414  munmap(0xb7fbc000, 100584)        = 0
5414  fstat64(1, {st_dev=makedev(0, 21), st_ino=13, st_mode=S_IFCHR|0620, st_nlink=1, st_uid=1000, st_gid=5, st_blksize=1024, st_blocks=0, st_rdev=makedev(136, 10), st_atime=2019/06/06-10:29:52.005720855, st_mtime=2019/06/06-10:29:52.005720855, st_ctime=2019/06/05-19:12:41.005720855}) = 0
5414  brk(NULL)                         = 0x804b000
5414  brk(0x806c000)                    = 0x806c000
5414  write(1, "Fsync please!\n", 14)   = 14
'''
    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = FsyncNoSpaceMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 0)


  def test_identify_with_one_opportunities(self):
    '''FsyncNoSpaceMutator should find one opportunity in a trace with
    one stat-like call
    '''

    trace_data = r''' 5414  munmap(0xb7fbc000, 100584)        = 0
5414  fstat64(1, {st_dev=makedev(0, 21), st_ino=13, st_mode=S_IFCHR|0620, st_nlink=1, st_uid=1000, st_gid=5, st_blksize=1024, st_blocks=0, st_rdev=makedev(136, 10), st_atime=2019/06/06-10:29:52.005720855, st_mtime=2019/06/06-10:29:52.005720855, st_ctime=2019/06/05-19:12:41.005720855}) = 0
5414  brk(NULL)                         = 0x804b000
5414  brk(0x806c000)                    = 0x806c000
5414  write(1, "Fsync please!\n", 14)   = 14
5414  fsync(0)                          = 0
'''
    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = FsyncNoSpaceMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 1)


  def test_identify_with_many_opportunities(self):
    '''FsyncNoSpaceMutator should find one opportunity in a trace with
    one stat-like call
    '''

    trace_data = r'''5414  munmap(0xb7fbc000, 100584)        = 0
5414  fstat64(1, {st_dev=makedev(0, 21), st_ino=13, st_mode=S_IFCHR|0620, st_nlink=1, st_uid=1000, st_gid=5, st_blksize=1024, st_blocks=0, st_rdev=makedev(136, 10), st_atime=2019/06/06-10:29:52.005720855, st_mtime=2019/06/06-10:29:52.005720855, st_ctime=2019/06/05-19:12:41.005720855}) = 0
5414  brk(NULL)                         = 0x804b000
5414  brk(0x806c000)                    = 0x806c000
5414  write(1, "Fsync please!\n", 14)   = 14
5414  fsync(0)                          = 0
5414  fsync(0)                          = 0
5414  fsync(0)                          = 0
'''

    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = FsyncNoSpaceMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 3)
