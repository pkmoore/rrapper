
''' Tests for the UnusualFiletypeMutator
'''

import unittest
import mock
from bunch import Bunch
import tempfile
from posix_omni_parser import Trace

from ..consts import DEFAULT_CONFIG_PATH

from UnusualFiletype import UnusualFiletypeMutator

class TestIdentify(unittest.TestCase):
  '''Test identify_opportunities
  '''

  def test_identify_with_no_opportunities(self):
    '''UnusualFiletypeMutator should find no opportunities in a trace
    with no stat-like calls
    '''
    trace_data = '''28725 close(1)                          = 0
28725 utimensat(AT_FDCWD, ".data.txt.TziqM5", [UTIME_NOW, {1525649303, 124679220}], AT_SYMLINK_NOFOLLOW) = 0
28725 chmod(".data.txt.TziqM5", 0664)   = 0
28725 rename(".data.txt.TziqM5", "data.txt") = 0
28725 _newselect(5, [0], [4], [0], {60, 0}) = 1 (out [4], left {59, 999997})
28725 write(4, "\4\0\0k\1\0\0\0", 8)    = 8
28725 _newselect(1, [0], [], [0], {60, 0}) = 1 (in [0], left {59, 999998})
28725 read(0, "\1\0\0\7\0", 32768)      = 5
28725 munmap(0xb7b36000, 266240)        = 0
28725 munmap(0xb7bc8000, 135168)        = 0'''
    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = UnusualFiletypeMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 0)


  def test_identify_with_one_opportunities(self):
    '''UnusualFiletypeMutator should find one opportunity in a trace with
    one stat-like call
    '''
    trace_data = '''28725 close(1)                          = 0
28725 lstat64(".data.txt.TziqM5", {st_dev=makedev(8, 1), st_ino=50795, st_mode=S_IFREG|0600, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=13, st_atime=2018/05/06-16:29:03.502410913, st_mtime=2018/05/06-16:29:03.502410913, st_ctime=2018/05/06-16:29:03.502410913}) = 0
28725 utimensat(AT_FDCWD, ".data.txt.TziqM5", [UTIME_NOW, {1525649303, 124679220}], AT_SYMLINK_NOFOLLOW) = 0
28725 chmod(".data.txt.TziqM5", 0664)   = 0
28725 rename(".data.txt.TziqM5", "data.txt") = 0
28725 _newselect(5, [0], [4], [0], {60, 0}) = 1 (out [4], left {59, 999997})
28725 write(4, "\4\0\0k\1\0\0\0", 8)    = 8
28725 _newselect(1, [0], [], [0], {60, 0}) = 1 (in [0], left {59, 999998})
28725 read(0, "\1\0\0\7\0", 32768)      = 5
28725 munmap(0xb7b36000, 266240)        = 0
28725 munmap(0xb7bc8000, 135168)        = 0'''
    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = UnusualFiletypeMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 1)


  def test_identify_with_many_opportunities(self):
    '''UnusualFiletypeMutator should find one opportunity in a trace with
    one stat-like call
    '''
    trace_data = '''28725 close(1)                          = 0
28725 lstat64(".data.txt.TziqM5", {st_dev=makedev(8, 1), st_ino=50795, st_mode=S_IFREG|0600, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=13, st_atime=2018/05/06-16:29:03.502410913, st_mtime=2018/05/06-16:29:03.502410913, st_ctime=2018/05/06-16:29:03.502410913}) = 0
28725 lstat64(".data.txt.TziqM5", {st_dev=makedev(8, 1), st_ino=50795, st_mode=S_IFREG|0600, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=13, st_atime=2018/05/06-16:29:03.502410913, st_mtime=2018/05/06-16:29:03.502410913, st_ctime=2018/05/06-16:29:03.502410913}) = 0
28725 lstat64(".data.txt.TziqM5", {st_dev=makedev(8, 1), st_ino=50795, st_mode=S_IFREG|0600, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=13, st_atime=2018/05/06-16:29:03.502410913, st_mtime=2018/05/06-16:29:03.502410913, st_ctime=2018/05/06-16:29:03.502410913}) = 0
28725 utimensat(AT_FDCWD, ".data.txt.TziqM5", [UTIME_NOW, {1525649303, 124679220}], AT_SYMLINK_NOFOLLOW) = 0
28725 chmod(".data.txt.TziqM5", 0664)   = 0
28725 rename(".data.txt.TziqM5", "data.txt") = 0
28725 _newselect(5, [0], [4], [0], {60, 0}) = 1 (out [4], left {59, 999997})
28725 write(4, "\4\0\0k\1\0\0\0", 8)    = 8
28725 _newselect(1, [0], [], [0], {60, 0}) = 1 (in [0], left {59, 999998})
28725 read(0, "\1\0\0\7\0", 32768)      = 5
28725 munmap(0xb7b36000, 266240)        = 0
28725 munmap(0xb7bc8000, 135168)        = 0'''
    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = UnusualFiletypeMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 3)

  def test_mutate_syscall_replace_SIFREG_with_SIF(self):
    ''' UnusualFiletypeMutator should mutate S_IFREG to S_IF
    '''
    trace_data = '28725 lstat64(".data.txt.TziqM5", {st_dev=makedev(8, 1), st_ino=50795, st_mode=S_IFREG|0600, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=13, st_atime=2018/05/06-16:29:03.502410913, st_mtime=2018/05/06-16:29:03.502410913, st_ctime=2018/05/06-16:29:03.502410913}) = 0'
    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = UnusualFiletypeMutator('S_IF')
    mut.mutate_syscalls(syscalls)
    test_trace_data = '28725 lstat64(".data.txt.TziqM5", {st_dev=makedev(8, 1), st_ino=50795, st_mode=S_IF|0600, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=13, st_atime=2018/05/06-16:29:03.502410913, st_mtime=2018/05/06-16:29:03.502410913, st_ctime=2018/05/06-16:29:03.502410913}) = 0'
    test_trace_file = tempfile.NamedTemporaryFile()
    test_trace_file.write(test_trace_data)
    test_trace_file.flush()
    test_syscalls = Trace.Trace(test_trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    test_trace_file.close()
    for i in range(len(syscalls[0].args)):
      self.assertEqual(syscalls[0].args[i].value, test_syscalls[0].args[i].value)

  def test_mutate_syscall_replace_SIF_with_SIFREG(self):
    ''' UnusualFiletypeMutator should mutate S_IF to S_IFREG
    '''
    trace_data = '28725 lstat64(".data.txt.TziqM5", {st_dev=makedev(8, 1), st_ino=50795, st_mode=S_IF|0600, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=13, st_atime=2018/05/06-16:29:03.502410913, st_mtime=2018/05/06-16:29:03.502410913, st_ctime=2018/05/06-16:29:03.502410913}) = 0'
    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = UnusualFiletypeMutator('S_IFREG')
    mut.mutate_syscalls(syscalls)
    test_trace_data = '28725 lstat64(".data.txt.TziqM5", {st_dev=makedev(8, 1), st_ino=50795, st_mode=S_IFREG|0600, st_nlink=1, st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=8, st_size=13, st_atime=2018/05/06-16:29:03.502410913, st_mtime=2018/05/06-16:29:03.502410913, st_ctime=2018/05/06-16:29:03.502410913}) = 0'
    test_trace_file = tempfile.NamedTemporaryFile()
    test_trace_file.write(test_trace_data)
    test_trace_file.flush()
    test_syscalls = Trace.Trace(test_trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    test_trace_file.close()
    for i in range(len(syscalls[0].args)):
      self.assertEqual(syscalls[0].args[i].value, test_syscalls[0].args[i].value)

