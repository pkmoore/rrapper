
''' Tests for the FutureTimeMutator
'''

import unittest
import tempfile
from posix_omni_parser import Trace

from ..consts import DEFAULT_CONFIG_PATH

from FutureTime import FutureTimeMutator


class TestIdentify(unittest.TestCase):
  '''Test identify_opportunities
  '''

  def test_identify_with_no_opportunities(self):
    '''FutureTimeMutator should find no opportunities in a trace
    with no time calls
    '''
    trace_data = r'''32473 stat64("/etc/localtime", {st_dev=makedev(8, 1), st_ino=934975, st_mode=S_IFREG|0644, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=8, st_size=2845, st_atime=1559715707 /* 2019-06-04T23:21:47.447272045-0700 */, st_atime_nsec=447272045, st_mtime=1555516381 /* 2019-04-17T08:53:01-0700 */, st_mtime_nsec=0, st_ctime=1556825835 /* 2019-05-02T12:37:15.298850882-0700 */, st_ctime_nsec=298850882}) = 0
32473 write(1, "Current local time and date: Wed Jun  5 19:15:04 2019\n", 54) = 54
32473 nanosleep({tv_sec=5, tv_nsec=0}, 0xbffff298) = 0
'''

    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = FutureTimeMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 0)


  def test_identify_with_one_opportunities(self):
    '''FutureTimeMutator should find one opportunity in a trace with
    one stat-like call
    '''
    trace_data = r'''32473 time([1559787304 /* 2019-06-05T19:15:04-0700 */]) = 1559787304 (2019-06-05T19:15:04-0700)
32473 stat64("/etc/localtime", {st_dev=makedev(8, 1), st_ino=934975, st_mode=S_IFREG|0644, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=8, st_size=2845, st_atime=1559715707 /* 2019-06-04T23:21:47.447272045-0700 */, st_atime_nsec=447272045, st_mtime=1555516381 /* 2019-04-17T08:53:01-0700 */, st_mtime_nsec=0, st_ctime=1556825835 /* 2019-05-02T12:37:15.298850882-0700 */, st_ctime_nsec=298850882}) = 0
32473 write(1, "Current local time and date: Wed Jun  5 19:15:04 2019\n", 54) = 54
32473 nanosleep({tv_sec=5, tv_nsec=0}, 0xbffff298) = 0
'''

    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = FutureTimeMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 1)


  def test_identify_with_many_opportunities(self):
    '''FutureTimeMutator should find one opportunity in a trace with
    one stat-like call
    '''

    trace_data = r'''32473 time([1559787304 /* 2019-06-05T19:15:04-0700 */]) = 1559787304 (2019-06-05T19:15:04-0700)
32473 stat64("/etc/localtime", {st_dev=makedev(8, 1), st_ino=934975, st_mode=S_IFREG|0644, st_nlink=1, st_uid=0, st_gid=0, st_blksize=4096, st_blocks=8, st_size=2845, st_atime=1559715707 /* 2019-06-04T23:21:47.447272045-0700 */, st_atime_nsec=447272045, st_mtime=1555516381 /* 2019-04-17T08:53:01-0700 */, st_mtime_nsec=0, st_ctime=1556825835 /* 2019-05-02T12:37:15.298850882-0700 */, st_ctime_nsec=298850882}) = 0
32473 write(1, "Current local time and date: Wed Jun  5 19:15:04 2019\n", 54) = 54
32473 nanosleep({tv_sec=5, tv_nsec=0}, 0xbffff298) = 0
32473 time([1559787309 /* 2019-06-05T19:15:09-0700 */]) = 1559787309 (2019-06-05T19:15:09-0700)
'''

    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = FutureTimeMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 2)
