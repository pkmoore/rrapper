''' Tests for the CrossdiskRenameMutator
'''

import unittest
import mock
from bunch import Bunch
import tempfile
from posix_omni_parser import Trace

from ..consts import DEFAULT_CONFIG_PATH

from CrossdiskRename import CrossdiskRenameMutator

class TestIdentify(unittest.TestCase):
  '''Test identify_opportunities
  '''

  def test_identify_with_no_opportunities(self):
    '''CrossdiskRenameMutator should find no opportunities in a trace
    with no stat-like calls
    '''

    trace_data = '''2503  mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e05000
2503  set_thread_area({entry_number:-1, base_addr:0xb7e05700, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0 (entry_number:6)
2503  mprotect(0xb7fb6000, 8192, PROT_READ) = 0
2503  mprotect(0x8049000, 4096, PROT_READ) = 0
2503  mprotect(0xb7ffe000, 4096, PROT_READ) = 0
2503  munmap(0xb7fbc000, 100584)        = 0
'''

    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = CrossdiskRenameMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 0)


  def test_identify_with_one_opportunities(self):
    '''CrossdiskRenameMutator should find one opportunity in a trace with
    one stat-like call

    '''
    trace_data = '''2503  mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e05000
2503  set_thread_area({entry_number:-1, base_addr:0xb7e05700, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0 (entry_number:6)
2503  mprotect(0xb7fb6000, 8192, PROT_READ) = 0
2503  rename("test/test.txt", "test/test2.txt") = 0
2503  mprotect(0x8049000, 4096, PROT_READ) = 0
2503  mprotect(0xb7ffe000, 4096, PROT_READ) = 0
2503  munmap(0xb7fbc000, 100584)        = 0
'''

    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = CrossdiskRenameMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 1)


  def test_identify_with_many_opportunities(self):
    '''CrossdiskRenameMutator should find one opportunity in a trace with
    one stat-like call
    '''

    trace_data = '''2503  mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xb7e05000
2503  set_thread_area({entry_number:-1, base_addr:0xb7e05700, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0 (entry_number:6)
2503  mprotect(0xb7fb6000, 8192, PROT_READ) = 0
2503  rename("test/test.txt", "test/test2.txt") = 0
2503  mprotect(0x8049000, 4096, PROT_READ) = 0
2503  mprotect(0xb7ffe000, 4096, PROT_READ) = 0
2503  munmap(0xb7fbc000, 100584)        = 0
2503  rename("test/test.txt", "test/test2.txt") = 0
'''

    trace_file = tempfile.NamedTemporaryFile()
    trace_file.write(trace_data)
    trace_file.flush()
    syscalls = Trace.Trace(trace_file.name, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    trace_file.close()
    mut = CrossdiskRenameMutator()
    lines = mut.identify_lines(syscalls)
    self.assertEqual(len(lines), 2)
