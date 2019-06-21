
from posix_omni_parser.parsers.StraceParser import StraceParser

class Block:
  def __init__(self, trace_path, pickle_file):
    self.path = trace_path
    self.parser = StraceParser(trace_path, pickle_file)
    self.eof = 0

  def read_file(self):
    with open(self.path, 'r') as fh:
      while(self.eof == 0):
        yield self._read_file(fh)
 
  def _read_file(self, file_handle):
    syscalls_list = []
    trace_lines_list = []
    for i in range(1000):
      try:
        trace_line = file_handle.next()
      except StopIteration:
        self.eof = 1
        break
      current_syscall = self.parser.parse_line(trace_line)
      syscalls_list.append(current_syscall)
      trace_lines_list.append(trace_line) 
    return [syscalls_list, trace_lines_list]
 
  def get_block(self):
    for block in self.read_file():
      yield block 
