"""
<Program Name>
  Block

<Started>
  June 2019

<Author>
  Junjie Ge

<Purpose>
  Every block is a "window" within all the syscalls, the purpose of each of the
  block is to divide the syscalls into multiple blocks in case we identify
  too many syscalls for one program. Breaking it into blocks potentially makes
  the mutators run faster

"""

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

    # define the window to be a constant. The block is smaller if the remaining
    # lines is less than that constant
    for i in range(1000):
      try:
        trace_line = file_handle.next()
      except StopIteration:
        self.eof = 1
        break
      
      # parses the strace line by line
      current_syscall = self.parser.parse_line(trace_line)
      syscalls_list.append(current_syscall)
      trace_lines_list.append(trace_line) 

    return [syscalls_list, trace_lines_list]
 
  def get_block(self):
    for block in self.read_file():
      yield block 
