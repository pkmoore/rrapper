from posix_omni_parser import Trace
import sys
from ..consts import DEFAULT_CONFIG_PATH

class UnusualFiletypeMutator:


  def __init__(self, filetype='S_IFREG', name=None, file_descriptor=None):
    if name != None and file_desciptor != None:
      print('Both name and file_descriptor cannot be set at the same time')
      sys.exit(1)
    self.filetype = filetype
    self.name = name
    self.name = None
    self.file_descriptor = file_descriptor


  def mutate_trace(self, trace):
    with open(trace, 'r') as f:
      string_lines = f.readlines()
    syscalls = Trace.Trace(trace, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    line = self._find_line(syscalls)
    # TODO: we only support replacing S_IFREG right now
    string_lines[line] = string_lines[line].replace('S_IFREG', self.filetype)
    print(string_lines[line])
    for i in string_lines:
      print(i)
    with open(trace, 'w') as f:
      for l in string_lines:
        f.write(l)


  def _find_line(self, syscalls):
    for k, v in enumerate(syscalls):
      # fstat takes a file descriptor
      if v.name.startswith('fstat'):
        if self.file_descriptor:
          if self.file_descriptor != v.args[0].value:
            continue
        return k
      # stat and lstat take a name rather than a file descriptor
      if v.name.startswith('stat') or v.name.startswith('lstat'):
        if self.name:
          if self.name != v.args[0].value:
            continue
        return k


