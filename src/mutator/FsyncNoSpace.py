from posix_omni_parser import Trace
import sys
from ..consts import DEFAULT_CONFIG_PATH

class FsyncNoSpaceMutator:


  def __init__(self, name=None):
      self.name = name


  def mutate_trace(self, trace):
    with open(trace, 'r') as f:
      string_lines = f.readlines()
    syscalls = Trace.Trace(trace, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    for k, v in enumerate(syscalls):
      if v.name == 'fsync':
        if self.name:
          if v.args[0].value != self.name:
            continue
        string_lines[k] = string_lines[k].replace(' = 0', ' = -1 ENOSPACE (No space left on device)')
        print(string_lines[k])
    with open(trace, 'w') as f:
      for l in string_lines:
        f.write(l)
