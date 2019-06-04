from posix_omni_parser import Trace
import sys
from ..consts import DEFAULT_CONFIG_PATH

class ReverseTimeMutator:


  def __init__(self, seconds=100):
      self.seconds = seconds


  def mutate_trace(self, trace):
    with open(trace, 'r') as f:
      string_lines = f.readlines()
    syscalls = Trace.Trace(trace, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    for k, v in enumerate(syscalls):
      if v.name == 'time':
        string_lines[k] = string_lines[k].replace(str(v.ret[0]), str(int(v.ret[0])-self.seconds))
    with open(trace, 'w') as f:
      for l in string_lines:
        f.write(l)

  def identify_lines(self,trace):
    lines = []
    with open(trace, 'r') as f:
      string_lines = f.readlines()
    syscalls = Trace.Trace(trace, DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle').syscalls
    for k, v in enumerate(syscalls):
      if v.name == 'time':
        lines.append(k)
    return lines