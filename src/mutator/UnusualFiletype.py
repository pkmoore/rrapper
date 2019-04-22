from posix_omni_parser import Trace
from mutator import GenericMutator
import sys
import os

DEFAULT_CONFIG_PATH = '~/.crashsim/'

class UnusualFiletypeMutator(GenericMutator):
  def __init__(self, filetype='S_IFREG', name=None, file_descriptor=None):
    if name != None and file_descriptor != None:
      raise ValueError('Both name and file_descriptor cannot be set at the same time')
    self.filetype = filetype
    if name:
      self.name = name
    if file_descriptor:
      self.file_descriptor = int(file_descriptor)


  def mutate_trace(self, trace):
    with open(trace, 'r') as f:
      string_lines = f.readlines()
    syscalls = Trace.Trace(trace, os.path.expanduser(DEFAULT_CONFIG_PATH) + 'syscall_definitions.pickle').syscalls
    lines = self.find_syscall_between_indexes(syscalls, 0, len(syscalls), self._match_statlike)
    line = lines[0]
    # TODO: we only support replacing S_IFREG right now
    string_lines[line] = string_lines[line].replace('S_IFREG', self.filetype)
    with open(trace, 'w') as f:
      for l in string_lines:
        f.write(l)

  def _match_fstat(self, syscall):
      if syscall.name.startswith('fstat'):
        if self.file_descriptor:
          if self.file_descriptor != syscall.args[0].value:
              return False
        return True

  def _match_stat_or_lstat(self, syscall):
      # fstat takes a file descriptor
      # stat and lstat take a name rather than a file descriptor
      if syscall.name.startswith('stat') or syscall.name.startswith('lstat'):
        if self.name:
          if self.name != syscall.args[0].value.strip('"'):
            return False
        return True

  def _match_statlike(self, syscall):
    return self._match_stat_or_lstat(syscall) or self._match_fstat(syscall)
