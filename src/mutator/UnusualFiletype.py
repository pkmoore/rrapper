from mutator import GenericMutator 
from MutationError import MutationError
import re

class UnusualFiletypeMutator(GenericMutator):
  def __init__(self, filetype='S_IFREG', name=None, file_descriptor=None):
    if name is not None and file_descriptor is not None:
      raise MutationError('Cannot specify both a name and a file_descriptor')
    self.filetype = filetype
    self.name = name
    self.file_descriptor = file_descriptor


  def mutate_syscalls(self, syscalls):
    index = self._find_index(syscalls)
    # TODO: posix-omni-parser does not parse stat-like calls correctly.
    # This means we cannot be sure the st_mode member will always be in the same place.
    # As a result, we must iterate through all of the arguments to find it.
    for i in range(len(syscalls[index].args)):
      if 'st_mode' in str(syscalls[index].args[i].value):
        syscalls[index].args[i].value=re.sub(r'S_IF(\w*)', self.filetype, syscalls[index].args[i].value)


  def _find_index(self, syscalls):
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


  def identify_lines(self, tm, que):
    while v = self.next_syscall():
      # fstat takes a file descriptor
      if v.name.startswith('fstat'):
        if self.file_descriptor:
          if self.file_descriptor != v.args[0].value:
            continue
        self.opportunity_identified(v, que)
      # stat and lstat take a name rather than a file descriptor
      if v.name.startswith('stat') or v.name.startswith('lstat'):
        if self.name:
          if self.name != v.args[0].value:
            continue
        self.opportunity_identified(v, que):

