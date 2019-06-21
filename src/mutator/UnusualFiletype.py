from mutator import GenericMutator
from MutationError import MutationError


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
    for i in syscalls[index].args:
      if 'st_mode' in i:
        # TODO: we only support replacing S_IFREG right now
        syscalls[index].args[i].replace('S_IFREG', self.filetype)


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

  def identify_lines(self, syscalls, lines):
    for k, v in enumerate(syscalls):
      # fstat takes a file descriptor
      if v != None and v.name.startswith('fstat'):
        if self.file_descriptor:
          if self.file_descriptor != v.args[0].value:
            continue
        lines.append(k)
      # stat and lstat take a name rather than a file descriptor
      if v != None and v.name.startswith('stat') or v != None and v.name.startswith('lstat'):
        if self.name:
          if self.name != v.args[0].value:
            continue
        lines.append(k)
