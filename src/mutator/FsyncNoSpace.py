from mutator import GenericMutator

class FsyncNoSpaceMutator(GenericMutator):


  def __init__(self, name=None):
      self.name = name


  def mutate_syscalls(self, syscalls):
    for k, v in enumerate(syscalls):
      if v.name == 'fsync':
        if self.name:
          if v.args[0].value != self.name:
            continue
        syscalls[k].ret = (-1, 'ENOSPACE')


  def identify_lines(self, tm, que):
    while v = self.next_syscall():
      if v.name == 'fsync':
        if self.name:
          if v.args[0].value != self.name:
            continue
        self.opportunity_identified(i, que)
