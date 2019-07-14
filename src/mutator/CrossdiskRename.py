from mutator import GenericMutator


class CrossdiskRenameMutator(GenericMutator):
  def __init__(self, name=None):
      self.name = name


  def mutate_syscalls(self, syscalls):
    for k, v in enumerate(syscalls):
      if v.name == 'rename':
        if self.name:
          if v.args[0].value != self.name:
            continue
          syscalls[k].ret = (-1, 'EXDEV')


  def identify_lines(self, syscalls, lines):
    for k, v in enumerate(syscalls):
      if v.name == 'rename':
        if self.name:
          if v.args[0].value != self.name:
            continue
        lines.append(k)
