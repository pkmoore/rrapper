from mutator import GenericMutator


class ReverseTimeMutator(GenericMutator):
  def __init__(self, seconds=100):
      self.seconds = seconds


  def mutate_syscalls(self, syscalls):
    for k, v in enumerate(syscalls):
      if v.name == 'time':
        syscalls[k].ret = (syscalls[k].ret[0] - self.seconds, '')

  def identify_lines(self, syscalls):
    lines = []
    for k, v in enumerate(syscalls):
      if v != None and v.name == 'time':
        lines.append(k)
    return lines
