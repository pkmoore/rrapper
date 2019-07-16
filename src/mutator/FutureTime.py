from mutator import GenericMutator


class FutureTimeMutator(GenericMutator):
  def __init__(self, seconds=100):
      self.seconds = seconds


  def mutate_syscalls(self, syscalls):
    for k, v in enumerate(syscalls):
      if v.name == 'time':
        syscalls[k].ret = (syscalls[k].ret[0] + self.seconds, '')


  def identify_lines(self, tm, que):
    while v = self.next_syscall():
      if v.name == 'time':
        self.opportunity_identified(v, que)
 
