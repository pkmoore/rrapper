from mutator import GenericMutator


class FutureTimeMutator(GenericMutator):
  def __init__(self, seconds=100):
      self.seconds = seconds
      self.name = "FutureTimeMutator"


  def mutate_syscalls(self, syscalls):
    for k, v in enumerate(syscalls):
      if v.name == 'time':
        syscalls[k].ret = (syscalls[k].ret[0] + self.seconds, '')


  def identify_lines(self, tm, que, thread_condition, producer):
    while True:
      syscall_trace = self.next_syscall(self.name, tm, thread_condition, producer)
      if not syscall_trace:
          return
      elif syscall_trace['syscall'].name == 'time':
        self.opportunity_identified(syscall_trace, self.name, que)
