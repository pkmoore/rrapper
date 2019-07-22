from mutator import GenericMutator


class CrossdiskRenameMutator(GenericMutator):
  def __init__(self, rename=None):
    self.name = rename
    self.mutator_name = 'CrossdiskRenameMutator'


  def mutate_syscalls(self, syscalls):
    for k, v in enumerate(syscalls):
      if v.name == 'rename':
        if self.name:
          if v.args[0].value != self.name:
            continue
          syscalls[k].ret = (-1, 'EXDEV')


  def identify_lines(self, tm, que, thread_condition):
    while True:
      syscall_trace = self.next_syscall(self.mutator_name, tm, thread_condition)
      if not syscall_trace:
        return
      elif syscall_trace['syscall'].name == 'rename':
        if self.name:
          if syscall_trace['syscall'].args[0].value != self.name:
            continue
        self.opportunity_identified(syscall_trace, self.mutator_name, que)
