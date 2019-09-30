from mutator import GenericMutator


class ASAPMutator(GenericMutator):
  def __init__(self):
    pass


  def mutate_syscalls(self, syscalls):
    raise NotImplementedError('This mutator cannot be used to mutate recordings')


  def identify_lines(self, tm, que, thread_condition):
    while True:
      syscall_trace = self.next_syscall(tm, thread_condition)
      if not syscall_trace:
        return
