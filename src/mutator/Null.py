from mutator import GenericMutator

class NullMutator(GenericMutator):
  def __init__(self, index=0):
    self.index = index

  def mutate_syscalls(self, syscalls):
    pass

  def identify_lines(self, syscalls, lines):
    return [self.index]
