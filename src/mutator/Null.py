from mutator import GenericMutator

class NullMutator(GenericMutator):
  def __init__(self, index=0):
    self.index = index

  def mutate_trace(self, trace):
    return trace

  def identify_lines(self, trace):
    return [self.index]
