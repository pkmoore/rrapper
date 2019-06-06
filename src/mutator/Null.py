from mutator import GenericMutator

class NullMutator(GenericMutator):
  def __init__(self, index=0):
    self.index = 0

  def mutate_trace(self, trace):
    pass

  def identify_lines(self, trace):
    return self.index
