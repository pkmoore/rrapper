"""
<Program Name>
  TraceManager

<Started>
  July 2019

<Author>
  Junjie Ge

<Purpose>
  Manages the trace identified by the producer (posix_omni_parser)

"""

class TraceManager:
  def __init__(self):
      self.syscall_objects = []
      self.trace = []
      self.mutators = []

  def register_mutator(self, mutator):
      self.mutators.append({'name': mutator, 'index': 0})

  def next_syscall(self, calling_mutator):
      tmp_index = calling_mutator['index']
      tmp_index += 1
      try:
          syscall_to_return = self.syscall_objects[calling_mutator['index']]
      except IndexError:
          '''Block somehow'''

  def prev_syscall(self, calling_mutator):
      tmp_index = calling_mutator['index']
      tmp_index -= 1
      try:
        return self.syscall_objects[tmp_index]
      except IndexError:
        raise StopIteration


