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
  
  def pop_front(self):
      self.syscall_objects.pop(0)
      self.trace.pop(0)
      for mutator in self.mutators:
          mutator['index'] -= 1

  def next_syscall(self, calling_mutator):
      mutator_index = -1
      for i in range(len(self.mutators)):
          if self.mutators[i]['name'] == calling_mutator:
              mutator_index = i
              break
      if mutator_index == -1:
          print('----')
          print(self.mutators)
          print('could not find the mutator')
          print('----')
      tmp_index = self.mutators[mutator_index]['index']
      tmp_index += 1
      try:
          syscall = self.syscall_objects[tmp_index]
          trace = self.trace[tmp_index]
          event_num = self.trace[tmp_index]
          syscall_trace_pack = {'syscall': syscall, 'event':event_num, 'trace':trace}
      except IndexError:
          return None
      self.mutators[mutator_index]['index'] += 1
      return syscall_trace_pack

  def prev_syscall(self, calling_mutator):
      tmp_index = calling_mutator['index']
      tmp_index -= 1
      try:
        return self.syscall_objects[tmp_index]
      except IndexError:
        raise StopIteration


