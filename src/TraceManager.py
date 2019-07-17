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

import logging
import sys

class TraceManager:
  def __init__(self):
      self.syscall_objects = []
      self.trace = []
      self.mutators = []

  def register_mutator(self, mutator):
      self.mutators.append({'name': mutator, 'index': 0})
  
  def pop_front(self):
    """
    <Purpose>
      This method gets rid of the backlog that are no longer needed by the
      mutators, and reposition every mutator in the correct index

    <Returns>
      None

    """
    self.syscall_objects.pop(0)
    self.trace.pop(0)
    for mutator in self.mutators:
      mutator['index'] -= 1

  def next_syscall(self, calling_mutator):
    """
    <Purpose>
      This method takes in the calling mutator, using its index, this methods
      return the next syscall

    <Returns>
      None if the end of the current parsed list is reached, or a dictionary
      containing information about the next syscall

    """
      
    # Checking if calling mutator is in the list of registered mutators
    mutator_index = -1
    for i in range(len(self.mutators)):
      if self.mutators[i]['name'] == calling_mutator:
        mutator_index = i
        break
    if mutator_index == -1:
      logging.debug('mutator %s, is not in the list of registered mutators', calling_mutator)
      sys.exit(1)

    # Get the next syscall if possible, if reaching the end of list, return None
    tmp_index = self.mutators[mutator_index]['index']
    tmp_index += 1
    try:
      syscall = self.syscall_objects[tmp_index]
      trace = self.trace[tmp_index]
      event_num = self.trace[tmp_index - 1]
      syscall_trace_pack = {'syscall': syscall, 'event':event_num, 'trace':trace}
    except IndexError:
      return None
    self.mutators[mutator_index]['index'] += 1
    return syscall_trace_pack

  def prev_syscall(self, calling_mutator):
    """
    <Purpose>
      This method takes in the calling mutator, using its index, this methods
      return the previous syscall

    <Returns>
      None if the end of the current parsed list is reached, or a dictionary
      containing information about the next syscall

    """

    # Checking if calling mutator is in the list of registered mutators
    mutator_index = -1
    for i in range(len(self.mutators)):
      if self.mutators[i]['name'] == calling_mutator:
        mutator_index = i
        break
    if mutator_index == -1:
      logging.debug('mutator %s, is not in the list of registered mutators', calling_mutator)
      sys.exit(1)

    # Get the next syscall if possible, if reaching the end of list, return None
    tmp_index = self.mutators[mutator_index]['index']
    tmp_index -= 1
    try:
      syscall = self.syscall_objects[tmp_index]
      trace = self.trace[tmp_index]
      event_num = self.trace[tmp_index - 1]
      syscall_trace_pack = {'syscall': syscall, 'event':event_num, 'trace':trace}
    except IndexError:
      return None
    self.mutators[mutator_index]['index'] -= 1
    return syscall_trace_pack


