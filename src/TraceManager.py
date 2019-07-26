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
import random
import string
import exceptions
import consts

class TraceManager:
  def __init__(self):
    self.producer_running = True
    self.syscall_objects = []
    self.trace = []
    self.mutators = []
    

  def register_mutator(self, mutator):
    """
    <Purpose>
      This method takes in a mutator and generates a random id and assign it
      to that mutator. It puts the id and an initial index of 0 to the list of
      mutators.

    <Returns>
      None

    """

    # Generates the id of the mutator
    mutator_id = self._id_generator()

    # Store the id in the mutator object
    mutator.set_id(mutator_id)

    self.mutators.append({'id': mutator_id, 'index': 0})

  
  def _id_generator(self, size=10, char=string.ascii_letters+string.digits):
    result = ''
    for i in range(size):
      result = result + random.choice(char)
    return result

  
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


  def get_next_syscall_trace_package(self, calling_mutator, sniplen=5):
    """
    <Purpose>
      This method takes in the calling mutator, using its index, this methods
      return the next syscall

    <Returns>
      None if the end of the current parsed list is reached, or a dictionary
      containing information about the next syscall

    """

    # Checking if calling mutator is in the list of registered mutators
    mutator_index = self._checking_mutator(calling_mutator)

    # Get the next syscall if possible, if reaching the end of list, return None
    index = self.mutators[mutator_index]['index']
    try:
      syscall = self.syscall_objects[index]
      event_num = self.trace[index][0]
      trace = []
      trace.append(self.trace[index][1])
    except IndexError:
      return None
  
    try:
      for i in range(1, sniplen):
        trace.append(self.trace[index + i][1])
    except IndexError:
      if self.producer_running:
        return None

    syscall_trace_pack = {'syscall': syscall, 'event':event_num, 'trace':trace}
    self.mutators[mutator_index]['index'] += 1
    return syscall_trace_pack


  def get_backlog(self, calling_mutator): # Not yet tested
    """
    <Purpose>
      This methods returns the entire backlog of a specific mutator.

    <Returns>
      Syscall_trace_pack, a dictionary which contains the entire backlog
      of the calling_mutator.

    """

    # Checking if calling mutator is in the list of registered mutators
    mutator_index = self._checking_mutator(calling_mutator)

    # Find out the range of the backlog. Where it starts and where it ends.
    index = self.mutators[mutator_index]['index']
    backlog_start = 0
    if index - consts.BACKLOG_SIZE > 0:
        backlog_start = index - consts.BACKLOG_SIZE

    syscall_trace_pack = {'syscall': self.syscall_objects[backlog_start:index], 
            'event':self.trace[backlog_start:index], 
            'trace':self.trace[backlog_start,index]}
    return syscall_trace_pack


  def _checking_mutator(self, calling_mutator):
    """
    <Purpose>
      This method looks whether the calling_mutator is in the list
      of register_mutator.

    <Returns>
      Index of the calling_mutator in the list of register_mutator.
      Raises MutatorError if not found.

    """
    mutator_index = -1
    for i in range(len(self.mutators)):
      if self.mutators[i]['id'] == calling_mutator:
        mutator_index = i
        break
    if mutator_index == -1:
      logging.debug('mutator %s, is not in the list of registered mutators', calling_mutator)
      raise exceptions.MutatorError('Mutator {} not found in registered mutators'.format(calling_mutator))
    return mutator_index
      

  def producer_done(self):
      self.producer_running = False

