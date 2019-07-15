"""
<Program Name>
  Producer

<Started>
  July 2019

<Author>
  Junjie Ge

<Purpose>
  Instance of posix_omni_parser that poputales the syscall_object and trace in
  trace manager

"""

from posix_omni_parser.parsers.StraceParser import StraceParser

import consts

class Producer:
  def __init__(self, trace_file, pickle_file, tm):
    self.tracefile = trace_file
    self.trace_manager = tm
    self.parser = StraceParser(self.tracefile, pickle_file)

  def produce(self):
    with open(self.tracefile, 'r') as fh:

      # before updating and deleting the syscall_objects simultaneously, first add an
      # intial amount of syscall_objects to the trace_manager
      for i in range(3000):
        try:
          trace_line = fh.next()
        except StopIteration:
          return
        self.trace_manager.syscall_objects.append(self.parser.parse_line(trace_line))
        self.trace_manager.trace.append(trace_line)


      while True:
        for i in self.trace_manager.mutators:
          '''lock'''
        backtrace_limit = 0
        for mutator in self.trace_manager.mutators:
          if mutator['index'] - 1000 < backtrace_limit:
            backtrace_limit = mutator['index'] - 1000

        if backtrace_limit > 0:
          for i in range(backtrace_limit):
            self.trace_manager.pop_front()
          for i in range(backtrace_limit):
            try:
              trace_line = fh.next()
            except StopIteration:
              return
            self.trace_manager.syscall_objects.append(self.parser.parse_line(trace_line))

            
