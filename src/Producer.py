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

import logging
import sys

from posix_omni_parser.parsers.StraceParser import StraceParser

import consts

class Producer:
  def __init__(self, trace_file, pickle_file, tm):
    # location of tracefile
    self.tracefile = trace_file
    self.trace_manager = tm
    self.parser = StraceParser(self.tracefile, pickle_file)


  def produce(self, thread_condition, backlog_size=1000):
    """
    <Purpose>
      This method parses and adds syscalls to the list of syscalls in
      TraceManager. It works like a sliding window that constantly updates the
      list depending on where the slowest mutator is in that list

    <Returns>
      None

    """

    with open(self.tracefile, 'r') as fh:
      # Finding and ignoring everything before 'syscall_'
      while True:
        try:
          trace_line = fh.next()
        except StopIteration:
          logging.debug("Incomplete Trace. Trace ended without 'syscall_'")          
          raise(RuntimeError)
        syscall = self.parser.parse_line(trace_line)
        if syscall and 'syscall_' in syscall.name:
          break

      # before updating and deleting the syscall_objects simultaneously, first add an
      # intial amount of syscall_objects to the trace_manager in order for
      # mutators to have an initial amout of backlogs
      for i in range(backlog_size * 2):
        with thread_condition:
          try:
            trace_line = fh.next()
          except StopIteration:
            thread_condition.notify_all()
            return
          syscall = self.parser.parse_line(trace_line)
          self.trace_manager.syscall_objects.append(syscall)
          self.trace_manager.trace.append(trace_line)
          thread_condition.notify()

      # This part is the updating window. It deletes everything before the
      # backlog of the slowest mutator and adds the same number of syscalls to
      # the end
      while True:
        backtrace_limit = self.trace_manager.mutators[0]['index'] - backlog_size
        for mutator in self.trace_manager.mutators:
          if mutator['index'] - backlog_size < backtrace_limit:
            backtrace_limit = mutator['index'] - backlog_size
        if backtrace_limit > 0:
          with thread_condition:
            for i in range(backtrace_limit):
              self.trace_manager.pop_front()
              try:
                trace_line = fh.next()
              except StopIteration:
                thread_condition.notify_all()
                return
              self.trace_manager.syscall_objects.append(self.parser.parse_line(trace_line))
              self.trace_manager.trace.append(trace_line)
              thread_condition.notify()


            
