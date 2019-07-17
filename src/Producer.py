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
    self.tracefile = trace_file
    self.trace_manager = tm
    self.parser = StraceParser(self.tracefile, pickle_file)

  def produce(self, thread_condition):
    with open(self.tracefile, 'r') as fh:
      
      # Finding and ignoring everything before 'syscall_'
      while True:
        try:
          trace_line = fh.next()
        except StopIteration:
          logging.debug("Incomplete Trace. Trace ended without 'syscall_'")          
          sys.exit(1)
        syscall = self.parser.parse_line(trace_line)
        if syscall and 'syscall_' in syscall.name:
          break

      # before updating and deleting the syscall_objects simultaneously, first add an
      # intial amount of syscall_objects to the trace_manager
      for i in range(10):
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


      while True:
        backtrace_limit = 99999999
        for mutator in self.trace_manager.mutators:
          if mutator['index'] - 1 < backtrace_limit:
            backtrace_limit = mutator['index'] - 1
        if backtrace_limit > 0:
          with thread_condition:
            for i in range(backtrace_limit):
              self.trace_manager.pop_front()
            for i in range(backtrace_limit):
              try:
                trace_line = fh.next()
              except StopIteration:
                thread_condition.notify_all()
                return
              self.trace_manager.syscall_objects.append(self.parser.parse_line(trace_line))
              self.trace_manager.trace.append(trace_line)
              thread_condition.notify()


            
