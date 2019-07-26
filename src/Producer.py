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
import exceptions

class Producer:
  def __init__(self, trace_file, pickle_file, tm):
    # location of tracefile
    self.tracefile = trace_file
    self.trace_manager = tm
    self.parser = StraceParser(self.tracefile, pickle_file)


  def produce(self, thread_condition, backlog_size=None):
    """
    <Purpose>
      This method parses and adds syscalls to the list of syscalls in
      TraceManager. It works like a sliding window that constantly updates the
      list depending on where the slowest mutator is in that list

    <Returns>
      None

    """

    if not backlog_size:
      backlog_size = consts.BACKLOG_SIZE

    with open(self.tracefile, 'r') as fh:
      # Finding and ignoring everything before 'syscall_'
      while True:
        try:
          trace_line = fh.next()
        except StopIteration:
          logging.debug("Incomplete Trace. Trace ended without 'syscall_'")
          raise exceptions.ProducerError('Syscall_ not found in Trace. Incompletet Trace?')
        syscall = self.parser.parse_line(trace_line)
        if syscall and 'syscall_' in syscall.name:
          break

      # Adding an initial amount of traces to the list so the indexes of mutators
      # can advance. This is requried otherwise mutator will have no trace to
      # identify and the next loop will be can infinite loop due to the
      # if backtrace_limit > 0
      for i in range(0, backlog_size * 4, 2):
        with thread_condition:
          try:
            event_line = fh.next()
            trace_line = fh.next()
          except StopIteration:
            self.trace_manager.producer_done()
            thread_condition.notify_all()
            return
          syscall = self.parser.parse_line(trace_line)
          self.trace_manager.syscall_objects.append(syscall)
          self.trace_manager.trace.append((event_line, trace_line))
          thread_condition.notify()

      # This part is the updating window. It deletes everything before the
      # backlog of the slowest mutator and adds the same number of syscalls to
      # the end
      while True:
        with thread_condition:
          backtrace_limit = self.trace_manager.mutators[0]['index'] - backlog_size
          for mutator in self.trace_manager.mutators:
            if mutator['index'] - backlog_size < backtrace_limit:
              backtrace_limit = mutator['index'] - backlog_size
          if backtrace_limit > 0:
            for i in range(backtrace_limit):
              self.trace_manager.pop_front()
              try:
                event_line = fh.next()
                trace_line = fh.next()
              except StopIteration:
                self.trace_manager.producer_done()
                thread_condition.notify_all()
                return
              self.trace_manager.syscall_objects.append(self.parser.parse_line(trace_line))
              self.trace_manager.trace.append((event_line, trace_line))
              thread_condition.notify()
      
      


            
