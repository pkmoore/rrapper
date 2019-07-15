from __future__ import print_function

import os
import ConfigParser
import TraceManager
import Producer
import Queue

from posix_omni_parser import Trace
from threading import Thread

import consts

def mutate(name, mutators, verbosity):
    # check if config file exists
    test_dir = consts.DEFAULT_CONFIG_PATH + name + "/"
    if not os.path.exists(test_dir):
      print("Test '{}' does not exist. Create before attempting to configure!" \
              .format(name))
      return 0

    # read config file for rr test directory
    config = ConfigParser.ConfigParser()
    config.read(test_dir + "config.ini")
    testname = config.get("rr_recording", "rr_dir")

    # open trace file for reading
    with open(test_dir + consts.STRACE_DEFAULT, 'r') as trace_file:
      trace_lines = trace_file.readlines()

   # strip and breakdown pid
    pid = trace_lines[0].split()[0]

    #config.set("request_handling_process", "mutator", args.mutator)
    # use the mutator to identify the line we are interested in
    pickle_file = consts.DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle'
    trace_manager = TraceManager.TraceManager()

    # Instantiating consumers
    identified_mutators = [] 
    for mutator in mutators:
      trace_manager.register_mutator(mutator)
      identified_mutators.append(eval(mutator))

    # Instantiating producer
    producer = Producer.Producer(test_dir + consts.STRACE_DEFAULT, pickle_file, trace_manager)
    producer_thread = Thread(target=producer.produce, args=())
    producer_thread.start()

    # ignore syscalls before the 'syscall_xxx()' marker
    for i in range(len(syscalls)):
      if 'syscall_' in syscalls[i].name:
        break

    off_set = i
    syscalls=syscalls[i:]

    lines = identify_mutator.identify_lines(syscalls)
    for i in range(len(lines)):
      lines[i] += off_set

    lines_count = len(lines)

    if (lines_count == 0):
      print("{} did not find any simulation opportunities."
            .format(mutator))
      return 1

    sections = config.sections()
    mutator_flag = len(sections) - 1 
    print(mutator_flag) 

    for j in range(lines_count):
      config.add_section("request_handling_process"+str(j + mutator_flag))
      config.set("request_handling_process"+str(j + mutator_flag), "event", None)
      config.set("request_handling_process"+str(j + mutator_flag), "pid", None)
      config.set("request_handling_process"+str(j + mutator_flag), "trace_file", test_dir + consts.STRACE_DEFAULT)
      config.set("request_handling_process"+str(j + mutator_flag), "trace_start", 0)
      config.set("request_handling_process"+str(j + mutator_flag), "trace_end", 0)

      identified_syscall_list_index = lines[j]

      config.set("request_handling_process"+str(j + mutator_flag), "mutator", mutator)

      # we must multiply by 2 here because the mutator is looking at a list
      # of parsed system call objects NOT the trace file itself.  This means
      # index A in the list of system calls corresponds with line number (A * 2)
      # in the trace file because including the rr event lines (which, again,
      # are NOT present in the list of system call objects) DOUBLES the number
      # of lines in the file
      identified_trace_file_index = identified_syscall_list_index * 2
      identified_trace_line = trace_lines[identified_trace_file_index]


      event_line = trace_lines[(identified_trace_file_index) - 1]
      user_event = int(event_line.split('+++ ')[1].split(' +++')[0])
      # now we must generate a new trace snippet that will be used to drive the test.
      # This snip will be sniplen (default 5) system calls in length and will have
      # the rr event number lines from the main recording STRIPPED OUT.
      lines_written = 0

      with open(test_dir + "trace_snip"+str(j + mutator_flag)+".strace", 'wb') as snip_file:
        for i in range(0, sniplen * 2, 2):
          try:
            snip_file.write(trace_lines[identified_trace_file_index + i])
            lines_written += 1
          except IndexError:
            break

      config.set("request_handling_process"+str(j + mutator_flag), "trace_file", test_dir + "trace_snip"+str(j + mutator_flag) + ".strace")
      config.set("request_handling_process"+str(j + mutator_flag), "event", user_event)
      config.set("request_handling_process"+str(j + mutator_flag), "pid", pid)
      config.set("request_handling_process"+str(j + mutator_flag), "trace_end", lines_written)

      # write final changes to config file
      with open(test_dir + "config.ini", 'w+') as config_file:
        config.write(config_file)
    return 1
