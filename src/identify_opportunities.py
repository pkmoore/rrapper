from __future__ import print_function

import os
import ConfigParser
import Queue
import threading
import TraceManager
import Producer

from mutator.Null import NullMutator                        # noqa: F401
from mutator.CrossdiskRename import CrossdiskRenameMutator  # noqa: F401
from mutator.FutureTime import FutureTimeMutator            # noqa: F401
from mutator.ReverseTime import ReverseTimeMutator          # noqa: F401
from mutator.UnusualFiletype import UnusualFiletypeMutator  # noqa: F401

import consts

def identify_opportunities(name, mutators, verbosity):
  # check if config file exists
  test_dir = consts.DEFAULT_CONFIG_PATH + name + "/"
  if not os.path.exists(test_dir):
    print("Test '{}' does not exist. Create before attempting to configure!" \
            .format(name))
    return 0

  # read config file for rr test directory
  config = ConfigParser.ConfigParser()
  config.read(test_dir + "config.ini")

  # open trace file for reading
  with open(test_dir + consts.STRACE_DEFAULT, 'r') as trace_file:
    trace_lines = trace_file.readlines()

  # strip and breakdown pid
  pid = trace_lines[0].split()[0]

  # use the mutator to identify the line we are interested in
  pickle_file = consts.DEFAULT_CONFIG_PATH + 'syscall_definitions.pickle'
  trace_manager = TraceManager.TraceManager()
  producing_syscall = threading.Condition()
  opportunities = Queue.Queue()

  # Instantiating producer
  producer = Producer.Producer(test_dir + consts.STRACE_DEFAULT, pickle_file, trace_manager)
  producer_thread = threading.Thread(target=producer.produce, name='producer', args=(producing_syscall,))
  producer_thread.start()

  # Instantiating consumers
  mutator_threads = []
  for mutator in mutators:
    identify_mutator = eval(mutator)
    trace_manager.register_mutator(identify_mutator.mutator_name)
    thread = threading.Thread(target=identify_mutator.identify_lines,
        name='mutator', args=(trace_manager, opportunities, producing_syscall))
    thread.start()
    mutator_threads.append(thread)

  config_number = 0
  while len(threading.enumerate()) > 1 or not opportunities.empty():
    try:
      identified_opportunity = opportunities.get(True, 1)
    except Queue.Empty:
      continue

    syscall_trace_obj = identified_opportunity[0]
    config.add_section("request_handling_process"+str(config_number))
    config.set("request_handling_process"+str(config_number), "event", None)
    config.set("request_handling_process"+str(config_number), "pid", None)
    config.set("request_handling_process"+str(config_number), "trace_file", test_dir + consts.STRACE_DEFAULT)
    config.set("request_handling_process"+str(config_number), "trace_start", 0)
    config.set("request_handling_process"+str(config_number), "trace_end", 0)
    config.set("request_handling_process"+str(config_number), "mutator",
        identified_opportunity[1]+'()')

    event_line = syscall_trace_obj['event']
    user_event = int(event_line.split('+++ ')[1].split(' +++')[0])

    # now we must generate a new trace snippet that will be used to drive the test.
    # This snip will be sniplen (default 1) system calls in length and will have
    # the rr event number lines from the main recording STRIPPED OUT.
    lines_written = 0
    with open(test_dir + "trace_snip"+str(config_number)+".strace", 'wb') as snip_file:
      snip_file.write(syscall_trace_obj['trace'])
      lines_written += 1

    config.set("request_handling_process"+str(config_number), "trace_file",
        test_dir + "trace_snip"+str(config_number) + ".strace")
    config.set("request_handling_process"+str(config_number), "event", user_event)
    config.set("request_handling_process"+str(config_number), "pid", pid)
    config.set("request_handling_process"+str(config_number), "trace_end", lines_written)

    # write final changes to config file
    with open(test_dir + "config.ini", 'w+') as config_file:
      config.write(config_file)

    config_number += 1
  return 1
