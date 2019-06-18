#!/usr/bin/env python2.7
# pylint: disable=missing-docstring, bad-indentation, bad-continuation
"""
<Program Name>
  inject

<Started>
  November 2017

<Author>
  Preston Moore

<Purpose>
  Attach to a spun-off process and perform all CrashSimulator's business.

  This is the injector that is executed by the rreplay module once configuration parsing
  is complete. From here, checkers and mutators are attached, mmap backing files and open fds
  are applied. Finally a system call loop is initialized that prepares to compare system call
  replay execution against trace using several syscall handler methods and debug printers.

"""

from __future__ import print_function
import sys
import os
import signal
import json
import traceback
import logging
import argparse
import re

import consts

from posix_omni_parser import Trace

from syscallreplay import syscall_dict

from syscallreplay import syscallreplay
from syscallreplay import generic_handlers
from syscallreplay import file_handlers
from syscallreplay import kernel_handlers
from syscallreplay import socket_handlers
from syscallreplay import recv_handlers
from syscallreplay import send_handlers
from syscallreplay import time_handlers
from syscallreplay import multiplex_handlers
from syscallreplay import util
from syscallreplay.util import ReplayDeltaError

from mutator.Null import NullMutator
from mutator.UnusualFiletype import UnusualFiletypeMutator
from mutator.ReverseTime import ReverseTimeMutator
from mutator.FutureTime import FutureTimeMutator
from mutator.CrossdiskRename import CrossdiskRenameMutator

logger = logging.getLogger('root')


def _kill_parent_process(pid):
  """
  <Purpose>
    Helper method that reads from /proc/<PID>/status,
    and kills the process with parsed TGID with SIGKILL.

  <Returns>
    None

  """
  proc_file = open('/proc/' + str(pid) + '/status', 'r')
  for i in proc_file:
    proc_str = i.split()
    if proc_str[0] == 'Tgid:':
      tgid = int(proc_str[1])
  if tgid != pid:
    logger.debug('Got differing tgid {}, killing group'
                  .format(tgid))
    os.kill(tgid, signal.SIGKILL)
  else:
    os.kill(pid, signal.SIGKILL)
  # Alan: ensure file is closed
  proc_file.close()





def handle_socketcall(syscall_id, syscall_object, entering, pid):
  """
  <Purpose>
    Validate the subcall (NOT SYSCALL!) id of the socket subcall against
    the subcall name we expect based on the current system call object.  Then,
    hand off responsibility to the appropriate subcall handler.

  <Returns>
    None

  """
  subcall_handlers = {
    ('socket', True): socket_handlers.socket_entry_handler,
    #('socket', False): socket_exit_handler,
    ('accept', True): socket_handlers.accept_subcall_entry_handler,
    ('accept4', True): socket_handlers.accept_subcall_entry_handler,
    #('accept', False): accept_subcall_entry_handler,
    ('bind', True): socket_handlers.bind_entry_handler,
    #('bind', False): bind_exit_handler,
    ('listen', True): socket_handlers.listen_entry_handler,
    #('listen', False): listen_exit_handler,
    ('recv', True): recv_handlers.recv_subcall_entry_handler,
    #('recvfrom', True): recvfrom_subcall_entry_handler,
    ('setsockopt', True): socket_handlers.setsockopt_entry_handler,
    ('send', True): send_handlers.send_entry_handler,
    #('send', False): send_exit_handler,
    ('connect', True): socket_handlers.connect_entry_handler,
    #('connect', False): connect_exit_handler,
    ('getsockopt', True): socket_handlers.getsockopt_entry_handler,
    ## ('sendmmsg', True): sendmmsg_entry_handler,
    #('sendto', True): sendto_entry_handler,
    #('sendto', False): sendto_exit_handler,
    ('shutdown', True): socket_handlers.shutdown_subcall_entry_handler,
    #('recvmsg', True): recvmsg_entry_handler,
    #('recvmsg', False): recvmsg_exit_handler,
    ('getsockname', True): socket_handlers.getsockname_entry_handler,
    ('getpeername', True): socket_handlers.getpeername_entry_handler
  }
  # The subcall id of the socket subcall is located in the EBX register
  # according to our Linux's convention.
  subcall_id = syscallreplay.peek_register(pid, syscallreplay.EBX)
  util.validate_subcall(subcall_id, syscall_object)
  try:
    subcall_handlers[(syscall_object.name, entering)](syscall_id,
                                                      syscall_object,
                                                      pid)
  except KeyError:
    raise NotImplementedError('No handler for socket subcall %s %s',
                              syscall_object.name,
                              'entry' if entering else 'exit')





def debug_handle_syscall(pid, syscall_id, syscall_object, entering):
  """
  <Purpose>
    A debug method for handle_syscall, which attempts to find
    a printer for the specific system call, providing specific
    debug information for why a delta may have occurred.

  <Returns>
    None

  """
  try:
    handle_syscall(pid, syscall_id, syscall_object, entering)
  except ReplayDeltaError:
    # represents available debug printers
    debug_printers = {
      4: file_handlers.write_entry_debug_printer,
      5: file_handlers.open_entry_debug_printer,
      197: file_handlers.fstat64_entry_debug_printer,
      146: file_handlers.writev_entry_debug_printer,
    }

    # check if printer is available for syscall, else raise normally
    if syscall_id in debug_printers.keys():
      debug_printers[syscall_id](pid, syscall_id, syscall_object)
    else:
      logger.debug('No debug printer associated with syscall_id')
    raise





def handle_syscall(pid, syscall_id, syscall_object, entering):
  """
  <Purpose>
    Validate the id of the system call against the name of the system call
    we are expecting based on the current system call object.  Then hand off
    responsiblity to the appropriate subcall handler.
    TODO: cosmetic - Reorder handler entrys numerically.

  <Returns>
    None
  """

  logger.debug('Handling syscall')

  # If we are entering a system call, update the number of system calls we
  # have handled
  # System call id 102 corresponds to 'socket subcall'.  This system call is
  # the entry point for code calls the appropriate socketf code based on the
  # subcall id in EBX.
  if syscall_id == 102:
    ## Hand off to code that deals with socket calls and return once that is
    ## complete.  Exceptions will be thrown if something is unsuccessful
    ## that end.  Return immediately after because we don't want our system
    ## call handler code double-handling the already handled socket subcall
    handle_socketcall(syscall_id, syscall_object, entering, pid)
    return

  forgers = {
    13: time_handlers.time_forger,
    78: time_handlers.gettimeofday_forger,
    265: time_handlers.clock_gettime_forger,
  }

  # if there is a forger registerd, check for a mismatch between the called
  # syscall and the trace syscall -- indicating we need to forge a call that
  # isn't present in the trace
  if syscall_id in forgers.keys():
    if syscall_object.name != syscall_dict.SYSCALLS[syscall_id][4:]:
      forgers[syscall_id](pid)
      return
  util.validate_syscall(syscall_id, syscall_object)

  # We ignore these system calls because they have to do with aspects of
  # execution that we don't want to try to replay and, at the same time,
  # don't have interesting information that we want to validate with a
  # handler.
  ignore_list = [
    77,   # sys_getrusage
    162,  # sys_nanosleep
    125,  # sys_mprotect
    175,  # sys_rt_sigprocmask
    116,  # sys_sysinfo
    119,  # sys_sigreturn
    126,  # sys_sigprocmask
    186,  # sys_sigaltstack
    252,  # exit_group
    266,  # set_clock_getres
    240,  # sys_futex
    242,  # sys_sched_getaffinity
    243,  # sys_set_thread_area
    311,  # sys_set_robust_list
    340,  # sys_prlimit64
    191,  # !!!!!!!!! sys_getrlimit
  ]

  # These represent the handlers for system calls that we have chosen not to
  # ignore. The key represents a tuple of the ID and the state (entering the
  # syscall or exiting), and the value is the respective syscallreplay handler.
  handlers = {
    (3, True): file_handlers.read_entry_handler,
    #(3, False): check_return_value_exit_handler,
    (4, True): file_handlers.write_entry_handler,
    #(4, False): file_handlers.write_exit_handler,
    (5, True): file_handlers.open_entry_handler,
    #(5, False): open_exit_handler,
    (6, True): file_handlers.close_entry_handler,
    #(6, False): close_exit_handler,
    ##(8, True): creat_entry_handler,
    #(8, False): check_return_value_exit_handler,
    ## These calls just get their return values checked ####
    ## (9, True): check_return_value_entry_handler,
    ## (9, False): check_return_value_exit_handler,
    (10, True): file_handlers.unlink_entry_handler,
    #(12, True): syscall_return_success_handler,
    (13, True): time_handlers.time_entry_handler,
    (15, True): generic_handlers.syscall_return_success_handler,
    #(20, True): syscall_return_success_handler,
    (24, True): generic_handlers.syscall_return_success_handler,
    (27, True): generic_handlers.syscall_return_success_handler,
    #(30, True): syscall_return_success_handler,
    (33, True): generic_handlers.syscall_return_success_handler,
    (38, True): file_handlers.rename_entry_handler,
    #(38, False): check_return_value_exit_handler,
    #(39, True): check_return_value_entry_handler,
    #(39, False): check_return_value_exit_handler,
    (41, True): generic_handlers.syscall_return_success_handler,
    #(42, True): pipe_entry_handler,
    (43, True): time_handlers.times_entry_handler,
    (45, True): kernel_handlers.brk_entry_handler,
    (45, False): kernel_handlers.brk_exit_handler,
    (49, True): generic_handlers.syscall_return_success_handler,
    (54, True): kernel_handlers.ioctl_entry_handler,
    #(54, False): ioctl_exit_handler,
    (60, True): generic_handlers.syscall_return_success_handler,
    (63, True): generic_handlers.syscall_return_success_handler,
    (78, True): time_handlers.gettimeofday_entry_handler,
    #(82, True): select_entry_handler,
    (85, True): file_handlers.readlink_entry_handler,
    (91, True): generic_handlers.check_return_value_entry_handler,
    (91, False): generic_handlers.check_return_value_exit_handler,
    #(93, True): ftruncate_entry_handler,
    #(93, False): ftruncate_exit_handler,
    (94, True): file_handlers.fchmod_entry_handler,
    #(94, False): check_return_value_entry_handler,
    (122, True): kernel_handlers.uname_entry_handler,
    #(125, True): check_return_value_entry_handler,
    #(125, False): check_return_value_exit_handler,
    (140, True): file_handlers.llseek_entry_handler,
    (140, False): file_handlers.llseek_exit_handler,
    #(141, True): getdents_entry_handler,
    (142, True): multiplex_handlers.select_entry_handler,
    #(142, False): getdents_exit_handler,
    #(145, True): readv_entry_handler,
    #(145, False): check_return_value_exit_handler,
    (146, True): file_handlers.writev_entry_handler,
    #(146, False): writev_exit_handler,
    #(150, True): syscall_return_success_handler,
    (168, True): multiplex_handlers.poll_entry_handler,
    (174, True): kernel_handlers.rt_sigaction_entry_handler,
    (183, True): file_handlers.getcwd_entry_handler,
    #(186, True): sigaltstack_entry_handler,
    (187, True): send_handlers.sendfile_entry_handler,
    (192, True): kernel_handlers.mmap2_entry_handler,
    (192, False): kernel_handlers.mmap2_exit_handler,
    #(194, True): ftruncate64_entry_handler,
    #(194, False): ftruncate64_entry_handler,
    (195, True): file_handlers.stat64_entry_handler,
    (196, True): file_handlers.lstat64_entry_handler,
    #(196, True): lstat64_entry_handler,
    (197, True): file_handlers.fstat64_entry_handler,
    (199, True): generic_handlers.syscall_return_success_handler,
    (200, True): generic_handlers.syscall_return_success_handler,
    (201, True): generic_handlers.syscall_return_success_handler,
    (202, True): generic_handlers.syscall_return_success_handler,
    (207, True): file_handlers.fchown_entry_handler,
    #(207, False): check_return_value_entry_handler,
    #(209, True): getresuid_entry_handler,
    #(211, True): getresgid_entry_handler,
    (219, True): generic_handlers.syscall_return_success_handler,
    (220, True): file_handlers.getdents64_entry_handler,
    #(220, False): getdents64_exit_handler,
    (221, True): file_handlers.fcntl64_entry_handler,
    #(228, True): fsetxattr_entry_handler,
    #(228, False): fsetxattr_exit_handler,
    #(231, True): fgetxattr_entry_handler,
    #(231, False): fgetxattr_exit_handler,
    #(234, True): flistxattr_entry_handler,
    #(234, False): flistxattr_entry_handler,
    #(242, True): sched_getaffinity_entry_handler,
    #(243, True): syscall_return_success_handler,
    (250, True): generic_handlers.syscall_return_success_handler,
    (254, True): multiplex_handlers.epoll_create_entry_handler,
    (255, True): multiplex_handlers.epoll_ctl_entry_handler,
    (256, True): multiplex_handlers.epoll_wait_entry_handler,
    #(258, True): set_tid_address_entry_handler,
    #(258, False): set_tid_address_exit_handler,
    #(259, True): timer_create_entry_handler,
    #(260, True): timer_settime_entry_handler,
    #(261, True): timer_gettime_entry_handler,
    #(263, True): timer_delete_entry_handler,
    (265, True): time_handlers.clock_gettime_entry_handler,
    #(265, True): clock_gettime_entry_handler,
    #(268, True): statfs64_entry_handler,
    #(271, True): syscall_return_success_handler,
    (272, True): generic_handlers.syscall_return_success_handler,
    (330, True): generic_handlers.syscall_return_success_handler,
    (295, True): file_handlers.openat_entry_handler,
    (300, True): file_handlers.fstatat64_entry_handler,
    #(300, False): check_return_value_exit_handler,
    #(301, True): unlinkat_entry_handler,
    #(301, False): check_return_value_exit_handler,
    (306, True): file_handlers.fchmodat_entry_handler,
    (307, True): generic_handlers.syscall_return_success_handler,
    #(311, True): syscall_return_success_handler,
    (320, True): time_handlers.utimensat_entry_handler,
    #(320, False): check_return_value_exit_handler,
    (328, True): file_handlers.eventfd2_entry_handler,
    #(340, True): prlimit64_entry_handler,
    #(345, True): sendmmsg_entry_handler,
    #(345, False): sendmmsg_exit_handler
  }

  # check if system call is within blacklist
  if syscall_id not in ignore_list:
    found = False

    # check for system call id within handlers dict
    for i in handlers.keys():
      if syscall_id == i[0]:
        found = True

    # raise exception if not found.
    if not found:
      raise NotImplementedError('Encountered un-ignored syscall {} '
                                'with no handler: {}({})'
                                .format('entry' if entering else 'exit',
                                        syscall_id,
                                        syscall_object.name))
    handlers[(syscall_id, entering)](syscall_id, syscall_object, pid)





def parse_backing_files(bfs):
  """
  <Purpose>
    Method that parses a string from the configuration
    and returns a representation of backing file pairs.

  <Returns>
    Dictionary containing backing file pairs

  """
  if bfs[-1] != ';':
    bfs += ';'
  bfs = bfs.split(';')
  bfs = bfs[:-1]
  tmp = {}
  for i in bfs:
    bf_pair = i.split(':')
    tmp[bf_pair[0]] = bf_pair[1]
  return tmp





def consume_configuration(config):
  """
  <Purpose>
    Method that simply opens and loads a generated JSON
    configuration file.

  <Returns>
    None

  """
  with open(config, 'r') as cfg_file:
    syscallreplay.injected_state = json.load(cfg_file)
  os.remove(config)





def apply_mmap_backing_files():
  """
  <Purpose>
    Method that ensures that mmap calls are simulated and that files
    are backed correctly into the process's address space.

  <Returns>
    None

  """
  if 'mmap_backing_files' in syscallreplay.injected_state:
    line = syscallreplay.injected_state['mmap_backing_files']
    files = parse_backing_files(line)
    syscallreplay.injected_state['mmap_backing_files'] = files





def exit_with_status(pid, code, mutator, event, index = 0):
  """
  <Purpose>
    Method that ensures that the injector is safely exited by
    killing the specified pid, printing a traceback, and
    return output on the success of replaying the trace.

  <Returns>
    None

  """
  mut = re.findall(r'src.mutator.\w+.(\w+)', mutator)
  error = int(event) + int(index)

  _kill_parent_process(pid)
  if code != 0:
    traceback.print_exc()
    print('\n{}() mutating event No.{} failed to complete trace, resulting in errors in event No.{}.\n'.format(mut[0], event, error))
  else:
    print('\n{}() mutating event number {} finished replay without deltas.\n'.format(mut[0], event))
  sys.exit(code)





def main():
  # initialize parser
  parser = argparse.ArgumentParser()
  parser.add_argument('config',
                      metavar='config',
                      nargs=1,
                      type=str,
                      help="path to configuration file")
  parser.add_argument('-v', '--verbosity',
                      dest='loglevel',
                      type=int,
                      default=40,
                      help='flag for displaying debug information')

  # parser arguments
  args = parser.parse_args()

  # Add simple logging for verbosity
  logger.setLevel(level = args.loglevel)
  if int(args.loglevel) == 10:
    syscallreplay.enable_debug_output(10)

  # Sets up syscallreplay.injected_state['config']
  config = "".join(args.config)
  consume_configuration(config)

  # Configure various locals from the config section of our injected state
  config_dict = syscallreplay.injected_state
  pid = int(config_dict['pid'])
  rec_pid = config_dict['rec_pid']
  event_number = config_dict['event']
  apply_mmap_backing_files()

  # create trace object
  pickle_file = consts.DEFAULT_CONFIG_PATH + "syscall_definitions.pickle"
  trace = Trace.Trace(config_dict['trace_file'], pickle_file)
  syscallreplay.syscalls = trace.syscalls
  syscallreplay.syscall_index = int(config_dict['trace_start'])
  syscallreplay.syscall_index_end = int(config_dict['trace_end'])

  # Set up checker and mutator
  checker = None
  mutator = None

# pylint: disable=eval-used
  if 'checker' in syscallreplay.injected_state:
    checker = eval(syscallreplay.injected_state['checker'])
  if 'mutator' in syscallreplay.injected_state:
    mutator = eval(syscallreplay.injected_state['mutator'])
    mutator.mutate_syscalls(syscallreplay.syscalls)
# pylint: enable=eval-used

  # Requires kernel.yama.ptrace_scope = 0
  # in /etc/sysctl.d/10-ptrace.conf
  # on modern Ubuntu
  logger.debug('Injecting %d', pid)
  syscallreplay.attach(pid)
  _, status = os.waitpid(pid, 0)
  logger.debug('Attached %d', pid)

  logger.debug('Requesting stop at next system call entry using SIGCONT')
  syscallreplay.syscall(pid, signal.SIGCONT)
  _, status = os.waitpid(pid, 0)

  # We need an additional call to PTRACE_SYSCALL here in order to skip
  # past an rr syscall buffering related injected system call
  logger.debug('Second sigcont %d', pid)
  syscallreplay.syscall(pid, 0)
  _, status = os.waitpid(pid, 0)

  # main system call handling loop
  logger.debug('Entering system call handling loop')
  syscallreplay.entering_syscall = True
  while not os.WIFEXITED(status):
    syscall_object = syscallreplay.syscalls[syscallreplay.syscall_index]
    try:
      syscall_id = syscallreplay.peek_register(pid,
                                               syscallreplay.ORIG_EAX)
      debug_handle_syscall(pid,
                           syscall_id,
                           syscall_object,
                           syscallreplay.entering_syscall)
    except:
      exit_with_status(pid, 1, str(mutator), event_number, syscallreplay.syscall_index)

    # call transition() if checker is implemented
    if checker:
      checker.transition(syscall_object)

    # incremenent syscall_index if not entering
    if not syscallreplay.entering_syscall:
      syscallreplay.syscall_index += 1

    syscallreplay.entering_syscall = not syscallreplay.entering_syscall
    syscallreplay.syscall(pid, 0)
    _, status = os.waitpid(pid, 0)

    if syscallreplay.syscall_index == syscallreplay.syscall_index_end:
      if checker:
        print('####    Checker Status    ####')
        if checker.is_accepting():
          print('{} accepted'.format(checker))
        else:
          print('{} not accepted'.format(checker))
        print('####  End Checker Status  ####')
      exit_with_status(pid, 0, str(mutator), event_number)





if __name__ == '__main__':
  main()
