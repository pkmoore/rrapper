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

from mutator.mutator import NullMutator
from mutator.UnusualFiletype import UnusualFiletypeMutator
from mutator.ReverseTime import ReverseTimeMutator
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
    98,   # sys_getrusage
    35,  # sys_nanosleep
    10,  # sys_mprotect
    14,  # sys_rt_sigprocmask
    99,  # sys_sysinfo
    15,  # sys_sigreturn
    126,  # sys_sigprocmask
    131,  # sys_sigaltstack
    252,  # exit_group
    266,  # set_clock_getres
    240,  # sys_futex
    203,  # sys_sched_setaffinity
    204,  # sys_sched_getaffinity
    243,  # sys_set_thread_area
    311,  # sys_set_robust_list
    340,  # sys_prlimit64
    97,  # sys_getrlimit
  ]

  # These represent the handlers for system calls that we have chosen not to
  # ignore. The key represents a tuple of the ID and the state (entering the
  # syscall or exiting), and the value is the respective syscallreplay handler.
  handlers = {
    (0, True): file_handlers.read_entry_handler,
    (1, True): file_handlers.write_entry_handler,
    (2, True): file_handlers.open_entry_handler,
    (3, True): file_handlers.close_entry_handler,
    (4, True): file_handlers.stat64_entry_handler,
    (5, True): file_handlers.fstat64_entry_handler,
    (6, True): file_handlers.lstat64_entry_handler,
    (7, True): multiplex_handlers.poll_entry_handler,
    (8, True): file_handlers.llseek_entry_handler,
    (9, True): kernel_handlers.mmap2_entry_handler,
    # 10 mprotect and is currently ignored
    # 11 munmap
    (11, True): generic_handlers.check_return_value_entry_handler,
    (12, True): kernel_handlers.brk_entry_handler,
    (13, True): kernel_handlers.rt_sigaction_entry_handler,
    # 14 rt_sigprocmask and is currently ignored
    # 15 rt_sigreturn and is currently ignored
    (16, True): kernel_handlers.ioctl_entry_handler,
    # 17 pread64
    # 18 pwrite64
    #(19, True): readv_entry_handler,
    (20, True): file_handlers.writev_entry_handler,
    # 21 access
    (21, True): generic_handlers.syscall_return_success_handler,
    #(22, True): pipe_entry_handler,
    (23, True): multiplex_handlers.select_entry_handler,
    # 24 sched_yield
    # 25 mremap
    # 26 msync
    # 27 mincore
    # 28 madvise
    # 29 shmget
    # 30 shmat
    # 31 shmctl
    # 32 dup
    # 33 dup2
    (33, True): generic_handlers.syscall_return_success_handler,
    # 34 pause
    # 35 nanosleep is currently ignored
    # 36 getitimer
    # 37 alarm
    (37, True): generic_handlers.syscall_return_success_handler,
    # 38 setitimer
    # 39 getpid
    (39, True): generic_handlers.syscall_return_success_handler,
    # 40 sendfile

    # Socket calls realized as syscalls here
    # 41 socket
    # 42 connect
    # 43 accept
    # 44 sendto
    # 45 recvfrom
    # 46 sendmsg
    # 47 recvmsg
    # 48 shutdown
    # 49 bind
    # 50 listen
    # 51 getsockname
    # 52 getpeername
    # 53 socketpair
    # 54 setsockopt
    # 55 getsockopt

    # Process stuff
    # 56 clone
    # 57 fork
    # 58 vfork
    # 59 execve
    # 60 exit
    # 61 wait4
    # 62 kill

    # 63 uname
    (63, True): kernel_handlers.uname_entry_handler,
    # 64 semget
    # 65 semop
    # 66 semctl
    # 67 shmdt
    # 68 msgget
    # 69 msgsnd
    # 70 msgrcv
    # 71 msgctl
    # 72 fcntl
    (72, True): generic_handlers.syscall_return_success_handler,
    # 73 flock
    # 74 fsync
    # 75 fdatasync
    # 76 truncate
    # 77 ftruncate
    # 78 getdents
    (79, True): file_handlers.getcwd_entry_handler,
    # 80 chdir
    # 81 fchdir
    (82, True): file_handlers.rename_entry_handler,
    # 83 mkdir
    # 84 rmdir
    # 85 creat
    # 86 link
    (87, True): file_handlers.unlink_entry_handler,
    # 88 symlink
    (89, True): file_handlers.readlink_entry_handler,
    # 90 chmod
    (90, True): generic_handlers.syscall_return_success_handler,
    (91, True): file_handlers.fchmod_entry_handler,
    # 92 chown
    (93, True): file_handlers.fchown_entry_handler,
    # 94 lchown
    (95, True): generic_handlers.syscall_return_success_handler,
    (96, True): time_handlers.gettimeofday_entry_handler,
    # 97 getrlimit currently ignored
    # 98 getrusage
    # 99 sysinfo
    (100, True): time_handlers.times_entry_handler,
    # 101 ptrace
    # 102 getuid
    (102, True): generic_handlers.syscall_return_success_handler,
    # 103 syslog
    # 104 getgid
    # 105 setuid
    # 106 setgid
    # 107 geteuid
    (107, True): generic_handlers.syscall_return_success_handler,
    # 108 getegid
    (108, True): generic_handlers.syscall_return_success_handler,
    # 109 setpgid
    # 110 getppid
    # 111 getpgrp
    # 112 setsid
    # 113 setreuid
    # 114 setregid
    # 115 getgroups
    # 116 setgroups
    # 117 setresuid
    # 118 getresuid
    # 119 setresgid
    # 120 getresgid
    # 121 getpgid
    # 122 setfsuid
    # 123 setfsgid
    # 124 getsid
    # 125 capget
    # 126 capset
    # 127 rt_sigpending
    # 128 rt_sigtimedwait
    # 129 rt_sigqueueinfo
    # 130 rt_sigsuspend
    # 131 sigaltstack
    # 132 utime
    # 133 mknod
    # 134 uselib
    # 135 personality
    # 136 ustat
    # 137 statfs
    # 138 fstatfs
    # 139 sysfs
    # 140 getpriority
    # 141 setpriority
    # 142 sched_setparam
    # 143 sched_getparam
    # 144 sched_setscheduler
    # 145 sched_getscheduler
    # 146 sched_get_priority_max
    # 147 sched_get_priority_min
    # 148 sched_rr_get_interval
    # 149 mlock
    # 150 munlock
    # 151 mlockall
    # 152 munlockall
    # 153 vhangup
    # 154 modify_ldt
    # 155 pivot_root
    # 156 sysctl
    # 157 prctl
    # 158 arch_prctl
    # 159 adjtimex
    # 160 setrlimit
    # 161 chroot
    # 162 sync
    # 163 acct
    # 164 settimeofday
    # 165 mount
    # 166 umount2
    # 167 swapon
    # 168 swapoff
    # 169 reboot
    # 170 sethostname
    # 171 setdomainname
    # 172 iopl
    # 173 ioperm
    # 174 create_module
    # 175 init_module
    # 176 delete_module
    # 177 get_kernel_syms
    # 178 query_module
    # 179 quotactl
    # 180 nfsservctl
    # 181 getpmsg
    # 182 putpmsg
    # 183 afs_syscall
    # 184 tuxcall
    # 185 security
    # 186 gettid
    # 187 readahead
    # 188 setxattr
    # 189 lsetxattr
    # 190 fsetxattr
    # 191 fgetxattr
    # 192 lgetxattr
    # 193 fgetxattr
    # 194 listxattr
    # 195 llistxattr
    # 196 flistxattr
    # 197 removexattr
    # 198 lremovexattr
    # 199 fremovexattr
    # 200 tkill
    (201, True): time_handlers.time_entry_handler,
    # 202 futex
    # 203 sched_setaffinity ignored
    # 204 sched_getaffinity ignored
    # 205 set_thread_area
    # 206 io_setup
    # 207 io_destroy
    # 208 io_getevents
    # 209 io_submit
    # 210 io_cancel
    # 211 get_thread_area
    # 212 lookup_dcookie
    (213, True): multiplex_handlers.epoll_create_entry_handler,
    # 214 epoll_ctl_old
    # 215 epoll_wait_old
    # 216 remap_file_pages
    #(217, True): file_handlers.getdents64_entry_handler,
    # 218 set_tid_address
    # 219 restart_syscall
    # 220 semtimedtop
    # 221 fadvise64
    # 222 timer_create
    # 223 timer_settime
    # 224 timer_gettime
    # 225 timer_getoverrun
    # 226 timer_delete
    # 227 clock_settime
    (228, True): time_handlers.clock_gettime_entry_handler,
    # 229 clock_getres
    # 230 clock_nanosleep
    # 231 exit_group
    (232, True): multiplex_handlers.epoll_wait_entry_handler,
    (233, True): multiplex_handlers.epoll_ctl_entry_handler,
    # 234 tgkill
    # 235 utimes
    # 236 vserver
    # 237 mbind
    # 238 set_mempolicy
    # 239 get_mempolicy
    # 240 mq_open
    # 241 mq_unlink
    # 242 mq_timedsend
    # 243 mq_timedreceive
    # 244 mq_notify
    # 245 mq_getsetattr
    # 246 kexec_load
    # 247 waitid
    # 248 add_key
    # 249 request_key
    # 250 keyctl
    # 251 ioprio_set
    # 252 ioprio_get
    # 253 inotify_init
    # 254 inotify_add_watch
    # 255 inotify_rm_watch
    # 256 migrate_pages
    (257, True): file_handlers.openat_entry_handler,
    # 258 mkdirat
    # 259 mknodat
    # 260 fchownat
    # 261 futimesat
    # 262 newfstatat
    # 263 unlinkat
    # 264 renameat
    # 265 linkat
    # 266 symlinkat
    # 267 readlinkat
    # 268 fchmodat
    # 269 faccessat
    # 270 pselect6
    # 271 ppoll
    # 272 unshare
    # 273 set_robust_list
    # 274 get_robust_list
    # 275 splice
    # 276 tee
    # 277 sync_file_range
    # 278 vmsplice
    # 279 move_pages
    (280, True): time_handlers.utimensat_entry_handler,
    # 281 epoll_pwait
    # 282 signalfd
    # 283 timerfd_create
    # 284 eventfd
    # 285 fallocate
    # 286 timerfd_settime
    # 287 timerfd_gettime
    # 288 accept4
    # 289 signalfd4
    # 290 eventfd2
    # 291 epoll_create1
    # 292 dup3
    # 293 pipe2
    # 294 inotify_init1
    # 295 preadv
    # 296 pwritev
    # 297 rt_tgsigqueueinfo
    # 298 perf_event_open
    # 299 recvmmsg
    # 300 fanotify_init
    # 301 fanotify_mark
    # 302 prlimit64
    # 303 name_to_handle_at
    # 304 open_by_handle_at
    # 305 clock_adjtime
    # 306 syncfs
    # 307 sendmmsg
    # 308 setns
    # 309 getcpu
    # 310 process_vm_readv
    # 311 process_vm_writev
    # 312 kcmp
    # 313 finit_module
    # 314 sched_setattr
    # 315 sched_getattr
    # 316 renameat2
    # 317 seccomp
    # 318 getrandom
    # 319 memfd_create
    # 320 kexec_file_load
    # 321 bpf
    # 322 stub_execveat
    # 323 userfaultfd
    # 324 membarrier
    # 325 mlock2
    # 326 copy_file_range
    # 327 preadv2
    # 327 pwritev2
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





def apply_open_fds(rec_pid):
  """
  <Purpose>
    Obtains open file descriptors from rec_pid and sets it
    within the injected state.

  <Returns>
    None

  """
  fds_for_pid = syscallreplay.injected_state['open_fds'][rec_pid]
  syscallreplay.injected_state['open_fds'] = fds_for_pid





def apply_mmap_backing_files():
  """
  <Purpose>
    Method that ensures that mmap calls are simulated and that files
    are backed correctly into the process's address space.

  <Returns>
    None

  """
  if 'mmap_backing_files' in syscallreplay.injected_state['config']:
    line = syscallreplay.injected_state['config']['mmap_backing_files']
    files = parse_backing_files(line)
    syscallreplay.injected_state['config']['mmap_backing_files'] = files





def exit_with_status(pid, code):
  """
  <Purpose>
    Method that ensures that the injector is safely exited by
    killing the specified pid, printing a traceback, and
    return output on the success of replaying the trace.

  <Returns>
    None

  """
  _kill_parent_process(pid)
  if code != 0:
    traceback.print_exc()
    print('Failed to complete trace')
  else:
    print('Completed the trace')
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
  config_dict = syscallreplay.injected_state['config']
  pid = int(config_dict['pid'])
  rec_pid = config_dict['rec_pid']
  apply_open_fds(rec_pid)
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
  if 'checker' in syscallreplay.injected_state['config']:
    checker = eval(syscallreplay.injected_state['config']['checker'])
  if 'mutator' in syscallreplay.injected_state['config']:
    mutator = eval(syscallreplay.injected_state['config']['mutator'])
    mutator.mutate_trace(config_dict['trace_file'])
    trace = Trace.Trace(config_dict['trace_file'], pickle_file)
    syscallreplay.syscalls = trace.syscalls
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

  if syscallreplay.peek_register(pid, syscallreplay.ORIG_RAX) == 0:
      logging.debug('Skip restart_syscall entry %d', pid)
      syscallreplay.syscall(pid, 0)
      _, status = os.waitpid(pid, 0)

      logging.debug('Skip restart_syscall exit %d', pid)
      syscallreplay.syscall(pid, 0)
      _, status = os.waitpid(pid, 0)

  # main system call handling loop
  logger.debug('Entering system call handling loop')
  syscallreplay.entering_syscall = True
  while not os.WIFEXITED(status):
    syscall_object = syscallreplay.syscalls[syscallreplay.syscall_index]
    try:
      syscall_id = syscallreplay.peek_register(pid,
                                               syscallreplay.ORIG_RAX)
      debug_handle_syscall(pid,
                           syscall_id,
                           syscall_object,
                           syscallreplay.entering_syscall)
    except:
      exit_with_status(pid, 1)

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
      exit_with_status(pid, 0)





if __name__ == '__main__':
  main()
