from __future__ import print_function
import sys
import os
from signal import SIGTERM
import json

import logging

from syscallreplay import syscall_dict

from syscallreplay import syscallreplay
from syscallreplay import file_handlers
from syscallreplay import kernel_handlers
from syscallreplay import socket_handlers
from syscallreplay import time_handlers
from syscallreplay import multiplex_handlers
from syscallreplay import util
from syscallreplay.util import ReplayDeltaError

sys.path.append('posix-omni-parser/')
import Trace

logging.basicConfig(stream=sys.stderr, level=4)

def handle_socketcall(syscall_id, syscall_object, entering, pid):
    ''' Validate the subcall (NOT SYSCALL!) id of the socket subcall against
    the subcall name we expect based on the current system call object.  Then,
    hand off responsibility to the appropriate subcall handler.


    '''
    subcall_handlers = {
        ('socket', True): socket_handlers.socket_entry_handler,
        #('socket', False): socket_exit_handler,
        #('accept', True): accept_subcall_entry_handler,
        #('accept', False): accept_subcall_entry_handler,
        #('bind', True): bind_entry_handler,
        #('bind', False): bind_exit_handler,
        #('listen', True): listen_entry_handler,
        #('listen', False): listen_exit_handler,
        #('recv', True): recv_subcall_entry_handler,
        #('recvfrom', True): recvfrom_subcall_entry_handler,
        #('setsockopt', True): setsockopt_entry_handler,
        #('send', True): send_entry_handler,
        #('send', False): send_exit_handler,
        ('connect', True): socket_handlers.connect_entry_handler,
        #('connect', False): connect_exit_handler,
        #('getsockopt', True): getsockopt_entry_handler,
        ## ('sendmmsg', True): sendmmsg_entry_handler,
        #('sendto', True): sendto_entry_handler,
        #('sendto', False): sendto_exit_handler,
        #('shutdown', True): shutdown_subcall_entry_handler,
        #('recvmsg', True): recvmsg_entry_handler,
        #('recvmsg', False): recvmsg_exit_handler,
        #('getsockname', True): getsockname_entry_handler,
        #('getsockname', False): getsockname_exit_handler,
        #('getpeername', True): getpeername_entry_handler
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

def handle_syscall(pid, syscall_id, syscall_object, entering):
    ''' Validate the id of the system call against the name of the system call
    we are expecting based on the current system call object.  Then hand off
    responsiblity to the appropriate subcall handler.
    TODO: cosmetic - Reorder handler entrys numerically


    '''
    logging.debug('Handling syscall')
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
    #logging.debug('Checking syscall against execution')
    forgers = {
        13: time_handlers.time_forger,
    }
    # if there is a forger registerd, check for a mismatch between the called
    # syscall and the trace syscall -- indicating we need to forge a call that
    # isn't present in the trace
    if syscall_id in forgers.keys():
        if syscall_object.name != syscall_dict.SYSCALLS[syscall_id][4:]:
            forgers[syscall_id](pid)
            return
    util.validate_syscall(syscall_id, syscall_object)
    # We ignore these system calls because they have to do with aspecs of
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
    handlers = {
        ##(8, True): creat_entry_handler,
        #(8, False): check_return_value_exit_handler,
        ## These calls just get their return values checked ####
        ## (9, True): check_return_value_entry_handler,
        ## (9, False): check_return_value_exit_handler,
        #(12, True): syscall_return_success_handler,
        ## (195, True): check_return_value_entry_handler,
        ## (195, False): check_return_value_exit_handler,
        #(39, True): check_return_value_entry_handler,
        #(39, False): check_return_value_exit_handler,
        (45, True): kernel_handlers.brk_entry_handler,
        (45, False): kernel_handlers.brk_exit_handler,
        #(91, True): check_return_value_entry_handler,
        #(91, False): check_return_value_exit_handler,
        ## (125, True): check_return_value_entry_handler,
        ## (125, False): check_return_value_exit_handler,
        ## mmap2 calls are never replayed. Sometimes we must fix a file
        ## descriptor  in position 4.
        #(192, True): mmap2_entry_handler,
        #(192, False): mmap2_exit_handler,
        #(196, True): lstat64_entry_handler,
        #(10, True): unlink_entry_handler,
        #(10, False): check_return_value_exit_handler,
        #(20, True): syscall_return_success_handler,
        #(30, True): syscall_return_success_handler,
        #(38, True): rename_entry_handler,
        #(38, False): check_return_value_exit_handler,
        #(15, True): syscall_return_success_handler,
        #(78, True): gettimeofday_entry_handler,
        (13, True): time_handlers.time_entry_handler,
        #(27, True): syscall_return_success_handler,
        (5, True): file_handlers.open_entry_handler,
        #(5, False): open_exit_handler,
        #(60, True): syscall_return_success_handler,
        #(85, True): readlink_entry_handler,
        #(93, True): ftruncate_entry_handler,
        #(93, False): ftruncate_exit_handler,
        #(94, True): fchmod_entry_handler,
        #(94, False): check_return_value_entry_handler,
        #(145, True): readv_entry_handler,
        #(145, False): check_return_value_exit_handler,
        #(146, True): writev_entry_handler,
        #(146, False): writev_exit_handler,
        (197, True): file_handlers.fstat64_entry_handler,
        #(197, False): check_return_value_exit_handler,
        #(122, True): uname_entry_handler,
        #(183, True): getcwd_entry_handler,
        #(140, True): llseek_entry_handler,
        #(140, False): llseek_exit_handler,
        #(42, True): pipe_entry_handler,
        ## (43, True): times_entry_handler,
        ## (10, True): syscall_return_success_handler,
        #(33, True): syscall_return_success_handler,
        #(199, True): syscall_return_success_handler,
        #(200, True): syscall_return_success_handler,
        #(201, True): syscall_return_success_handler,
        #(202, True): syscall_return_success_handler,
        (4, True): file_handlers.write_entry_handler,
        #(4, False): file_handlers.write_exit_handler,
        (3, True): file_handlers.read_entry_handler,
        #(3, False): check_return_value_exit_handler,
        (6, True): file_handlers.close_entry_handler,
        #(6, False): close_exit_handler,
        (168, True): multiplex_handlers.poll_entry_handler,
        #(54, True): ioctl_entry_handler,
        #(54, False): ioctl_exit_handler,
        (174, True): kernel_handlers.rt_sigaction_entry_handler,
        (195, True): file_handlers.stat64_entry_handler,
        (221, True): file_handlers.fcntl64_entry_handler,
        #(195, False): check_return_value_exit_handler,
        #(141, True): getdents_entry_handler,
        #(142, False): getdents_exit_handler,
        #(142, True): select_entry_handler,
        #(82, True): select_entry_handler,
        #(196, True): lstat64_entry_handler,
        #(268, True): statfs64_entry_handler,
        #(265, True): clock_gettime_entry_handler,
        #(41, True): dup_entry_handler,
        #(41, False): dup_exit_handler,
        #(150, True): syscall_return_success_handler,
        #(186, True): sigaltstack_entry_handler,
        #(194, True): ftruncate64_entry_handler,
        #(194, False): ftruncate64_entry_handler,
        #(207, True): fchown_entry_handler,
        #(207, False): check_return_value_entry_handler,
        #(209, True): getresuid_entry_handler,
        #(211, True): getresgid_entry_handler,
        #(220, True): getdents64_entry_handler,
        #(220, False): getdents64_exit_handler,
        #(228, True): fsetxattr_entry_handler,
        #(228, False): fsetxattr_exit_handler,
        #(231, True): fgetxattr_entry_handler,
        #(231, False): fgetxattr_exit_handler,
        #(234, True): flistxattr_entry_handler,
        #(234, False): flistxattr_entry_handler,
        #(242, True): sched_getaffinity_entry_handler,
        #(243, True): syscall_return_success_handler,
        (254, True): multiplex_handlers.epoll_create_entry_handler,
        (255, True): multiplex_handlers.epoll_ctl_entry_handler,
        (256, True): multiplex_handlers.epoll_wait_entry_handler,
        #(258, True): set_tid_address_entry_handler,
        #(258, False): set_tid_address_exit_handler,
        #(259, True): timer_create_entry_handler,
        #(260, True): timer_settime_entry_handler,
        #(261, True): timer_gettime_entry_handler,
        #(263, True): timer_delete_entry_handler,
        #(265, True): clock_gettime_entry_handler,
        #(271, True): syscall_return_success_handler,
        #(272, True): fadvise64_64_entry_handler,
        #(272, False): check_return_value_exit_handler,
        #(295, True): openat_entry_handler,
        #(295, False): openat_exit_handler,
        #(300, True): fstatat64_entry_handler,
        #(300, False): check_return_value_exit_handler,
        #(301, True): unlinkat_entry_handler,
        #(301, False): check_return_value_exit_handler,
        #(311, True): syscall_return_success_handler,
        #(320, True): utimensat_entry_handler,
        #(320, False): check_return_value_exit_handler,
        #(328, True): eventfd2_entry_handler,
        #(340, True): prlimit64_entry_handler,
        #(345, True): sendmmsg_entry_handler,
        #(345, False): sendmmsg_exit_handler
        }
    if syscall_id not in ignore_list:
        try:
            handlers[(syscall_id, entering)](syscall_id, syscall_object, pid)
        except KeyError:
            raise NotImplementedError('Encountered un-ignored syscall {} '
                                      'with no handler: {}({})'
                                      .format('entry' if entering else 'exit',
                                              syscall_id,
                                              syscall_object.name))


if __name__ == '__main__':
    pid = int(sys.argv[1])
    event = sys.argv[2]
    trace = Trace.Trace(sys.argv[3])
    syscalls = trace.syscalls
    syscall_index = int(sys.argv[4])
    syscall_index_end = int(sys.argv[5])
    state_file = sys.argv[6]
    with open(state_file, 'r') as f:
        syscallreplay.injected_state = json.load(f)
    os.remove(state_file)
    # Requires kernel.yama.ptrace_scope = 0
    # in /etc/sysctl.d/10-ptrace.conf
    # on modern Ubuntu
    print("Injecting", pid)
    syscallreplay.attach(pid)
    syscallreplay.syscall(pid)
    # We need an additional call to PTRACE_SYSCALL here in order to skip
    # past an rr syscall buffering related injected system call
    syscallreplay.syscall(pid)
    print("Continuing", pid)
    syscallreplay.entering_syscall = True
    _, status = os.waitpid(pid, 0)
    while not os.WIFEXITED(status):
        syscall_object = syscalls[syscall_index]
        handle_syscall(pid, syscallreplay.peek_register(pid, syscallreplay.ORIG_EAX), syscall_object, syscallreplay.entering_syscall)
        if not syscallreplay.entering_syscall:
            syscall_index += 1
        syscallreplay.entering_syscall = not syscallreplay.entering_syscall
        syscallreplay.syscall(pid)
        _, status = os.waitpid(pid, 0)
        if syscall_index == syscall_index_end:
            print('Completed the trace')
            os.kill(pid, SIGTERM)
            sys.exit(0)
