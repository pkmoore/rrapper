import os

from syscallreplay import generic_handlers
from syscallreplay import file_handlers
from syscallreplay import kernel_handlers
from syscallreplay import socket_handlers
from syscallreplay import recv_handlers
from syscallreplay import send_handlers
from syscallreplay import time_handlers
from syscallreplay import multiplex_handlers
from syscallreplay import util


def _socket_subcall_dispatcher(syscall_id, syscall_object, entering, pid):
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

def arch_get_handlers():
  arch = os.getenv('CRASHSIM_ARCH')
  if arch == 'x86':
    return x86_handlers
  elif arch == 'x86_64':
    return x86_64_handlers
  else:
    raise RuntimeError('CRASHSIM_ARCH environment variable not set. '
                       'Valid values are \'x86\' and \'x86_64\'')


def arch_get_debug_printers():
  arch = os.getenv('CRASHSIM_ARCH')
  if arch == 'x86':
    return x86_debug_printers
  elif arch == 'x86_64':
    return x86_64_debug_printers
  else:
    raise RuntimeError('CRASHSIM_ARCH environment variable not set. '
                       'Valid values are \'x86\' and \'x86_64\'')


def arch_get_forgers():
  arch = os.getenv('CRASHSIM_ARCH')
  if arch == 'x86':
    return x86_forgers
  elif arch == 'x86_64':
    return x86_64_forgers
  else:
    raise RuntimeError('CRASHSIM_ARCH environment variable not set. '
                       'Valid values are \'x86\' and \'x86_64\'')



# These represent the handlers for system calls that we have chosen not to
# ignore. The key represents a tuple of the ID and the state (entering the
# syscall or exiting), and the value is the respective syscallreplay handler.
x86_64_handlers = {
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


x86_64_debug_printers = {
  1: file_handlers.write_entry_debug_printer,
  2: file_handlers.open_entry_debug_printer,
  5: file_handlers.fstat64_entry_debug_printer,
  20: file_handlers.writev_entry_debug_printer,
}


x86_64_forgers = {

}


x86_handlers = {
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
  (102, True): _socket_subcall_dispatcher,
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


x86_debug_printers = {
  4: file_handlers.write_entry_debug_printer,
  5: file_handlers.open_entry_debug_printer,
  197: file_handlers.fstat64_entry_debug_printer,
  146: file_handlers.writev_entry_debug_printer,
}


x86_forgers = {
  13: time_handlers.time_forger,
  78: time_handlers.gettimeofday_forger,
  265: time_handlers.clock_gettime_forger,
}
