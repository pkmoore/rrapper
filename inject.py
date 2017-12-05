from __future__ import print_function
import sys
import os
from syscallreplay import syscallreplay
from syscallreplay import file_handlers


if __name__ == '__main__':
    pid = int(sys.argv[1])
    # Requires kernel.yama.ptrace_scope = 0
    # in /etc/sysctl.d/10-ptrace.conf
    # on modern Ubuntu
    print("Injecting", pid)
    syscallreplay.attach(pid)
    syscallreplay.syscall(pid)
    print("Continuing", pid)
    result = os.waitpid(pid, 0)
    print("initial wait:", os.WIFEXITED(result[1]))
    while not os.WIFEXITED(result[1]):
        syscallreplay.syscall(pid)
        print(syscallreplay.peek_register(pid, syscallreplay.ORIG_EAX))
        result = os.waitpid(pid, 0)
    #syscallreplay.sigcont(pid)
    #syscallreplay.sigcont(pid)
