"""Find the event number associated with a line from an strace trace
"""
from __future__ import print_function

import os
import sys
import subprocess
import re
import ConfigParser
import time

def find_first_execve(lines):
    for i, v in enumerate(lines):
        if re.search('.*execve.*', v):
            return i

if __name__ == '__main__':
    strace_file = sys.argv[1]
    line_no = int(sys.argv[2])
    os.environ['RR_LOG'] = 'ReplaySession'
    f = open('proc.out', 'w', 0)
    subjects = []
    command = ['rr', 'replay', '-a']
    proc = subprocess.Popen(command, stdout=f, stderr=f)
    time.sleep(3)
    f.close()
    f = open('proc.out', 'r')
    lines = f.readlines()
    os.unlink('proc.out')
    assert lines
    lines = [x for x in lines if re.search(r'.*ENTERING_SYSCALL', x)]
    lines = lines[find_first_execve(lines):]

    pre_context = lines[:line_no]
    pre_context = pre_context[-5:]
    post_context = lines[line_no:]
    post_context = post_context[:5]

    for i in pre_context:
        print(i, end='')
    print("!!!")
    for i in post_context:
        print(i, end='')
