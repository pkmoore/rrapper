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
    while proc.poll() == None:
        pass
    f.close()
    f = open('proc.out', 'r')
    lines = f.readlines()
    os.unlink('proc.out')
    assert lines
    l = open(strace_file).readlines()
    line = l[line_no-1]
    name = line.split('  ')[1]
    name = name[:name.find('(')]

    lines = [x for x in lines if re.search(r'.*ENTERING_SYSCALL', x)]
    lines = lines[find_first_execve(lines):]
    lines = [x for x in lines if not re.search(r'replaying SYSCALL: time;', x)]

    potentials = []
    for idx, val in enumerate(lines):
        if re.search(name, val):
            potentials.append(idx)

    for i in potentials:
        event_num = re.search(r'event [0-9]*', lines[i]).group(0).split(' ')[1]
        print('--- Potential event: {}'.format(event_num))
        for j in lines[i-5:i+5]:
            print(j, end='')
        print('---')

