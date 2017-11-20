from __future__ import print_function

import os
import sys
import subprocess
import re
import ConfigParser
import time
from syscallreplay import syscallreplay


if __name__ == '__main__':
    cfg  = ConfigParser.SafeConfigParser()
    cfg.read(sys.argv[1])
    #os.environ['RR_LOG'] = 'ReplaySession'
    f = open('proc.out', 'w', 0)
    for i in cfg.sections():
        command = ['rr', 'replay', '-a', '-n', cfg.get(i, 'event')]
        proc = subprocess.Popen(command, stdout=f, stderr=f)
    time.sleep(3)
    f.close()
    f = open('proc.out', 'r')
    lines = f.readlines()
    for i in lines:
        print(i.strip())
    lines = [x.strip().split(' ') for x in lines if re.match('EVENT: [0-9]+ PID: [0-9]+', x)]
    procs = [{'event': x[1], 'pid': x[3]} for x in lines]
    print(procs)
    for i in procs:
        syscallreplay.attach(int(i['pid']))
        syscallreplay.sigcont(int(i['pid']))
        syscallreplay.sigcont(int(i['pid']))
