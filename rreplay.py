"""Run rr and attach injectors appropriately based on the specified config
"""
from __future__ import print_function

import os
import os.path
import sys
import subprocess
import re
import ConfigParser
import time


if __name__ == '__main__':
    if os.path.exists('rrdump_proc.pipe'):
        os.unlink('rrdump_proc.pipe')
    cfg = ConfigParser.SafeConfigParser()
    cfg.read(sys.argv[1])
    #os.environ['RR_LOG'] = 'ReplaySession'
    subjects = []
    for i in cfg.sections():
        subjects.append({'event': cfg.get(i, 'event'),
                         'trace_file': cfg.get(i, 'trace_file'),
                         'trace_start': cfg.get(i, 'trace_start'),
                         'trace_end': cfg.get(i, 'trace_end')})
    events_str = ''
    for i in subjects:
        events_str += i['event'] + ','
    command = ['rr', 'replay', '-a', '-n', events_str]
    proc = subprocess.Popen(command)

    while not os.path.exists('rrdump_proc.pipe'):
        continue
    f = open('rrdump_proc.pipe', 'r')
    buf = ''
    subject_index = 0
    handles = []
    # A message on the pipe looks like:
    # EVENT: <event number> PID: <pid>\n
    while True:
        buf += f.read(1)
        if buf[-1] == '\n':
            s = subjects[subject_index]
            # The pid we want is in index 3 of the split message list
            s['pid'] = buf.split(' ')[3]
            handles.append({'event': i['event'],
                            'handle': subprocess.Popen(['python',
                                                        './inject.py',
                                                        s['pid'],
                                                        s['event'],
                                                        s['trace_file'],
                                                        s['trace_start'],
                                                        s['trace_end'],
                                                        str(s['event']) +
                                                        '_state.json'])})
            subject_index += 1
        if subject_index == len(subjects):
            break
    f.close()
    os.unlink('rrdump_proc.pipe')
    for h in handles:
        if h['handle'].wait() != 0:
            print('Injector for event {} failed'.format(h['event']))
