"""Run rr and attach injectors appropriately based on the specified config
"""
from __future__ import print_function

import os
import os.path
import signal
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
    sections = cfg.sections()
    rr_dir_section = sections[0]
    rr_dir = cfg.get(rr_dir_section, 'rr_dir')
    sections = sections[1:]
    for i in sections:
        subjects.append({'event': cfg.get(i, 'event'),
                         'rec_pid': cfg.get(i, 'pid'),
                         'trace_file': cfg.get(i, 'trace_file'),
                         'trace_start': cfg.get(i, 'trace_start'),
                         'trace_end': cfg.get(i, 'trace_end'),
                         'injected_state': str(cfg.get(i, 'event')) + '_state.json',
                         'other_procs': [],})
    events_str = ''
    for i in subjects:
        events_str += i['rec_pid'] + ':' + i['event'] + ','
    command = ['rr', 'replay', '-a', '-n', events_str, rr_dir]
    f = open('proc.out', 'w')
    proc = subprocess.Popen(command, stdout=f, stderr=f)
    while not os.path.exists('rrdump_proc.pipe'):
        continue
    f = open('rrdump_proc.pipe', 'r')
    buf = ''
    subject_index = 0
    handles = []
    # A message on the pipe looks like:
    # INJECT: EVENT: <event number> PID: <pid> REC_PID: <rec_pid>\n
    # or
    # DONT_INJECT: EVENT: <event number> PID: <pid> REC_PID: <rec_pid>\n
    subjects_injected = 0
    while True:
        buf += f.read(1)
        if buf[-1] == '\n':
            parts = buf.split(' ')
            inject = parts[0].strip()[:-1]
            event = parts[2]
            pid = parts[4]
            rec_pid = parts[6].strip()

            operating = [x for x in subjects if x['event'] == event]
            # HACK HACK HACK: we only support spinning off once per event now
            s = operating[0]
            if inject == 'INJECT':
                s['pid'] = pid
                s['handle'] =  subprocess.Popen(['python',
                                                 './inject.py',
                                                 s['pid'],
                                                 s['event'],
                                                 s['trace_file'],
                                                 s['trace_start'],
                                                 s['trace_end'],
                                                 s['injected_state']])
                subjects_injected += 1
            elif inject == 'DONT_INJECT':
                s['other_procs'].append(pid)
            if subjects_injected == len(subjects):
                break
            buf = ''
    f.close()
    os.unlink('rrdump_proc.pipe')
    for s in subjects:
        ret = s['handle'].wait()
        for i in s['other_procs']:
            try:
                os.kill(int(i), signal.SIGKILL)
            except OSError:
                pass
        if ret != 0:
            print('Injector for event:rec_pid {}:{} failed'
                  .format(s['event'], s['rec_pid']))
    f.close()
    os.unlink('proc.out')
