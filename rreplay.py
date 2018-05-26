#!/usr/bin/env python

"""
Run rr and attach injectors appropriately based on the specified config
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
import json
import commands

# TODO: maybe a more functional approach, rather than use a global declaration?
rrdump_pipe = None
def _get_message(pipe_name):
    global rrdump_pipe

    # check if pipe path exists
    if not rrdump_pipe:
        while not os.path.exists(pipe_name):
            continue
        rrdump_pipe = open(pipe_name, 'r')

    # read message from pipe into buffer, and return
    buf = ''
    while True:
        buf += rrdump_pipe.read(1)
        if buf == '':
            return ''
        if buf[-1] == '\n':
            return buf

def main():

    # check to see if rrdump pipe exists, and if so, unlink
    if os.path.exists('rrdump_proc.pipe'):
        os.unlink('rrdump_proc.pipe')

    # check to see rr is a valid shell-level command
    status, _ = commands.getstatusoutput('rr help')
    if status != 0:
        print("Unable to call rr command. Is it installed or in PATH?")
        exit(1)

    # ensure that positional argument is passed to represent path to config
    if len(sys.argv) < 2:
        print("Invalid number of arguments:\n\tpython rreplay.py [CONFIG_PATH]\n")
        exit(1)

    # ensure that the specified configuration file exists
    if not os.path.isfile(sys.argv[1]) is True:
        print("INI configuration file does not exist: %s", sys.argv[1])

    # instantiate new SafeConfigParser, read path to config
    print("-- Begin parsing INI configuration file")
    cfg = ConfigParser.SafeConfigParser()
    cfg.read(sys.argv[1])

    # instantiate vars and parse config by retrieving sections
    subjects = []
    sections = cfg.sections()

    # set rr_dir as specified key-value pair in config, cut out first element in list
    print("-- Discovering replay directory")
    rr_dir_section = sections[0]
    rr_dir = cfg.get(rr_dir_section, 'rr_dir')
    sections = sections[1:]

    # for each following item
    for i in sections:
        s = {}
        s['event'] = cfg.get(i, 'event')
        s['rec_pid'] = cfg.get(i, 'pid')
        s['trace_file'] = cfg.get(i, 'trace_file')
        s['trace_start'] = cfg.get(i, 'trace_start')
        s['trace_end'] = cfg.get(i, 'trace_end')
        s['injected_state_file'] = str(cfg.get(i, 'event')) + '_state.json'
        s['other_procs'] = []

        # mmap_backing_files is optional if we aren't using that feature
        try:
            s['mmap_backing_files'] = cfg.get(i, 'mmap_backing_files')
        except ConfigParser.NoOptionError:
            pass
        subjects.append(s)

    # create a new event string listing pid to record and event to listen for (e.g 14350:16154)
    events_str = ''
    for i in subjects:
        events_str += i['rec_pid'] + ':' + i['event'] + ','

    print("-- Executing replay command and writing to proc.out")
    # instantiate thread-safe OS-executed command with output tossed into proc.out
    command = ['rr', 'replay', '-a', '-n', events_str, rr_dir]
    f = open('proc.out', 'w')
    proc = subprocess.Popen(command, stdout=f, stderr=f)

    subject_index = 0
    handles = []

    # A message on the pipe looks like:
    # INJECT: EVENT: <event number> PID: <pid> REC_PID: <rec_pid>\n
    # or
    # DONT_INJECT: EVENT: <event number> PID: <pid> REC_PID: <rec_pid>\n
    subjects_injected = 0
    while True:
        message = _get_message('rrdump_proc.pipe')
        parts = message.split(' ')
        inject = parts[0].strip()[:-1]
        event = parts[2]
        pid = parts[4]
        rec_pid = parts[6].strip()

        operating = [x for x in subjects if x['event'] == event]

        # HACK HACK HACK: we only support spinning off once per event now
        s = operating[0]
        if inject == 'INJECT':
            with open(s['injected_state_file'], 'r') as d:
                tmp = json.load(d)
            s['pid'] = pid
            tmp['config'] = s
            with open(s['injected_state_file'], 'w') as d:
                json.dump(tmp, d)
            s['handle'] =  subprocess.Popen(['python',
                                             './inject.py',
                                             s['injected_state_file']])
            subjects_injected += 1
        elif inject == 'DONT_INJECT':
            s['other_procs'].append(pid)
        if subjects_injected == len(subjects):
            break

    # TODO: interpret and understand
    for s in subjects:
        if 'handle' in s:
            ret = s['handle'].wait()
        else:
            print('No handle associated with subject {}'.format(s))
            ret = -1
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
    os.unlink('rrdump_proc.pipe')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("! Killing rrapper\nDumping proc.out")

        # read output
        with open('proc.out', 'r') as content_file:
            print(content_file.read())

        # ensure clean exit by unlinking
        os.unlink('proc.out')
        os.unlink('rrdump_proc.pipe')
        exit(0)
