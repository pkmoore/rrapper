#!/usr/bin/env python2
# pylint: disable=missing-docstring, unused-argument, invalid-name,
"""Run rr and attach injectors appropriately based on the specified config
"""
from __future__ import print_function

import os
import os.path
import signal
import subprocess
import ConfigParser
import json
import commands
import logging
import argparse

logger = None

# pylint: disable=global-statement
rrdump_pipe = None


def get_message(pipe_name):
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
# pylint: enable=global-statement


def get_configuration(ini_path):
    # instantiate new SafeConfigParser, read path to config
    logger.debug("-- Begin parsing INI configuration file")
    cfg = ConfigParser.SafeConfigParser()
    found = cfg.read(ini_path)
    if ini_path not in found:
        raise IOError('INI configuration could not be read: {}'
                      .format(ini_path))

    # instantiate vars and parse config by retrieving sections
    subjects = []
    sections = cfg.sections()

    # set rr_dir as specified key-value pair in config, cut out first element
    # in list
    logger.debug("-- Discovering replay directory")
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
    return rr_dir, subjects


def execute_rr(rr_dir, subjects):
    # create a new event string listing pid to record and event to listen for
    # (e.g 14350:16154)
    events_str = ''
    for i in subjects:
        events_str += i['rec_pid'] + ':' + i['event'] + ','

    logger.debug("-- Executing replay command and writing to proc.out")
    # execute rr with spin-off switch.  Output tossed into proc.out
    command = ['rr', 'replay', '-a', '-n', events_str, rr_dir]
    with open('proc.out', 'w') as f:
        subprocess.Popen(command, stdout=f, stderr=f)


def process_messages(subjects):
    # A message on the pipe looks like:
    # INJECT: EVENT: <event number> PID: <pid> REC_PID: <rec_pid>\n
    # or
    # DONT_INJECT: EVENT: <event number> PID: <pid> REC_PID: <rec_pid>\n
    subjects_injected = 0
    message = get_message('rrdump_proc.pipe')
    while message != '':
        parts = message.split(' ')
        inject = parts[0].strip()[:-1]
        event = parts[2]
        pid = parts[4]

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
            s['handle'] = subprocess.Popen(['python',
                                            './inject.py',
                                            s['injected_state_file']])
            subjects_injected += 1
        elif inject == 'DONT_INJECT':
            s['other_procs'].append(pid)
        message = get_message('rrdump_proc.pipe')


def wait_on_handles(subjects):
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


def cleanup():
    os.unlink('proc.out')
    os.unlink('rrdump_proc.pipe')


def main(ini_path):
    rr_dir, subjects = get_configuration(ini_path)
    execute_rr(rr_dir, subjects)
    process_messages(subjects)
    wait_on_handles(subjects)
    cleanup()


def parse_arguments():
    # initialize argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-v',
                        '--verbosity',
                        dest='verbosity',
                        help='output based on verbosity level')
    parser.add_argument('path',
                        help='specify INI configuration path for replay')

    return parser.parse_args()


def configure_logging(level):
    # pylint: disable=global-statement
    global logger
    log_levels = {"1": logging.INFO, "2": logging.DEBUG}
    logging.basicConfig(level=log_levels.get(args.verbosity, logging.ERROR))
    # set level of logging based on argument parsing
    logger = logging.getLogger(__name__)
    # pylint: enable=global-statement


def check_environment(ini_path):
    # check to see if rrdump pipe exists, and if so, unlink
    if os.path.exists('rrdump_proc.pipe'):
        os.unlink('rrdump_proc.pipe')

    # check to see rr is a valid shell-level command. Error status is nonzero
    status, _ = commands.getstatusoutput('rr help')
    if status != 0:
        logger.debug("Unable to call rr command. Is it installed or in PATH?")
        exit(1)


if __name__ == '__main__':
    args = parse_arguments()
    configure_logging(args.verbosity)
    check_environment(args.path)

    try:
        main(args.path)
    except KeyboardInterrupt:
        logger.debug("Killing rrapper\nDumping proc.out")

        # read output
        with open('proc.out', 'r') as content_file:
            print(content_file.read())

        # ensure clean exit by unlinking
        cleanup()
        exit(0)
