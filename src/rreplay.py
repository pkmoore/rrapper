#!/usr/bin/env python2
# pylint: disable=bad-indentation, unused-argument, invalid-name,
"""
<Program Name>
  rreplay.py

<Started>
  November 2017

<Author>
  Preston Moore
  Alan Cao

<Purpose>
  Performs a replay of a rrtest-formatted test, parsing the config.ini
  file and hooking onto the rrdump pipe for data from the modified rr
  process. This allows us to then call upon the injector, which compares
  the trace against the execution for divergences / deltas.

"""


from __future__ import print_function

import os
import signal
import sys
import subprocess
import ConfigParser
import json
import logging
import argparse

import consts
import syscallreplay.util as util


# pylint: disable=global-statement
rrdump_pipe = None


def get_message(pipe_name):
  """
  <Purpose>
    Opens a named pipe for communication between
    modified rr and rreplay. This allows for messages
    to be read and returned in a buffer for further processing.

  <Returns>
    buf: a list of messages collected from the named pipe

  """
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
  """
  <Purpose>

  <Returns>
    rr_dir: the directory in which the rr-generated trace files are stored
    subjects: a list of dicts that store parsed items from the config INI path

  """
  # instantiate new SafeConfigParser, read path to config
  logging.debug("-- Begin parsing INI configuration file")
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
  logging.debug("-- Discovering replay directory")
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
    # checkers are also optional
    try:
      s['checker'] = cfg.get(i, 'checker')
    except ConfigParser.NoOptionError:
      pass
    try:
      s['mutator'] = cfg.get(i, 'mutator')
    except ConfigParser.NoOptionError:
      pass

    subjects.append(s)
  return rr_dir, subjects





def execute_rr(rr_dir, subjects):
  """
  <Purpose>
    Create a new event string with pid and event for rr replay,
    and then actually execute rr with the string.

  <Returns>
    None

  """
  # create a new event string listing pid to record and event to listen for
  # (e.g 14350:16154)
  events_str = ''
  for i in subjects:
    events_str += i['rec_pid'] + ':' + i['event'] + ','

  my_env = os.environ.copy()
  logging.debug("-- Executing replay command and writing to proc.out")
  # execute rr with spin-off switch.  Output tossed into proc.out
  command = ['rr', 'replay', '-a', '-n', events_str, rr_dir]
  with open('proc.out', 'w') as f:
    subprocess.Popen(command, stdout=f, stderr=f, env=my_env)





def process_messages(subjects):
  """
  <Purpose>
    Retrieves messages from the specified named pipe, and parse
    accordingly. Once inject events are retrieved, a JSON file
    is generated and the injector is called to work accordingly.

    A message on the pipe looks like:
    INJECT: EVENT: <event number> PID: <pid> REC_PID: <rec_pid>\n
    or
    DONT_INJECT: EVENT: <event number> PID: <pid> REC_PID: <rec_pid>\n

  <Returns>
    None

  """
  subjects_injected = 0
  message = get_message('rrdump_proc.pipe')
  while message != '':
    parts = message.split(' ')
    inject = parts[0].strip()[:-1]
    event = parts[2]
    pid = parts[4]
    # Wait until we can see the process reported by rr to continue
    while not util.process_is_alive(pid):
      print('waiting...')
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

      s['handle'] = subprocess.Popen(['inject',
                                      s['injected_state_file']])
      subjects_injected += 1
    elif inject == 'DONT_INJECT':
      s['other_procs'].append(pid)
    message = get_message('rrdump_proc.pipe')





def wait_on_handles(subjects):
  """
  <Purpose>
    Wait on handles for each subject. Ensure that other procs
    are killed accordingly with SIGKILL.

  <Returns>
    None

  """
  for s in subjects:

    # check if handle is in subject
    if 'handle' in s:
      ret = s['handle'].wait()
    else:
      print('No handle associated with subject {}'.format(s))
      ret = -1

    # check for other procs
    for i in s['other_procs']:
      try:
        os.kill(int(i), signal.SIGKILL)
      except OSError:
        pass

    # print error if return value != 0
    if ret != 0:
      print('Injector for event:rec_pid {}:{} failed'
            .format(s['event'], s['rec_pid']))





def cleanup():
  """
  <Purpose>
    Delete generated output file and pipe if necessary.

  <Returns>
    None

  """
  if os.path.exists('proc.out'):
    os.unlink('proc.out')
  if os.path.exists('rrdump_proc.pipe'):
    os.unlink('rrdump_proc.pipe')





def main():
  # initialize argparse
  parser = argparse.ArgumentParser()
  parser.add_argument('-v', '--verbosity',
                      dest='loglevel',
                      action='store_const',
                      const=logging.DEBUG,
                      help='flag for displaying debug information')
  parser.add_argument('testname',
                      help='specify rrtest-created test for replay')

  # parse arguments
  args = parser.parse_args()

  # add simple logging for verbosity
  logging.basicConfig(level=args.loglevel)

  # ensure that a pre-existing pipe is unlinked before execution
  if os.path.exists('rrdump_proc.pipe'):
    os.unlink('rrdump_proc.pipe')

  # check if user-specified test exists
  test_dir = consts.DEFAULT_CONFIG_PATH + args.testname
  if not os.path.exists(test_dir):
    print("Test {} does not exist. Create before attempting to configure!" \
            .format(args.testname))
    sys.exit(1)

  # read config.ini from the test directory
  rr_dir, subjects = get_configuration(test_dir + "/" + "config.ini")

  # execute rr
  execute_rr(rr_dir, subjects)

  # process pipe messages
  process_messages(subjects)

  # wait on handles
  wait_on_handles(subjects)

  # cleanup routine
  cleanup()





if __name__ == '__main__':
  try:
    main()
    sys.exit(0)

  # if there is some sort of hanging behavior, we can cleanup if user sends a
  # SIGINT
  except KeyboardInterrupt:
    logging.debug("Killing rreplay.\nDumping proc.out")

    # read output
    with open('proc.out', 'r') as content_file:
      print(content_file.read())

    # ensure clean exit by unlinking
    cleanup()
    sys.exit(0)

  # catch any other sort of exception that may occur, and ensure proper cleanup
  # is still performed
  except Exception:
    cleanup()
    sys.exit(1)
