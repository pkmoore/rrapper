#!/usr/bin/env python2.7
# pylint: disable=missing-docstring, bad-indentation, too-many-locals
"""
<Program Name>
  rrtest

<Started>
  July 2018

<Author>
  Alan Cao

<Purpose>
  Automates the creation of CrashSimulator-compliant tests.

  This application-level script enables the user to perform a preemptive record and
  replay execution, such that a strace segment is produced. This strace can then
  be compared against a ReplaySession debug log in order to determine corresponding
  events and trace lines, such that a final test can be produced and stored. Once
  complete, a user can utilize `rreplay` in order to execute another replay execution.

"""

from __future__ import print_function

import os
import sys
import argparse
import subprocess
import re
import logging
import shutil
import errno
import ConfigParser

import consts


def find_first_execve(lines):
  """
  <Purpose>
    This method looks through a specified list of lines,
    uses a regex to determine where a execve call is made,
    and returns the line number through enumerate()

  <Returns>
    line: integer representing line number

  """

  for line, content in enumerate(lines):
    if re.search('.*execve.*', content):
      return line
  return None




def rr_copy(src, dest):
  """
  <Purpose>
    Utilizes shutil's high-level copytree method in order
    to copy any filetype from one destination to another.
    It also ensures that ENOTDIR is handled properly by
    attempting a regular copy.

  <Returns>
    None

  """

  try:
    shutil.copytree(src, dest)
  except OSError as exc:
    if exc.errno == errno.ENOTDIR:
      shutil.copy(src, dest)
    else:
      raise



def main():
  # initialize parser
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers()

  # two commands - create / configure
  create_group = subparsers.add_parser('create')
  configure_group = subparsers.add_parser('configure')

  # ./rrtest create -n testname -c "./runthisbinary"
  create_group.set_defaults(cmd='create')
  create_group.add_argument('-n', '--name',
                            dest='name',
                            help='name of the test to be created')
  create_group.add_argument('-c', '--command',
                            dest='command',
                            help='specify command for rrtest')

  # ./rrtest configure -n testname -e EVENT_NUM
  configure_group.set_defaults(cmd='configure')
  configure_group.add_argument('-n', '--name',
                               dest='name',
                               help='name of the test to be configured')
  configure_group.add_argument('-t', '--traceline',
                               dest='trace_line',
                               type=int,
                               help='specific strace line to examine for replay')
  configure_group.add_argument('-s', '--sniplen',
                               dest='sniplen',
                               default=5,
                               type=int,
                               help='number of lines to create a strace snippet')

  # general flags to be set
  parser.add_argument('-v', '--verbosity',
                      dest='verbosity',
                      action='store_const',
                      const=logging.DEBUG,
                      help='flag for displaying debug information')

  # parse arguments
  args = parser.parse_args()

  # configure logger
  logging.basicConfig(level=args.verbosity)

  # initialize actual application logic
  if args.cmd == 'create':

    # check for mandatory arguments
    man_options = ['name', 'command']
    for opt in man_options:
      if not args.__dict__[opt]:
        parser.print_help()
        sys.exit(1)

    # initialize test directory in ~/.crashsim/xxxxx
    test_dir = consts.DEFAULT_CONFIG_PATH + args.name + "/"
    try:
      os.makedirs(test_dir)
    except OSError as err:
      if err.errno != errno.EEXIST:
        raise

    # call rr to record the command passed, store results within test directory
    # subprocess.call with shell=True is used, such that shell command formatting is
    # preserved. TODO: improve, if necessary.
    rr_create_record = ['rr', 'record', '-n', '-q', args.command]
    subprocess.call(" ".join(rr_create_record), shell=True)

    # retrieve latest trace through latest-trace linked file
    testname = os.path.realpath(consts.RR_TEST_CONFIG_PATH + "latest-trace")

    # copy rr recorded test into our own directory
    #rr_copy(testname, test_dir + testname)

    # copy rr produced strace into our own directory
    rr_copy(consts.STRACE_DEFAULT, test_dir + consts.STRACE_DEFAULT)

    # create INI config file
    config = ConfigParser.ConfigParser()
    config.add_section("rr_recording")
    config.set("rr_recording", "rr_dir", testname)

    config.add_section("request_handling_process")
    config.set("request_handling_process", "event", None)
    config.set("request_handling_process", "pid", None)
    config.set("request_handling_process", "trace_file", test_dir + consts.STRACE_DEFAULT)
    config.set("request_handling_process", "trace_start", 0)
    config.set("request_handling_process", "trace_end", 0)

    # write config file
    with open(test_dir + "config.ini", 'wb') as config_file:
      config.write(config_file)

    # output trace to STDOUT for user to determine proper trace line
    with open(test_dir + consts.STRACE_DEFAULT, 'r') as trace:
      print(trace.read())
    sys.exit(0)

  elif args.cmd == 'configure':

    # check for mandatory arguments
    man_options = ['name', 'trace_line']
    for opt in man_options:
      if not args.__dict__[opt]:
        parser.print_help()
        sys.exit(1)

    # check if config file exists
    test_dir = consts.DEFAULT_CONFIG_PATH + args.name + "/"
    if not os.path.exists(test_dir):
      print("Test '{}' does not exist. Create before attempting to configure!" \
              .format(args.name))
      sys.exit(1)

    # read config file for rr test directory
    config = ConfigParser.ConfigParser()
    config.read(test_dir + "config.ini")
    testname = config.get("rr_recording", "rr_dir")

    # create command and set proper environmental variable
    os.environ['RR_LOG'] = 'ReplaySession'
    rr_config_replay = ['rr', 'replay', '-a', testname]

    # execute replay command, this time to compare against trace. We write the
    # ReplaySession output to replaysession.log
    out_fd = open(test_dir + "replaysession.log", 'wb')
    proc = subprocess.Popen(rr_config_replay, stdout=out_fd, stderr=out_fd)
    while proc.poll() is None:
      pass
    out_fd.close()

    # open log for reading
    with open(test_dir + "replaysession.log", 'r') as test_log:
      rr_lines = test_log.readlines()

    # open trace file for reading
    with open(test_dir + consts.STRACE_DEFAULT, 'r') as trace_file:
      trace_lines = trace_file.readlines()

    # strip and breakdown pid
    pid = trace_lines[0].split()[0]

    # retrieve system call name
    line = trace_lines[args.trace_line - 1]
    name = line.split('  ')[1]
    name = name[:name.find('(')]

    rr_lines = [x for x in rr_lines if re.search(r'.*ENTERING_SYSCALL', x)]
    rr_lines = rr_lines[find_first_execve(rr_lines):]
    rr_lines = [x for x in rr_lines if not re.search(r'replaying SYSCALL: time;', x)]

    # store a list of potential events
    potentials = []
    for idx, val in enumerate(rr_lines):
      if re.search(name, val):
        potentials.append(idx)

    # output each potential event, plus lines that come before and after it.
    for i in potentials:
      event_num = re.search(r'event [0-9]*', rr_lines[i]).group(0).split(' ')[1]
      print('--- Potential event: {}'.format(event_num))
      for j in rr_lines[i-5:i+5]:
        print(j, end='')
      print('---')

    # TODO: advanced regexes to automatically grab event number
    user_event = input("\n\nEnter event number: ")

    # create a new strace snippet, with the event as the first line
    with open(test_dir + "trace_snip.strace", 'wb') as snip_file:
      # write a 5 line snippet file by default
      for i in range(args.sniplen):
        try:
          snip_file.write(trace_lines[args.trace_line - 1 + i])
        except IndexError:
          break

    # update changes in config.ini
    config.set("request_handling_process", "trace_file", test_dir + "trace_snip.strace")
    config.set("request_handling_process", "event", user_event)
    config.set("request_handling_process", "pid", pid)
    config.set("request_handling_process", "trace_end", args.sniplen)

    # write final changes to config file
    with open(test_dir + "config.ini", 'w+') as config_file:
      config.write(config_file)

    sys.exit(0)





if __name__ == '__main__':
    main()
