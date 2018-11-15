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

from posix_omni_parser import Trace
from checker.checker import NullChecker

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
    to copy any filetype (including dirs) from one destination
    to another. It also ensures that ENOTDIR is handled properly by
    attempting a regular copy.

  <Returns>
    None

  """

  try:
    # check if path is a directory
    if os.path.isdir(src):
      for item in os.listdir(src):
        s_file = os.path.join(src, item)
        d_file = os.path.join(dest, item)
        if os.path.isdir(s_file):
          shutil.copytree(s_file, d_file)
        else:
          shutil.copy2(s_file, d_file)

    # otherwise copy the filetype normally
    else:
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
  list_group = subparsers.add_parser('list')
  pack_group = subparsers.add_parser('pack')
  analyze_group = subparsers.add_parser('analyze')

  # ./rrtest create -n testname -c "./runthisbinary"
  create_group.set_defaults(cmd='create')
  create_group.add_argument('-n', '--name',
                            dest='name',
                            help='name of the test to be created')
  create_group.add_argument('-c', '--command',
                            dest='command',
                            help='specify command for rrtest')
  create_group.add_argument('-f', '--force',
                            dest='force',
                            help='force overwrite creation of the test')

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
  configure_group.add_argument('-e', '--event',
                               dest='event',
                               help='event number')

  configure_group.add_argument('-m', '--mutator',
                               dest='mutator',
                               help='mutator to use')

  # ./rrtest list
  list_group.set_defaults(cmd='list')

  # ./rrtest pack -n testname
  pack_group.set_defaults(cmd='pack')
  pack_group.add_argument('-n', '--name',
                              dest='name',
                              help='name of the test to be packed')

  # rrtest analyze -t tracename
  analyze_group.set_defaults(cmd='analyze')
  analyze_group.add_argument('-t', '--tracename',
                             dest='tracename',
                             help='name of trace to be analyzed')
  analyze_group.add_argument('-c', '--checker',
                             dest='checker',
                             help='checker constructor call to be eval()\'d')

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
    if os.path.isdir(test_dir) and args.force != 'YES':
      print('A test with path {} already exists'.format(test_dir))
      sys.exit(1)
    elif os.path.isdir(test_dir) and args.force == 'YES':
      logging.debug('Overwriting %s', test_dir)
      shutil.rmtree(test_dir)

    os.makedirs(test_dir)

    # call rr to record the command passed, store results within test directory
    # subprocess.call with shell=True is used, such that shell command formatting is
    # preserved. TODO: improve, if necessary.
    rr_create_record = ['rr', 'record', '-n', '-q', args.command]
    ret = subprocess.call(" ".join(rr_create_record), shell=True)
    if ret != 0:
      print('`rr record` failed [exit status: {}]'.format(ret))
      sys.exit(ret)

    # retrieve latest trace through latest-trace linked file
    testname = os.path.realpath(consts.RR_TEST_CONFIG_PATH + "latest-trace")

    # copy rr recorded test into our own directory
    rr_copy(testname, test_dir)

    # copy rr produced strace into our own directory
    rr_copy(consts.STRACE_DEFAULT, test_dir + consts.STRACE_DEFAULT)

    #  fix incomplete exit_group(2) line
    fixup_exit_group_cmd = ['sed', '-i', "'$ s/exit_group([^[:blank:])]*$/&) = -1/'", test_dir + consts.STRACE_DEFAULT]
    subprocess.call(" ".join(fixup_exit_group_cmd), shell=True)

    # create INI config file
    config = ConfigParser.ConfigParser()
    config.add_section("rr_recording")
    config.set("rr_recording", "rr_dir", test_dir)

    config.add_section("request_handling_process")
    config.set("request_handling_process", "event", None)
    config.set("request_handling_process", "pid", None)
    config.set("request_handling_process", "trace_file", test_dir + consts.STRACE_DEFAULT)
    config.set("request_handling_process", "trace_start", 0)
    config.set("request_handling_process", "trace_end", 0)
    config.set("request_handling_process", "loglevel", 40)

    # write config file
    with open(test_dir + "config.ini", 'wb') as config_file:
      config.write(config_file)

    # output trace to STDOUT for user to determine proper trace line
    with open(test_dir + consts.STRACE_DEFAULT, 'r') as trace:
      lineno=0
      line='<init>'
      last_endchar = '\n'
      while True:
        line = trace.readline()
        line = re.sub(r'^[0-9]+\s+', '', line)
        if len(line) == 0:
          # append a newline at the end of output
          print('')
          break
        lineno += 1
        if last_endchar == '\n':
          endchar = ''
        print('LINE ' + str(lineno) + ': ' + line, end=endchar)
        last_endchar = line[-1]
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

    # open trace file for reading
    with open(test_dir + consts.STRACE_DEFAULT, 'r') as trace_file:
      trace_lines = trace_file.readlines()

    # strip and breakdown pid
    pid = trace_lines[0].split()[0]

    if not args.event:
      # offset by -1 because line numbers start counting from 1
      chosen_line = trace_lines[args.trace_line - 1 ]
      if re.match(r'[0-9]+\s+\+\+\+\s+[0-9]+\s+\+\+\+', chosen_line):
        print('It seems like you have chosen a line containing an rr event '
              'number rather than a line containing a system call.  You '
              'must select a line containing a system call')
        sys.exit(1)
      # We want the event JUST BEFORE our chosen system call so we must go
      # back 2 lines from the chosen trace line
      event_line = trace_lines[args.trace_line - 2 ]

      user_event = int(event_line.split('+++ ')[1].split(' +++')[0])

    else:
      user_event = args.event

    # create a new strace snippet, with the event as the first line
    with open(test_dir + "trace_snip.strace", 'wb') as snip_file:
      # write a 5 line snippet file by default
      for i in range(0, args.sniplen * 2, 2):
        try:
          snip_file.write(trace_lines[args.trace_line - 1 + i])
        except IndexError:
          break

    # update changes in config.ini
    if args.mutator:
      config.set("request_handling_process", "mutator", args.mutator)
    config.set("request_handling_process", "trace_file", test_dir + "trace_snip.strace")
    config.set("request_handling_process", "event", user_event)
    config.set("request_handling_process", "pid", pid)
    config.set("request_handling_process", "trace_end", args.sniplen)

    # write final changes to config file
    with open(test_dir + "config.ini", 'w+') as config_file:
      config.write(config_file)

    sys.exit(0)

  elif args.cmd == "list":

    # print only filenames of tests in DEFAULT_CONFIG_PATH
    print("\nAvailable Tests:\n----------------")
    for test in os.listdir(consts.DEFAULT_CONFIG_PATH):
      # check if file is a directory, since tests are generated as them
      if os.path.isdir(os.path.join(consts.DEFAULT_CONFIG_PATH, test)):
        print(test)

    print("")
    sys.exit(0)

  elif args.cmd == "pack":

    # check for mandatory arguments
    man_options = ['name']
    for opt in man_options:
      if not args.__dict__[opt]:
        parser.print_help()
        sys.exit(1)

    # perform a rr pack on the test directory
    test_dir = consts.DEFAULT_CONFIG_PATH + args.name
    subprocess.Popen(["rr", "pack", test_dir])

    # zip up specified directory with zipf handle
    shutil.make_archive(args.name, 'zip', test_dir)

    print("Packed up trace and stored as {}".format(args.name + ".zip"))
    sys.exit(0)

  elif args.cmd == 'analyze':
    man_options = ['tracename']
    for opt in man_options:
      if not args.__dict__[opt]:
        parser.print_help()
        sys.exit(1)
    pickle_file = consts.DEFAULT_CONFIG_PATH + "syscall_definitions.pickle"
    trace = Trace.Trace(args.tracename, pickle_file)
    checker = eval(args.checker)
    for i in trace.syscalls:
      checker.transition(i)
    print(checker.is_accepting())

  else:
    parser.print_help()
    sys.exit(1)

if __name__ == '__main__':
  main()
