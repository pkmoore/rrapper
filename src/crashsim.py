"""
<Program Name>
  crashsim

<Started>
  June 2019

<Author>
  Junjie Ge

<Purpose>
  A shorter command aimed to replace rrtest and rreplay in order to improve user experience

"""

import sys
import argparse
import subprocess
import logging

def main():
  # initialize parser
  parser = argparse.ArgumentParser()
  subparsers = parser.add_subparsers()

  # two commands - create / configure
  test_name = subparsers.add_parser(sys.argv[1])

  # ./rrtest create -n testname -c "./runthisbinary"
  test_name.set_defaults(cmd=sys.argv[1])
  test_name.add_argument('-m', '--mutator',
                               dest='mutator',
                               help='mutator to use')
  test_name.add_argument('-c', '--command',
                            dest='command',
                            help='specify command for rrtest')
  # test_name.add_argument('-f', '--force',
  #                           dest='force',
  #                           help='force overwrite creation of the test')

  # general flags to be set
  parser.add_argument('-v', '--verbosity',
                      dest='verbosity',
                      action='store_const',
                      const=logging.debug,
                      help='flag for displaying debug information')

  # parse arguments
  args = parser.parse_args()

  # configure logger
  logging.basicConfig(level=args.verbosity)

  # initialize actual application logic 
  man_options = ['command']
  for opt in man_options:
    if not args.__dict__[opt]:
      parser.print_help()
      sys.exit(1)

  # creating the test
  proc_create = subprocess.Popen(["rrtest", "create", "--name", args.cmd, "--command", args.command])
  proc_create.wait()

  if proc_create.returncode != 0:
    print("Test creation failed")
    sys.exit(1)

  # configuring the test
  proc_configure = subprocess.Popen(["rrtest", "configure", "--name", args.cmd, "--mutator", args.mutator]) 
  proc_configure.wait()

  if proc_configure.returncode != 0:
    print("Test configuration failed")
    sys.exit(1)
  
  # replay the test
  proc_replay = subprocess.Popen(["rreplay", args.cmd])
  proc_replay.wait()

  if proc_replay.returncode != 0:
    print("Replay failed")
    sys.exit(1)

if __name__ == "__main__":
  main()