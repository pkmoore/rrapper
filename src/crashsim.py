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
  subparser = parser.add_subparsers(metavar='MYTEST', help='name of test')


  # if no arguments given
  try:
    sys.argv[1]
  except:
    parser.print_help()
    sys.exit(1)

  if sys.argv[1] == "-h":
    parser.print_help()
    sys.exit(1)

  test_name = subparser.add_parser(sys.argv[1])

  # setting necessary flags
  test_name.set_defaults(cmd=sys.argv[1])
  test_name.add_argument('-m', '--mutator',
                               dest='mutator',
                               required=True,
                               help='mutator to use')
  test_name.add_argument('-c', '--command',
                               dest='command',
                               required=True,
                               help='specify command for rrtest')
  test_name.add_argument('-f', '--force',
                               dest='force',
                               default='YES',
                               help='force overwrite creation of the test')

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

  # creating the test
  proc_create = subprocess.Popen(["rrtest", "create", "--name", args.cmd,
      "--command", args.command, "-f", args.force])
  proc_create.wait()

  logging.debug("Checking if rrtest create is successfull")
  if proc_create.returncode != 0:
    sys.exit(1)

  # configuring the test
  proc_configure = subprocess.Popen(["rrtest", "configure", "--name", args.cmd, "--mutator", args.mutator]) 
  proc_configure.wait()

  logging.debug("Checking if rrtest configure is successfull")
  if proc_configure.returncode != 0:
    sys.exit(1)
  
  # replay the test
  proc_replay = subprocess.Popen(["rreplay", args.cmd])
  proc_replay.wait()

  logging.debug("Checking if rreplay is successfull")
  if proc_replay.returncode != 0:
    sys.exit(1)

if __name__ == "__main__":
  main()
